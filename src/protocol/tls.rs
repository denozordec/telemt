//! Fake TLS 1.3 Handshake
//!
//! This module handles the fake TLS 1.3 handshake used by MTProto proxy
//! for domain fronting. The handshake looks like valid TLS 1.3 but
//! actually carries MTProto authentication data.

#![allow(dead_code)]
#![cfg_attr(not(test), forbid(clippy::undocumented_unsafe_blocks))]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::correctness,
        clippy::option_if_let_else,
        clippy::or_fun_call,
        clippy::branches_sharing_code,
        clippy::single_option_map,
        clippy::useless_let_if_seq,
        clippy::redundant_locals,
        clippy::cloned_ref_to_slice_refs,
        unsafe_code,
        clippy::await_holding_lock,
        clippy::await_holding_refcell_ref,
        clippy::debug_assert_with_mut_call,
        clippy::macro_use_imports,
        clippy::cast_ptr_alignment,
        clippy::cast_lossless,
        clippy::ptr_as_ptr,
        clippy::large_stack_arrays,
        clippy::same_functions_in_if_condition,
        trivial_casts,
        trivial_numeric_casts,
        unused_extern_crates,
        unused_import_braces,
        rust_2018_idioms
    )
)]
#![cfg_attr(
    not(test),
    allow(
        clippy::use_self,
        clippy::redundant_closure,
        clippy::too_many_arguments,
        clippy::doc_markdown,
        clippy::missing_const_for_fn,
        clippy::unnecessary_operation,
        clippy::redundant_pub_crate,
        clippy::derive_partial_eq_without_eq,
        clippy::type_complexity,
        clippy::new_ret_no_self,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::significant_drop_tightening,
        clippy::significant_drop_in_scrutinee,
        clippy::float_cmp,
        clippy::nursery
    )
)]

use super::constants::*;
use crate::crypto::{SecureRandom, sha256_hmac};
#[cfg(test)]
use crate::error::ProxyError;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

// ============= Public Constants =============

/// TLS handshake digest length
pub const TLS_DIGEST_LEN: usize = 32;

/// Position of digest in TLS ClientHello
pub const TLS_DIGEST_POS: usize = 11;

/// Length to store for replay protection (first 16 bytes of digest)
pub const TLS_DIGEST_HALF_LEN: usize = 16;

/// Time skew limits for anti-replay (in seconds)
///
/// The default window is intentionally narrow to reduce replay acceptance.
/// Operators with known clock-drifted clients should tune deployment config
/// (for example replay-window policy) to match their environment.
pub const TIME_SKEW_MIN: i64 = -2 * 60; // 2 minutes before
pub const TIME_SKEW_MAX: i64 = 2 * 60; // 2 minutes after
/// Maximum accepted boot-time timestamp (seconds) before skew checks are enforced.
pub const BOOT_TIME_MAX_SECS: u32 = 7 * 24 * 60 * 60;
/// Hard cap for boot-time compatibility bypass to avoid oversized acceptance
/// windows when replay TTL is configured very large.
pub const BOOT_TIME_COMPAT_MAX_SECS: u32 = 2 * 60;

// ============= Private Constants =============

/// TLS Extension types
mod extension_type {
    pub const KEY_SHARE: u16 = 0x0033;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub const ALPN: u16 = 0x0010;
    pub const EXTENDED_MASTER_SECRET: u16 = 0x0017;
    pub const SESSION_TICKET: u16 = 0x0023;
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
}

/// TLS Cipher Suites
mod cipher_suite {
    pub const TLS_AES_128_GCM_SHA256: [u8; 2] = [0x13, 0x01];
}

/// TLS Named Curves
mod named_curve {
    pub const X25519: u16 = 0x001d;
}

// ============= TLS Validation Result =============

/// Result of validating TLS handshake
#[derive(Debug)]
pub struct TlsValidation {
    /// Username that validated
    pub user: String,
    /// Session ID from ClientHello
    pub session_id: Vec<u8>,
    /// Client digest for response generation
    pub digest: [u8; TLS_DIGEST_LEN],
    /// Timestamp extracted from digest
    pub timestamp: u32,
}

// ============= TLS Extension Builder =============

/// Builder for TLS extensions with correct length calculation
#[derive(Clone)]
struct TlsExtensionBuilder {
    extensions: Vec<u8>,
}

impl TlsExtensionBuilder {
    fn new() -> Self {
        Self {
            extensions: Vec::with_capacity(256),
        }
    }

    /// Add Key Share extension with X25519 key
    fn add_key_share(&mut self, public_key: &[u8; 32]) -> &mut Self {
        self.extensions
            .extend_from_slice(&extension_type::KEY_SHARE.to_be_bytes());
        let entry_len: u16 = 2 + 2 + 32;
        self.extensions.extend_from_slice(&entry_len.to_be_bytes());
        self.extensions
            .extend_from_slice(&named_curve::X25519.to_be_bytes());
        self.extensions.extend_from_slice(&(32u16).to_be_bytes());
        self.extensions.extend_from_slice(public_key);
        self
    }

    /// Add Supported Versions extension
    fn add_supported_versions(&mut self, version: u16) -> &mut Self {
        self.extensions
            .extend_from_slice(&extension_type::SUPPORTED_VERSIONS.to_be_bytes());
        self.extensions.extend_from_slice(&(2u16).to_be_bytes());
        self.extensions.extend_from_slice(&version.to_be_bytes());
        self
    }

    /// Add extended_master_secret extension (0x0017) — zero-length data, presence-only
    fn add_extended_master_secret(&mut self) -> &mut Self {
        self.extensions
            .extend_from_slice(&extension_type::EXTENDED_MASTER_SECRET.to_be_bytes());
        self.extensions.extend_from_slice(&(0u16).to_be_bytes());
        self
    }

    /// Add session_ticket extension (0x0023) — empty, mirrors client offer
    fn add_session_ticket(&mut self) -> &mut Self {
        self.extensions
            .extend_from_slice(&extension_type::SESSION_TICKET.to_be_bytes());
        self.extensions.extend_from_slice(&(0u16).to_be_bytes());
        self
    }

    /// Add ec_point_formats extension (0x000b) — uncompressed only
    fn add_ec_point_formats(&mut self) -> &mut Self {
        // Extension type
        self.extensions
            .extend_from_slice(&extension_type::EC_POINT_FORMATS.to_be_bytes());
        // Extension data length: 1 (list len) + 1 (format)
        self.extensions.extend_from_slice(&(2u16).to_be_bytes());
        // ec_point_formats list length
        self.extensions.push(0x01);
        // uncompressed (0x00)
        self.extensions.push(0x00);
        self
    }

    /// Add renegotiation_info extension (0xff01) — empty RI (initial handshake)
    fn add_renegotiation_info(&mut self) -> &mut Self {
        self.extensions
            .extend_from_slice(&extension_type::RENEGOTIATION_INFO.to_be_bytes());
        // Extension data: 1 byte length + 0 bytes RI value
        self.extensions.extend_from_slice(&(1u16).to_be_bytes());
        self.extensions.push(0x00);
        self
    }

    /// Build final extensions with length prefix
    fn build(self) -> Vec<u8> {
        let Ok(len) = u16::try_from(self.extensions.len()) else {
            return Vec::new();
        };
        let mut result = Vec::with_capacity(2 + self.extensions.len());
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&self.extensions);
        result
    }

    /// Get current extensions without length prefix (for calculation)
    fn as_bytes(&self) -> &[u8] {
        &self.extensions
    }
}

// ============= ServerHello Builder =============

/// Builder for TLS ServerHello with correct structure
struct ServerHelloBuilder {
    /// Random bytes (32 bytes, will contain digest)
    random: [u8; 32],
    /// Session ID (echoed from ClientHello)
    session_id: Vec<u8>,
    /// Cipher suite
    cipher_suite: [u8; 2],
    /// Compression method
    compression: u8,
    /// Extensions
    extensions: TlsExtensionBuilder,
}

impl ServerHelloBuilder {
    fn new(session_id: Vec<u8>) -> Self {
        Self {
            random: [0u8; 32],
            session_id,
            cipher_suite: cipher_suite::TLS_AES_128_GCM_SHA256,
            compression: 0x00,
            extensions: TlsExtensionBuilder::new(),
        }
    }

    fn with_x25519_key(mut self, key: &[u8; 32]) -> Self {
        self.extensions.add_key_share(key);
        self
    }

    fn with_tls13_version(mut self) -> Self {
        self.extensions.add_supported_versions(0x0304);
        self
    }

    /// Add Chrome-compatible compat extensions based on what the client offered.
    ///
    /// These extensions make the ServerHello indistinguishable from a real
    /// browser TLS 1.3 handshake at the DPI level:
    /// - extended_master_secret is always included (ubiquitous in Chrome/Firefox)
    /// - renegotiation_info is always included (TLS 1.2 compat signal)
    /// - ec_point_formats is always included
    /// - session_ticket is mirrored only when the client offered it
    fn with_compat_extensions(mut self, client_has_session_ticket: bool) -> Self {
        self.extensions.add_extended_master_secret();
        self.extensions.add_renegotiation_info();
        self.extensions.add_ec_point_formats();
        if client_has_session_ticket {
            self.extensions.add_session_ticket();
        }
        self
    }

    /// Build ServerHello message (without record header)
    fn build_message(&self) -> Vec<u8> {
        let Ok(session_id_len) = u8::try_from(self.session_id.len()) else {
            return Vec::new();
        };
        let extensions = self.extensions.extensions.clone();
        let Ok(extensions_len) = u16::try_from(extensions.len()) else {
            return Vec::new();
        };

        let body_len = 2 + 32 + 1 + self.session_id.len() + 2 + 1 + 2 + extensions.len();
        if body_len > 0x00ff_ffff {
            return Vec::new();
        }

        let mut message = Vec::with_capacity(4 + body_len);

        message.push(0x02);

        let Ok(body_len_u32) = u32::try_from(body_len) else {
            return Vec::new();
        };
        let len_bytes = body_len_u32.to_be_bytes();
        message.extend_from_slice(&len_bytes[1..4]);

        message.extend_from_slice(&TLS_VERSION);
        message.extend_from_slice(&self.random);

        message.push(session_id_len);
        message.extend_from_slice(&self.session_id);

        message.extend_from_slice(&self.cipher_suite);
        message.push(self.compression);

        message.extend_from_slice(&extensions_len.to_be_bytes());
        message.extend_from_slice(&extensions);

        message
    }

    /// Build complete ServerHello TLS record
    fn build_record(&self) -> Vec<u8> {
        let message = self.build_message();
        if message.is_empty() {
            return Vec::new();
        }
        let Ok(message_len) = u16::try_from(message.len()) else {
            return Vec::new();
        };

        let mut record = Vec::with_capacity(5 + message.len());
        record.push(TLS_RECORD_HANDSHAKE);
        record.extend_from_slice(&TLS_VERSION);
        record.extend_from_slice(&message_len.to_be_bytes());
        record.extend_from_slice(&message);
        record
    }
}

// ============= ClientHello helpers =============

/// Check whether a specific extension type is present in a ClientHello.
///
/// Used to mirror optional extensions (e.g. session_ticket) back to the
/// client only when they were originally offered, avoiding a mismatch that
/// a passive observer could use as a fingerprint.
pub fn has_extension_in_client_hello(handshake: &[u8], target_type: u16) -> bool {
    if handshake.len() < 5 || handshake[0] != TLS_RECORD_HANDSHAKE {
        return false;
    }
    let record_len = u16::from_be_bytes([handshake[3], handshake[4]]) as usize;
    if handshake.len() < 5 + record_len {
        return false;
    }

    let mut pos = 5;
    if handshake.get(pos) != Some(&0x01) {
        return false;
    }
    pos += 4; // type + 3-byte len
    pos += 2 + 32; // legacy version + random
    if pos >= handshake.len() {
        return false;
    }
    let session_id_len = handshake[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > handshake.len() {
        return false;
    }
    let cipher_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos >= handshake.len() {
        return false;
    }
    let comp_len = handshake[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > handshake.len() {
        return false;
    }
    let ext_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > handshake.len() {
        return false;
    }

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let elen = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end {
            break;
        }
        if etype == target_type {
            return true;
        }
        pos += elen;
    }
    false
}

// ============= Public Functions =============

/// Validate TLS ClientHello against user secrets.
///
/// Returns validation result if a matching user is found.
/// The result **must** be used — ignoring it silently bypasses authentication.
#[must_use]
pub fn validate_tls_handshake(
    handshake: &[u8],
    secrets: &[(String, Vec<u8>)],
    ignore_time_skew: bool,
) -> Option<TlsValidation> {
    validate_tls_handshake_with_replay_window(
        handshake,
        secrets,
        ignore_time_skew,
        u64::from(BOOT_TIME_MAX_SECS),
    )
}

/// Validate TLS ClientHello and cap the boot-time bypass by replay-cache TTL.
///
/// A boot-time timestamp is only accepted when it falls below all three
/// bounds: `BOOT_TIME_MAX_SECS`, configured replay window, and
/// `BOOT_TIME_COMPAT_MAX_SECS`, preventing oversized compatibility windows.
#[must_use]
pub fn validate_tls_handshake_with_replay_window(
    handshake: &[u8],
    secrets: &[(String, Vec<u8>)],
    ignore_time_skew: bool,
    replay_window_secs: u64,
) -> Option<TlsValidation> {
    let now = if !ignore_time_skew {
        system_time_to_unix_secs(SystemTime::now())?
    } else {
        0_i64
    };

    let replay_window_u32 = u32::try_from(replay_window_secs).unwrap_or(u32::MAX);
    let boot_time_cap_secs = if ignore_time_skew {
        0
    } else {
        BOOT_TIME_MAX_SECS
            .min(replay_window_u32)
            .min(BOOT_TIME_COMPAT_MAX_SECS)
    };

    validate_tls_handshake_at_time_with_boot_cap(
        handshake,
        secrets,
        ignore_time_skew,
        now,
        boot_time_cap_secs,
    )
}

fn system_time_to_unix_secs(now: SystemTime) -> Option<i64> {
    let d = now.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(d.as_secs()).ok()
}

fn validate_tls_handshake_at_time(
    handshake: &[u8],
    secrets: &[(String, Vec<u8>)],
    ignore_time_skew: bool,
    now: i64,
) -> Option<TlsValidation> {
    validate_tls_handshake_at_time_with_boot_cap(
        handshake,
        secrets,
        ignore_time_skew,
        now,
        BOOT_TIME_MAX_SECS,
    )
}

fn validate_tls_handshake_at_time_with_boot_cap(
    handshake: &[u8],
    secrets: &[(String, Vec<u8>)],
    ignore_time_skew: bool,
    now: i64,
    boot_time_cap_secs: u32,
) -> Option<TlsValidation> {
    if handshake.len() < TLS_DIGEST_POS + TLS_DIGEST_LEN + 1 {
        return None;
    }

    let digest: [u8; TLS_DIGEST_LEN] = handshake[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN]
        .try_into()
        .ok()?;

    let session_id_len_pos = TLS_DIGEST_POS + TLS_DIGEST_LEN;
    let session_id_len = handshake.get(session_id_len_pos).copied()? as usize;
    if session_id_len > 32 {
        return None;
    }
    let session_id_start = session_id_len_pos + 1;

    if handshake.len() < session_id_start + session_id_len {
        return None;
    }

    let session_id = handshake[session_id_start..session_id_start + session_id_len].to_vec();

    let mut msg = handshake.to_vec();
    msg[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN].fill(0);

    let mut first_match: Option<(&String, u32)> = None;

    for (user, secret) in secrets {
        let computed = sha256_hmac(secret, &msg);

        if !bool::from(digest[..28].ct_eq(&computed[..28])) {
            continue;
        }

        let timestamp = u32::from_le_bytes([
            digest[28] ^ computed[28],
            digest[29] ^ computed[29],
            digest[30] ^ computed[30],
            digest[31] ^ computed[31],
        ]);

        if !ignore_time_skew {
            let is_boot_time = boot_time_cap_secs > 0 && timestamp < boot_time_cap_secs;
            if !is_boot_time {
                let time_diff = now - i64::from(timestamp);
                if !(TIME_SKEW_MIN..=TIME_SKEW_MAX).contains(&time_diff) {
                    continue;
                }
            }
        }

        if first_match.is_none() {
            first_match = Some((user, timestamp));
        }
    }

    first_match.map(|(user, timestamp)| TlsValidation {
        user: user.clone(),
        session_id,
        digest,
        timestamp,
    })
}

/// Generate a fake X25519 public key for TLS
///
/// Uses RFC 7748 X25519 scalar multiplication over the canonical basepoint,
/// yielding distribution-consistent public keys for anti-fingerprinting.
pub fn gen_fake_x25519_key(rng: &SecureRandom) -> [u8; 32] {
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&rng.bytes(32));
    x25519(scalar, X25519_BASEPOINT_BYTES)
}

/// Build TLS ServerHello response
///
/// This builds a complete TLS 1.3-like response including:
/// - ServerHello record with browser-compatible extensions
/// - Change Cipher Spec record
/// - Three ApplicationData records mimicking the real TLS 1.3 encrypted
///   handshake flight: EncryptedExtensions + Certificate + Finish
///
/// When `client_hello` is provided, optional extensions (e.g. session_ticket)
/// are mirrored only if the client originally offered them, preventing an
/// extension-presence fingerprint distinguishable by DPI.
pub fn build_server_hello(
    secret: &[u8],
    client_digest: &[u8; TLS_DIGEST_LEN],
    session_id: &[u8],
    _fake_cert_len: usize,
    rng: &SecureRandom,
    alpn: Option<Vec<u8>>,
    new_session_tickets: u8,
    client_hello: Option<&[u8]>,
) -> Vec<u8> {
    const MIN_APP_DATA: usize = 64;
    const MAX_APP_DATA: usize = MAX_TLS_CIPHERTEXT_SIZE;

    // Determine which optional extensions to mirror from the ClientHello.
    let client_has_session_ticket = client_hello
        .map(|ch| has_extension_in_client_hello(ch, extension_type::SESSION_TICKET))
        .unwrap_or(false);

    let x25519_key = gen_fake_x25519_key(rng);

    // Build ServerHello with browser-compatible extension set.
    let server_hello = ServerHelloBuilder::new(session_id.to_vec())
        .with_x25519_key(&x25519_key)
        .with_tls13_version()
        .with_compat_extensions(client_has_session_ticket)
        .build_record();

    // Build Change Cipher Spec record
    let change_cipher_spec = [
        TLS_RECORD_CHANGE_CIPHER,
        TLS_VERSION[0],
        TLS_VERSION[1],
        0x00,
        0x01,
        0x01,
    ];

    // Build three separate ApplicationData records that mimic the real
    // TLS 1.3 encrypted handshake flight structure:
    //   1. EncryptedExtensions  (50–80 bytes)
    //   2. Certificate          (1200–2000 bytes)
    //   3. CertificateVerify + Finished (100–150 bytes)
    //
    // A single monolithic random blob is trivially distinguishable by DPI
    // via record-count and size-distribution heuristics. Three records with
    // plausible size ranges are consistent with any modern TLS 1.3 server.
    let enc_ext_len = (rng.range(31) + 50).clamp(MIN_APP_DATA, MAX_APP_DATA);
    let cert_len = (rng.range(801) + 1200).clamp(MIN_APP_DATA, MAX_APP_DATA);
    let finish_len = (rng.range(51) + 100).clamp(MIN_APP_DATA, MAX_APP_DATA);

    // Embed optional ALPN negotiation marker in the first record
    // (EncryptedExtensions), then pad the rest with random bytes.
    let build_app_data_record = |data_len: usize, embed_alpn: bool| -> Vec<u8> {
        let mut payload = Vec::with_capacity(data_len);
        if embed_alpn {
            if let Some(proto) = alpn
                .as_ref()
                .filter(|p| !p.is_empty() && p.len() <= u8::MAX as usize)
            {
                let proto_list_len = 1usize + proto.len();
                let ext_data_len = 2usize + proto_list_len;
                let marker_len = 4usize + ext_data_len;
                if marker_len <= data_len {
                    payload.extend_from_slice(&0x0010u16.to_be_bytes());
                    payload.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
                    payload.extend_from_slice(&(proto_list_len as u16).to_be_bytes());
                    payload.push(proto.len() as u8);
                    payload.extend_from_slice(proto);
                }
            }
        }
        let remaining = data_len.saturating_sub(payload.len());
        if remaining > 0 {
            payload.extend_from_slice(&rng.bytes(remaining));
        }
        payload.truncate(data_len);

        let mut record = Vec::with_capacity(5 + data_len);
        record.push(TLS_RECORD_APPLICATION);
        record.extend_from_slice(&TLS_VERSION);
        record.extend_from_slice(&(data_len as u16).to_be_bytes());
        record.extend_from_slice(&payload);
        record
    };

    let enc_ext_record = build_app_data_record(enc_ext_len, true);
    let cert_record = build_app_data_record(cert_len, false);
    let finish_record = build_app_data_record(finish_len, false);

    // Build optional NewSessionTicket records
    let mut tickets = Vec::new();
    let ticket_count = new_session_tickets.min(4);
    if ticket_count > 0 {
        for _ in 0..ticket_count {
            let ticket_len: usize = rng.range(48) + 48;
            let mut record = Vec::with_capacity(5 + ticket_len);
            record.push(TLS_RECORD_APPLICATION);
            record.extend_from_slice(&TLS_VERSION);
            record.extend_from_slice(&(ticket_len as u16).to_be_bytes());
            record.extend_from_slice(&rng.bytes(ticket_len));
            tickets.push(record);
        }
    }

    // Combine all records
    let mut response = Vec::with_capacity(
        server_hello.len()
            + change_cipher_spec.len()
            + enc_ext_record.len()
            + cert_record.len()
            + finish_record.len()
            + tickets.iter().map(|r| r.len()).sum::<usize>(),
    );
    response.extend_from_slice(&server_hello);
    response.extend_from_slice(&change_cipher_spec);
    response.extend_from_slice(&enc_ext_record);
    response.extend_from_slice(&cert_record);
    response.extend_from_slice(&finish_record);
    for t in &tickets {
        response.extend_from_slice(t);
    }

    // Compute HMAC for the response
    let mut hmac_input = Vec::with_capacity(TLS_DIGEST_LEN + response.len());
    hmac_input.extend_from_slice(client_digest);
    hmac_input.extend_from_slice(&response);
    let response_digest = sha256_hmac(secret, &hmac_input);

    // Insert computed digest into ServerHello
    response[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN].copy_from_slice(&response_digest);

    response
}

/// Extract SNI (server_name) from a TLS ClientHello.
pub fn extract_sni_from_client_hello(handshake: &[u8]) -> Option<String> {
    if handshake.len() < 43 || handshake[0] != TLS_RECORD_HANDSHAKE {
        return None;
    }

    let record_len = u16::from_be_bytes([handshake[3], handshake[4]]) as usize;
    if handshake.len() < 5 + record_len {
        return None;
    }

    let mut pos = 5;
    if handshake.get(pos).copied()? != 0x01 {
        return None;
    }

    pos += 4;
    pos += 2 + 32;
    if pos + 1 > handshake.len() {
        return None;
    }

    let session_id_len = *handshake.get(pos)? as usize;
    pos += 1 + session_id_len;
    if pos + 2 > handshake.len() {
        return None;
    }

    let cipher_suites_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos + 1 > handshake.len() {
        return None;
    }

    let comp_len = *handshake.get(pos)? as usize;
    pos += 1 + comp_len;
    if pos + 2 > handshake.len() {
        return None;
    }

    let ext_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > handshake.len() {
        return None;
    }

    let mut saw_sni_extension = false;
    let mut extracted_sni = None;

    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let elen = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end {
            break;
        }
        if etype == 0x0000 {
            if saw_sni_extension {
                return None;
            }
            saw_sni_extension = true;
        }
        if etype == 0x0000 && elen >= 5 {
            let list_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
            let mut sn_pos = pos + 2;
            let sn_end = std::cmp::min(sn_pos + list_len, pos + elen);
            while sn_pos + 3 <= sn_end {
                let name_type = handshake[sn_pos];
                let name_len =
                    u16::from_be_bytes([handshake[sn_pos + 1], handshake[sn_pos + 2]]) as usize;
                sn_pos += 3;
                if sn_pos + name_len > sn_end {
                    break;
                }
                if name_type == 0
                    && name_len > 0
                    && let Ok(host) = std::str::from_utf8(&handshake[sn_pos..sn_pos + name_len])
                    && is_valid_sni_hostname(host)
                {
                    extracted_sni = Some(host.to_string());
                    break;
                }
                sn_pos += name_len;
            }
        }
        pos += elen;
    }

    extracted_sni
}

fn is_valid_sni_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }

    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }

    true
}

/// Extract ALPN protocol list from ClientHello, return in offered order.
pub fn extract_alpn_from_client_hello(handshake: &[u8]) -> Vec<Vec<u8>> {
    if handshake.len() < 5 || handshake[0] != TLS_RECORD_HANDSHAKE {
        return Vec::new();
    }

    let record_len = u16::from_be_bytes([handshake[3], handshake[4]]) as usize;
    if handshake.len() < 5 + record_len {
        return Vec::new();
    }

    let mut pos = 5;
    if handshake.get(pos) != Some(&0x01) {
        return Vec::new();
    }
    pos += 4;
    pos += 2 + 32;
    if pos >= handshake.len() {
        return Vec::new();
    }
    let session_id_len = *handshake.get(pos).unwrap_or(&0) as usize;
    pos += 1 + session_id_len;
    if pos + 2 > handshake.len() {
        return Vec::new();
    }
    let cipher_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos >= handshake.len() {
        return Vec::new();
    }
    let comp_len = *handshake.get(pos).unwrap_or(&0) as usize;
    pos += 1 + comp_len;
    if pos + 2 > handshake.len() {
        return Vec::new();
    }
    let ext_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;
    if ext_end > handshake.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    while pos + 4 <= ext_end {
        let etype = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let elen = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;
        if pos + elen > ext_end {
            break;
        }
        if etype == extension_type::ALPN && elen >= 3 {
            let list_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
            let mut lp = pos + 2;
            let list_end = (pos + 2).saturating_add(list_len).min(pos + elen);
            while lp < list_end {
                let plen = handshake[lp] as usize;
                lp += 1;
                if lp + plen > list_end {
                    break;
                }
                out.push(handshake[lp..lp + plen].to_vec());
                lp += plen;
            }
            break;
        }
        pos += elen;
    }
    out
}

/// Check if bytes look like a TLS ClientHello
pub fn is_tls_handshake(first_bytes: &[u8]) -> bool {
    if first_bytes.len() < 3 {
        return false;
    }
    first_bytes[0] == TLS_RECORD_HANDSHAKE
        && first_bytes[1] == 0x03
        && (first_bytes[2] == 0x01 || first_bytes[2] == 0x03)
}

/// Parse TLS record header, returns (record_type, length)
pub fn parse_tls_record_header(header: &[u8; 5]) -> Option<(u8, u16)> {
    let record_type = header[0];
    let version = [header[1], header[2]];

    if version != [0x03, 0x01] && version != TLS_VERSION {
        return None;
    }

    let length = u16::from_be_bytes([header[3], header[4]]);
    Some((record_type, length))
}

/// Validate a ServerHello response structure
///
/// This is useful for testing that our ServerHello is well-formed.
#[cfg(test)]
fn validate_server_hello_structure(data: &[u8]) -> Result<(), ProxyError> {
    if data.len() < 5 {
        return Err(ProxyError::InvalidTlsRecord {
            record_type: 0,
            version: [0, 0],
        });
    }

    if data[0] != TLS_RECORD_HANDSHAKE {
        return Err(ProxyError::InvalidTlsRecord {
            record_type: data[0],
            version: [data[1], data[2]],
        });
    }

    if data[1..3] != TLS_VERSION {
        return Err(ProxyError::InvalidTlsRecord {
            record_type: data[0],
            version: [data[1], data[2]],
        });
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return Err(ProxyError::InvalidHandshake(format!(
            "ServerHello record truncated: expected {}, got {}",
            5 + record_len,
            data.len()
        )));
    }

    if data[5] != 0x02 {
        return Err(ProxyError::InvalidHandshake(format!(
            "Expected ServerHello (0x02), got 0x{:02x}",
            data[5]
        )));
    }

    let msg_len = u32::from_be_bytes([0, data[6], data[7], data[8]]) as usize;
    if msg_len + 4 != record_len {
        return Err(ProxyError::InvalidHandshake(format!(
            "Message length mismatch: {} + 4 != {}",
            msg_len, record_len
        )));
    }

    Ok(())
}

// ============= Compile-time Security Invariants =============

mod compile_time_security_checks {
    use super::{TLS_DIGEST_HALF_LEN, TLS_DIGEST_LEN};
    use static_assertions::const_assert;

    const_assert!(TLS_DIGEST_LEN == 32);
    const_assert!(TLS_DIGEST_HALF_LEN * 2 == TLS_DIGEST_LEN);
    const_assert!(28 + 4 == TLS_DIGEST_LEN);
}

// ============= Security-focused regression tests =============

#[cfg(test)]
#[path = "tests/tls_security_tests.rs"]
mod security_tests;

#[cfg(test)]
#[path = "tests/tls_adversarial_tests.rs"]
mod adversarial_tests;

#[cfg(test)]
#[path = "tests/tls_fuzz_security_tests.rs"]
mod fuzz_security_tests;

#[cfg(test)]
#[path = "tests/tls_length_cast_hardening_security_tests.rs"]
mod length_cast_hardening_security_tests;
