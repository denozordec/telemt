use super::*;
use crate::crypto::AesCtr;
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use tokio::io::AsyncWriteExt;
use tokio::io::duplex;
use tokio::time::{Duration as TokioDuration, timeout};

#[test]
fn should_yield_sender_only_on_budget_with_backlog() {
    assert!(!should_yield_c2me_sender(0, true));
    assert!(!should_yield_c2me_sender(C2ME_SENDER_FAIRNESS_BUDGET - 1, true));
    assert!(!should_yield_c2me_sender(C2ME_SENDER_FAIRNESS_BUDGET, false));
    assert!(should_yield_c2me_sender(C2ME_SENDER_FAIRNESS_BUDGET, true));
}

#[tokio::test]
async fn enqueue_c2me_command_uses_try_send_fast_path() {
    let (tx, mut rx) = mpsc::channel::<C2MeCommand>(2);
    enqueue_c2me_command(
        &tx,
        C2MeCommand::Data {
            payload: Bytes::from_static(&[1, 2, 3]),
            flags: 0,
        },
    )
    .await
    .unwrap();

    let recv = timeout(TokioDuration::from_millis(50), rx.recv())
        .await
        .unwrap()
        .unwrap();
    match recv {
        C2MeCommand::Data { payload, flags } => {
            assert_eq!(payload.as_ref(), &[1, 2, 3]);
            assert_eq!(flags, 0);
        }
        C2MeCommand::Close => panic!("unexpected close command"),
    }
}

#[tokio::test]
async fn enqueue_c2me_command_falls_back_to_send_when_queue_is_full() {
    let (tx, mut rx) = mpsc::channel::<C2MeCommand>(1);
    tx.send(C2MeCommand::Data {
        payload: Bytes::from_static(&[9]),
        flags: 9,
    })
    .await
    .unwrap();

    let tx2 = tx.clone();
    let producer = tokio::spawn(async move {
        enqueue_c2me_command(
            &tx2,
            C2MeCommand::Data {
                payload: Bytes::from_static(&[7, 7]),
                flags: 7,
            },
        )
        .await
        .unwrap();
    });

    let _ = timeout(TokioDuration::from_millis(100), rx.recv())
        .await
        .unwrap();
    producer.await.unwrap();

    let recv = timeout(TokioDuration::from_millis(100), rx.recv())
        .await
        .unwrap()
        .unwrap();
    match recv {
        C2MeCommand::Data { payload, flags } => {
            assert_eq!(payload.as_ref(), &[7, 7]);
            assert_eq!(flags, 7);
        }
        C2MeCommand::Close => panic!("unexpected close command"),
    }
}

#[test]
fn desync_dedup_cache_is_bounded() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let now = Instant::now();
    for key in 0..DESYNC_DEDUP_MAX_ENTRIES as u64 {
        assert!(
            should_emit_full_desync(key, false, now),
            "unique keys up to cap must be tracked"
        );
    }

    assert!(
        !should_emit_full_desync(u64::MAX, false, now),
        "new key above cap must remain suppressed to avoid log amplification"
    );

    assert!(
        !should_emit_full_desync(7, false, now),
        "already tracked key inside dedup window must stay suppressed"
    );
}

#[test]
fn desync_dedup_full_cache_churn_stays_suppressed() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("desync dedup test lock must be available");
    clear_desync_dedup_for_testing();

    let now = Instant::now();
    for key in 0..DESYNC_DEDUP_MAX_ENTRIES as u64 {
        assert!(should_emit_full_desync(key, false, now));
    }

    for offset in 0..2048u64 {
        assert!(
            !should_emit_full_desync(u64::MAX - offset, false, now),
            "fresh full-cache churn must remain suppressed under pressure"
        );
    }
}

fn make_forensics_state() -> RelayForensicsState {
    RelayForensicsState {
        trace_id: 1,
        conn_id: 2,
        user: "test-user".to_string(),
        peer: "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
        peer_hash: 3,
        started_at: Instant::now(),
        bytes_c2me: 0,
        bytes_me2c: Arc::new(AtomicU64::new(0)),
        desync_all_full: false,
    }
}

fn make_crypto_reader(reader: tokio::io::DuplexStream) -> CryptoReader<tokio::io::DuplexStream> {
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoReader::new(reader, AesCtr::new(&key, iv))
}

fn encrypt_for_reader(plaintext: &[u8]) -> Vec<u8> {
    let key = [0u8; 32];
    let iv = 0u128;
    let mut cipher = AesCtr::new(&key, iv);
    cipher.encrypt(plaintext)
}

#[tokio::test]
async fn read_client_payload_times_out_on_header_stall() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");
    let (reader, _writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let result = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        TokioDuration::from_millis(25),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut),
        "stalled header read must time out"
    );
}

#[tokio::test]
async fn read_client_payload_times_out_on_payload_stall() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");
    let (reader, mut writer) = duplex(1024);
    let encrypted_len = encrypt_for_reader(&[8, 0, 0, 0]);
    writer.write_all(&encrypted_len).await.unwrap();

    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let result = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        TokioDuration::from_millis(25),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut),
        "stalled payload body read must time out"
    );
}

#[tokio::test]
async fn read_client_payload_large_intermediate_frame_is_exact() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(262_144);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let payload_len = buffer_pool.buffer_size().saturating_mul(3).max(65_537);
    let mut plaintext = Vec::with_capacity(4 + payload_len);
    plaintext.extend_from_slice(&(payload_len as u32).to_le_bytes());
    plaintext.extend((0..payload_len).map(|idx| (idx as u8).wrapping_mul(31)));

    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let read = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        payload_len + 16,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("payload read must succeed")
    .expect("frame must be present");

    let (frame, quickack) = read;
    assert!(!quickack, "quickack flag must be unset");
    assert_eq!(frame.len(), payload_len, "payload size must match wire length");
    for (idx, byte) in frame.iter().enumerate() {
        assert_eq!(*byte, (idx as u8).wrapping_mul(31));
    }
    assert_eq!(frame_counter, 1, "exactly one frame must be counted");
}

#[tokio::test]
async fn read_client_payload_secure_strips_tail_padding_bytes() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let payload = [0x11u8, 0x22, 0x33, 0x44, 0xaa, 0xbb, 0xcc, 0xdd];
    let tail = [0xeeu8, 0xff, 0x99];
    let wire_len = payload.len() + tail.len();

    let mut plaintext = Vec::with_capacity(4 + wire_len);
    plaintext.extend_from_slice(&(wire_len as u32).to_le_bytes());
    plaintext.extend_from_slice(&payload);
    plaintext.extend_from_slice(&tail);
    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let read = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Secure,
        1024,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("secure payload read must succeed")
    .expect("secure frame must be present");

    let (frame, quickack) = read;
    assert!(!quickack, "quickack flag must be unset");
    assert_eq!(frame.as_ref(), &payload);
    assert_eq!(frame_counter, 1, "one secure frame must be counted");
}

#[tokio::test]
async fn read_client_payload_secure_rejects_wire_len_below_4() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let mut plaintext = Vec::with_capacity(7);
    plaintext.extend_from_slice(&3u32.to_le_bytes());
    plaintext.extend_from_slice(&[1u8, 2, 3]);
    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let result = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Secure,
        1024,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await;

    assert!(
        matches!(result, Err(ProxyError::Proxy(ref msg)) if msg.contains("Frame too small: 3")),
        "secure wire length below 4 must be fail-closed by the frame-too-small guard"
    );
}

#[tokio::test]
async fn read_client_payload_intermediate_skips_zero_len_frame() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(1024);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let payload = [7u8, 6, 5, 4, 3, 2, 1, 0];
    let mut plaintext = Vec::with_capacity(4 + 4 + payload.len());
    plaintext.extend_from_slice(&0u32.to_le_bytes());
    plaintext.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    plaintext.extend_from_slice(&payload);
    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let read = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        1024,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("intermediate payload read must succeed")
    .expect("frame must be present");

    let (frame, quickack) = read;
    assert!(!quickack, "quickack flag must be unset");
    assert_eq!(frame.as_ref(), &payload);
    assert_eq!(frame_counter, 1, "zero-length frame must be skipped");
}

#[tokio::test]
async fn read_client_payload_abridged_extended_len_sets_quickack() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let buffer_pool = Arc::new(BufferPool::new());
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    let payload_len = 4 * 130;
    let len_words = (payload_len / 4) as u32;
    let mut plaintext = Vec::with_capacity(1 + 3 + payload_len);
    plaintext.push(0xff | 0x80);
    let lw = len_words.to_le_bytes();
    plaintext.extend_from_slice(&lw[..3]);
    plaintext.extend((0..payload_len).map(|idx| (idx as u8).wrapping_add(17)));

    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let read = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Abridged,
        payload_len + 16,
        TokioDuration::from_secs(1),
        &buffer_pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("abridged payload read must succeed")
    .expect("frame must be present");

    let (frame, quickack) = read;
    assert!(quickack, "quickack bit must be propagated from abridged header");
    assert_eq!(frame.len(), payload_len);
    assert_eq!(frame_counter, 1, "one abridged frame must be counted");
}

#[tokio::test]
async fn read_client_payload_returns_buffer_to_pool_after_emit() {
    let _guard = desync_dedup_test_lock()
        .lock()
        .expect("middle relay test lock must be available");

    let pool = Arc::new(BufferPool::with_config(64, 8));
    pool.preallocate(1);
    assert_eq!(pool.stats().pooled, 1, "precondition: one pooled buffer");

    let (reader, mut writer) = duplex(4096);
    let mut crypto_reader = make_crypto_reader(reader);
    let stats = Stats::new();
    let forensics = make_forensics_state();
    let mut frame_counter = 0;

    // Force growth beyond default pool buffer size to catch ownership-take regressions.
    let payload_len = 257usize;
    let mut plaintext = Vec::with_capacity(4 + payload_len);
    plaintext.extend_from_slice(&(payload_len as u32).to_le_bytes());
    plaintext.extend((0..payload_len).map(|idx| (idx as u8).wrapping_mul(13)));

    let encrypted = encrypt_for_reader(&plaintext);
    writer.write_all(&encrypted).await.unwrap();

    let _ = read_client_payload(
        &mut crypto_reader,
        ProtoTag::Intermediate,
        payload_len + 8,
        TokioDuration::from_secs(1),
        &pool,
        &forensics,
        &mut frame_counter,
        &stats,
    )
    .await
    .expect("payload read must succeed")
    .expect("frame must be present");

    assert_eq!(frame_counter, 1);
    let pool_stats = pool.stats();
    assert!(
        pool_stats.pooled >= 1,
        "emitted payload buffer must be returned to pool to avoid pool drain"
    );
}
