#![no_main]
// Untrusted strings flow through the hex decoder, path confinement and
// the signing-message encoder on every result submission; none of them
// may panic (the old byte-offset hex slicing did).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Byte-safe split: from_utf8_lossy output can contain multi-byte
    // replacement chars, and str::split_at would panic mid-char.
    let mid = data.len() / 2;
    let a = String::from_utf8_lossy(&data[..mid]).to_string();
    let b = String::from_utf8_lossy(&data[mid..]).to_string();
    let s = String::from_utf8_lossy(data);
    let _ = jobfmt::from_hex(&a, a.len() / 2);
    let _ = jobfmt::from_hex(s.trim(), 32);
    let _ = jobfmt::confined_name(&s);

    let r = jobfmt::WorkerResult {
        worker_id: a.to_string(),
        job_id: b.to_string(),
        status: "halted".into(),
        instructions: {
            let mut b = [0u8; 8];
            for (i, x) in data.iter().take(8).enumerate() { b[i] = *x; }
            u64::from_le_bytes(b)
        },
        result_hash: s.chars().take(64).collect(),
        chunk_hashes: vec![a.to_string(), b.to_string()],
        output_hex: None,
        trap: None,
        pubkey_hex: None,
        sig_hex: None,
    };
    // Encoding must be deterministic and never panic.
    assert_eq!(jobfmt::signing_message(&r), jobfmt::signing_message(&r));
});
