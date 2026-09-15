//! zk tier: receipt verification via an external verifier process.
//!
//! The SP1 SDK does not build on every platform, and verification is a
//! distinct role from coordination, so the coordinator does NOT link
//! the SDK. Instead it spawns a verifier binary (built from
//! `sp1-host`: the `zk-verify` bin) that loads the receipt, re-derives
//! the verifying key from the committed guest ELF, and prints a JSON
//! verdict. A verified receipt attests that the pinned emulator — the
//! exact committed guest binary — executed the job's (manifest, elf,
//! input) and produced the committed chunk chain. One proof replaces
//! worker consensus: no quorum threshold applies.

use serde::Deserialize;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct ReceiptOutcome {
    pub status: u32,
    pub instructions: u64,
    pub chunk_hashes: Vec<String>,
    pub output_hex: String,
}

#[derive(Deserialize)]
struct Verdict {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    status: Option<u32>,
    #[serde(default)]
    instructions: Option<u64>,
    #[serde(default)]
    chain: Option<Vec<String>>,
    #[serde(default)]
    output_hex: Option<String>,
}

/// Verify `receipt_bytes` by spawning `cmd` (the zk-verify binary)
/// with the guest ELF and expected job binding. The receipt is passed
/// via a temp file: multi-megabyte argv would exceed OS limits.
pub fn verify_receipt(
    cmd: &str,
    receipt_bytes: &[u8],
    expected_binding: &[[u8; 32]; 3],
    guest_elf: &Path,
) -> Result<ReceiptOutcome, String> {
    let dir = std::env::temp_dir().join("p2pc-zk-verify");
    std::fs::create_dir_all(&dir).map_err(|e| format!("zk verify dir: {e}"))?;
    let receipt_path = dir.join("receipt.bin");
    std::fs::write(&receipt_path, receipt_bytes).map_err(|e| format!("receipt write: {e}"))?;

    let binding_hex: Vec<String> =
        expected_binding.iter().map(|h| hex_upper(h)).collect();
    let output = Command::new(cmd)
        .arg(guest_elf)
        .arg(&receipt_path)
        .args(&binding_hex)
        .output()
        .map_err(|e| format!("zk verifier spawn ({cmd}): {e}"))?;
    let _ = std::fs::remove_file(&receipt_path);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("zk verifier failed: {}", stderr.trim()));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let verdict: Verdict = serde_json::from_str(stdout.trim())
        .map_err(|e| format!("zk verifier output: {e}"))?;
    if !verdict.ok {
        return Err(verdict
            .error
            .unwrap_or_else(|| "receipt rejected".into()));
    }
    Ok(ReceiptOutcome {
        status: verdict.status.ok_or("verdict missing status")?,
        instructions: verdict.instructions.ok_or("verdict missing instructions")?,
        chunk_hashes: verdict.chain.ok_or("verdict missing chain")?,
        output_hex: verdict.output_hex.ok_or("verdict missing output")?,
    })
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}
