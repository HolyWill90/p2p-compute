use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

/// A job directory is the unit of distribution:
///   job.json     — this manifest
///   program.elf  — the pinned-toolchain RISC-V image
///   input.bin    — the input blob
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobManifest {
    pub schema: u32,
    pub id: String,
    pub name: String,
    /// Pinned ISA string; must equal abi::ISA.
    pub isa: String,
    /// Toolchain description for humans; the emulator contract is the
    /// ISA, this field documents what built the ELF.
    pub toolchain: String,
    pub chunk_size: u64,
    pub max_instructions: u64,
    pub verification_class: String,
    pub elf: String,
    pub input: String,
}

#[derive(Debug, Clone)]
pub struct Job {
    pub manifest: JobManifest,
    pub dir: PathBuf,
    pub elf: Vec<u8>,
    pub input: Vec<u8>,
}

pub const SCHEMA: u32 = 1;

pub fn load_dir(dir: &Path) -> Result<Job, String> {
    let manifest_path = dir.join("job.json");
    let raw = std::fs::read(&manifest_path)
        .map_err(|e| format!("reading {}: {e}", manifest_path.display()))?;
    let manifest: JobManifest =
        serde_json::from_slice(&raw).map_err(|e| format!("parsing job.json: {e}"))?;
    if manifest.schema != SCHEMA {
        return Err(format!("job schema {} != {SCHEMA}", manifest.schema));
    }
    if manifest.isa != abi::ISA {
        return Err(format!(
            "job targets ISA '{}' but this emulator pins '{}'",
            manifest.isa,
            abi::ISA
        ));
    }
    let elf = std::fs::read(dir.join(&manifest.elf))
        .map_err(|e| format!("reading elf: {e}"))?;
    let input = std::fs::read(dir.join(&manifest.input))
        .map_err(|e| format!("reading input: {e}"))?;
    Ok(Job { manifest, dir: dir.to_path_buf(), elf, input })
}

pub fn save_dir(dir: &Path, manifest: &JobManifest, elf: &[u8], input: &[u8]) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("mkdir: {e}"))?;
    let json = serde_json::to_vec_pretty(manifest).unwrap();
    std::fs::write(dir.join("job.json"), json).map_err(|e| format!("{e}"))?;
    std::fs::write(dir.join(&manifest.elf), elf).map_err(|e| format!("{e}"))?;
    std::fs::write(dir.join(&manifest.input), input).map_err(|e| format!("{e}"))?;
    Ok(())
}

/// What one worker reports. This is the artifact the quorum compares.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResult {
    pub worker_id: String,
    pub job_id: String,
    /// "halted" | "instruction_limit" | "trap"
    pub status: String,
    pub instructions: u64,
    /// Final chunk hash — the identity of the execution.
    pub result_hash: String,
    /// Full chunk hash chain (hex, lowercase).
    pub chunk_hashes: Vec<String>,
    /// Output bytes (hex) if the job halted.
    pub output_hex: Option<String>,
    /// Human-readable trap detail when status == "trap".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trap: Option<String>,
    /// Ed25519 public key of the worker (hex), when it has an identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey_hex: Option<String>,
    /// Ed25519 signature over the raw result-hash bytes (hex). Binds
    /// the identity to the claimed result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig_hex: Option<String>,
}
