use crate::cpu::Cpu;
use crate::mem::Mem;

pub type Hash = [u8; 32];

/// The genesis chain seed: the state before the first instruction is
/// hashed against an all-zero previous hash.
pub const GENESIS: Hash = [0u8; 32];

/// Canonical state hash. The entire architectural state is:
///   previous chunk hash || x0..x31 || pc || memory Merkle root
/// Nothing else exists to hash — that is the determinism contract
/// expressed as data.
pub fn state_hash(prev: &Hash, cpu: &Cpu, mem: &Mem) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(prev);
    for r in &cpu.x {
        h.update(&r.to_le_bytes());
    }
    h.update(&cpu.pc.to_le_bytes());
    h.update(&mem.merkle_root());
    h.finalize().into()
}
