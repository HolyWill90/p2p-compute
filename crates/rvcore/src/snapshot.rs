use crate::cpu::Cpu;
use crate::mem::{Mem, PAGE_SIZE};

/// Per-chunk machine state snapshots.
///
/// A snapshot is the complete architectural state (registers, pc, and
/// every allocated memory page) serialized to bytes. Its purpose is the
/// dispute fast path: a judge can verify a snapshot against an agreed
/// chunk hash — `state_hash(prev_chain_hash, snapshot_state) == chain_hash`,
/// which is computationally impossible to fake — and then re-execute
/// exactly one chunk instead of replaying from genesis.
///
/// Snapshots are untrusted input. Trust comes exclusively from the hash
/// check against the chain prefix both disputing parties already agree on.

pub const MAGIC: &[u8; 4] = b"RVS1";

pub fn capture(cpu: &Cpu, mem: &Mem) -> Vec<u8> {
    let pages = mem.allocated_pages();
    let mut out = Vec::with_capacity(8 + 32 * 8 + 8 + 4 * 8 + pages * (4 + PAGE_SIZE));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(pages as u32).to_le_bytes());
    for r in &cpu.x {
        out.extend_from_slice(&r.to_le_bytes());
    }
    out.extend_from_slice(&cpu.pc.to_le_bytes());
    out.extend_from_slice(&cpu.mtvec.to_le_bytes());
    out.extend_from_slice(&cpu.mepc.to_le_bytes());
    out.extend_from_slice(&cpu.mcause.to_le_bytes());
    out.extend_from_slice(&cpu.mstatus.to_le_bytes());
    for (idx, page) in mem.page_iter() {
        out.extend_from_slice(&idx.to_le_bytes());
        out.extend_from_slice(page.as_slice());
    }
    out
}

pub fn restore(bytes: &[u8]) -> Result<(Cpu, Mem), String> {
    if bytes.len() < 8 + 32 * 8 + 8 + 4 * 8 {
        return Err("snapshot: too short".into());
    }
    if &bytes[0..4] != MAGIC {
        return Err("snapshot: bad magic".into());
    }
    let u64le = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
    let page_count = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let mut x = [0u64; 32];
    for (i, r) in x.iter_mut().enumerate() {
        *r = u64le(8 + i * 8);
    }
    let pc_off = 8 + 32 * 8;
    let pc = u64le(pc_off);
    // Machine CSRs (mtvec/mepc/mcause/mstatus) are architectural state
    // and ride along in the snapshot.
    let mut csr = [0u64; 4];
    for (i, r) in csr.iter_mut().enumerate() {
        *r = u64le(pc_off + 8 + i * 8);
    }
    let cpu = Cpu {
        x,
        pc,
        mtvec: csr[0],
        mepc: csr[1],
        mcause: csr[2],
        mstatus: csr[3],
        tohost: None,
    };
    let mut mem = Mem::new();
    // Skip pc + the 4 machine CSRs written after it.
    let mut off = pc_off + 8 + 32;
    for _ in 0..page_count {
        if off + 4 + PAGE_SIZE > bytes.len() {
            return Err("snapshot: truncated page data".into());
        }
        let idx = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        let mut page: Box<[u8; PAGE_SIZE]> = Box::new([0; PAGE_SIZE]);
        page.copy_from_slice(&bytes[off + 4..off + 4 + PAGE_SIZE]);
        mem.insert_page(idx, page);
        off += 4 + PAGE_SIZE;
    }
    if off != bytes.len() {
        return Err("snapshot: trailing bytes".into());
    }
    Ok((cpu, mem))
}
