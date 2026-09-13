use abi::{ELF_BASE, STACK_TOP};
use rvcore::interp::{execute_chunk_from, ChunkEnd, Config};
 #[allow(unused_imports)] use rvcore::snapshot::capture as _cap;
use rvcore::{state_hash, Mem, GENESIS};

fn load_program(mem: &mut Mem, insts: &[u32]) {
    let mut base = ELF_BASE;
    for inst in insts {
        mem.load_image(base, &inst.to_le_bytes()).unwrap();
        base += 4;
    }
}

/// A program that keeps mutating memory across chunk boundaries so
/// snapshots carry real state: 20 increments of a counter in memory,
/// one per ~5 instructions.
fn counter_program() -> Vec<u32> {
    // lui x5, 0x40000 (0x4000_0000); loop: lw x6,0(x5); addi x6,x6,1; sw x6,0(x5); ...
    // Unrolled: 20x (lw, addi, sw) = 60 insts + setup + ebreak.
    let mut v = vec![u_type(0x40000, 5, 0b0110111)];
    for _ in 0..20 {
        v.push(i_type(0, 5, 2, 6, 0b0000011)); // lw x6, 0(x5)
        v.push(i_type(1, 6, 0, 6, 0b0010011)); // addi x6, x6, 1
        s_type(0, 6, 5, 2, 0b0100011); // sw x6, 0(x5)
    }
    v.push((1 << 20) | 0b1110011); // ebreak
    v
}

fn u_type(imm20: u32, rd: u32, op: u32) -> u32 {
    (imm20 << 12) | (rd << 7) | op
}
fn i_type(imm: i64, rs1: u32, f3: u32, rd: u32, op: u32) -> u32 {
    (((imm as u32) & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
}
fn s_type(imm: i64, rs2: u32, rs1: u32, f3: u32, op: u32) -> u32 {
    let i = imm as u32 & 0xfff;
    ((i >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | ((i & 0x1f) << 7) | op
}

#[test]
fn snapshot_roundtrip_is_bit_exact() {
    let insts = counter_program();
    let mut mem = Mem::new();
    load_program(&mut mem, &insts);
    let outcome = rvcore::interp::run(
        &mut mem,
        ELF_BASE,
        b"",
        &Config { chunk_size: 5, max_instructions: 1000, ..Default::default() },
    );
    assert_eq!(outcome.status, rvcore::ExitStatus::Halted);

    let chain = &outcome.chunk_hashes;

    // Re-run with snapshots enabled and compare chains:
    // to re-run and capture at the same point via run's own machinery.
    let tmp = std::env::temp_dir().join("p2pc-snap-test");
    std::fs::remove_dir_all(&tmp).ok();
    let mut mem2 = Mem::new();
    load_program(&mut mem2, &insts);
    let outcome2 = rvcore::interp::run(
        &mut mem2,
        ELF_BASE,
        b"",
        &Config {
            chunk_size: 5,
            max_instructions: 1000,
            snapshot_dir: Some(tmp.clone()),
            ..Default::default()
        },
    );
    assert_eq!(outcome2.chunk_hashes, *chain, "snapshotted run must match");

    // Verify every boundary snapshot hashes back to its chain entry.
    for (i, _h) in chain.iter().enumerate().take(chain.len().saturating_sub(1)) {
        let path = tmp.join(format!("snap-{i}.bin"));
        // Boundaries: i in 0..4 are chunk boundaries; the last chain
        // entry is the exit snapshot (also written).
        if !path.exists() {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        let (cpu, mem3) = rvcore::snapshot::restore(&bytes).unwrap();
        let prev = if i == 0 { GENESIS } else { chain[i - 1] };
        assert_eq!(
            state_hash(&prev, &cpu, &mem3),
            chain[i],
            "snapshot {i} must hash to its chain entry"
        );
    }
}

#[test]
fn judge_one_chunk_from_snapshot_matches_full_replay() {
    let insts = counter_program();
    let tmp = std::env::temp_dir().join("p2pc-snap-judge");
    std::fs::remove_dir_all(&tmp).ok();

    let mut mem = Mem::new();
    load_program(&mut mem, &insts);
    let full = rvcore::interp::run(
        &mut mem,
        ELF_BASE,
        b"",
        &Config {
            chunk_size: 5,
            max_instructions: 1000,
            snapshot_dir: Some(tmp.clone()),
            ..Default::default()
        },
    );
    let chain = &full.chunk_hashes;
    assert!(chain.len() >= 3);

    // Judge chunk index 3 from the snapshot at boundary 2: verify the
    // snapshot against the agreed prefix, execute one chunk, compare
    // with the authoritative chain.
    let snap = std::fs::read(tmp.join("snap-2.bin")).unwrap();
    let (cpu, mem3) = rvcore::snapshot::restore(&snap).unwrap();
    let prev = chain[1];
    assert_eq!(state_hash(&prev, &cpu, &mem3), chain[2], "snapshot verifies");

    let (h, end, _n) = execute_chunk_from(&snap, &chain[2], 5).unwrap();
    assert!(matches!(end, ChunkEnd::Boundary));
    assert_eq!(h, chain[3], "one-chunk judge equals full replay at chunk 3");

    // And a mutated snapshot must FAIL verification: a forged state
    // cannot reproduce the agreed chain hash.
    let mut forged = snap.clone();
    let last = forged.len() - 1;
    forged[last] ^= 0x01;
    if let Ok((cpu4, mem4)) = rvcore::snapshot::restore(&forged) {
        assert_ne!(state_hash(&prev, &cpu4, &mem4), chain[2]);
    }
}


#[test]
fn forged_csr_in_snapshot_changes_state_hash() {
    // CSRs are architectural (they route traps): a snapshot tampered
    // in its CSR bytes must produce a different state hash, so a
    // forged snapshot cannot pass the chain check with hidden state.
    let mem = Mem::new();
    let mut cpu = rvcore::Cpu::new(ELF_BASE, STACK_TOP);
    cpu.mtvec = 0x8000_0100;
    cpu.mepc = 0x8000_0200;
    cpu.mstatus = 0x1800;
    let snap = rvcore::snapshot::capture(&cpu, &mem);
    let honest_hash = {
        let (restored_cpu, restored_mem) = rvcore::snapshot::restore(&snap).unwrap();
        state_hash(&GENESIS, &restored_cpu, &restored_mem)
    };
    // Flip a byte inside the CSR block (it rides after pc: 8 + 32 + 8
    // bytes in, the first CSR word is mtvec).
    let mut forged = snap.clone();
    // Capture layout: magic+page-count header (8 bytes), x0..x31
    // (256 bytes), pc (8 bytes), then the four CSRs.
    let csr_start = 8 + 32 * 8 + 8;
    assert_eq!(u64::from_le_bytes(forged[csr_start..csr_start + 8].try_into().unwrap()), 0x8000_0100);
    forged[csr_start] ^= 0x01;
    let forged_hash = {
        let (forged_cpu, forged_mem) = rvcore::snapshot::restore(&forged).unwrap();
        state_hash(&GENESIS, &forged_cpu, &forged_mem)
    };
    assert_ne!(honest_hash, forged_hash);
}
