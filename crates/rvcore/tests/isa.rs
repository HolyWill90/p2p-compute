use abi::{ELF_BASE, INPUT_DATA_ADDR, INPUT_LEN_ADDR, OUTPUT_DATA_ADDR, OUTPUT_LEN_ADDR, STACK_TOP};
use rvcore::cpu::Cpu;
use rvcore::interp::{step, Config, Trap};
use rvcore::mem::Mem;

// ---- instruction encoders (test-side; the interpreter decodes, these build) ----

fn r_type(f7: u32, rs2: u32, rs1: u32, f3: u32, rd: u32, op: u32) -> u32 {
    (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
}
fn i_type(imm: i64, rs1: u32, f3: u32, rd: u32, op: u32) -> u32 {
    (((imm as u32) & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
}
fn s_type(imm: i64, rs2: u32, rs1: u32, f3: u32, op: u32) -> u32 {
    let i = imm as u32 & 0xfff;
    ((i >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | ((i & 0x1f) << 7) | op
}
fn b_type(imm: i64, rs2: u32, rs1: u32, f3: u32) -> u32 {
    let i = imm as u32;
    let b12 = (i >> 12) & 1;
    let b11 = (i >> 11) & 1;
    let b10_5 = (i >> 5) & 0x3f;
    let b4_1 = (i >> 1) & 0xf;
    (b12 << 31) | (b10_5 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (b4_1 << 8) | (b11 << 7) | 0b1100011
}
fn u_type(imm20: u32, rd: u32, op: u32) -> u32 {
    (imm20 << 12) | (rd << 7) | op
}
fn j_type(imm: i64, rd: u32) -> u32 {
    let i = imm as u32;
    let b20 = (i >> 20) & 1;
    let b10_1 = (i >> 1) & 0x3ff;
    let b11 = (i >> 11) & 1;
    let b19_12 = (i >> 12) & 0xff;
    (b20 << 31) | (b19_12 << 12) | (b11 << 20) | (b10_1 << 21) | (rd << 7) | 0b1101111
}

const OP: u32 = 0b0110011;
const OP32: u32 = 0b0111011;
const OPIMM: u32 = 0b0010011;
const OPIMM32: u32 = 0b0011011;
const LOAD: u32 = 0b0000011;
const STORE: u32 = 0b0100011;
const SYSTEM: u32 = 0b1110011;

fn ebreak() -> u32 {
    (1 << 20) | SYSTEM
}

fn load_program(mem: &mut Mem, insts: &[u32]) {
    let mut base = ELF_BASE;
    for inst in insts {
        mem.load_image(base, &inst.to_le_bytes()).unwrap();
        base += 4;
    }
}

/// Execute a program until halt; panic on trap.
fn exec(insts: &[u32], setup: impl FnOnce(&mut Mem)) -> (Cpu, Mem) {
    let mut mem = Mem::new();
    load_program(&mut mem, insts);
    setup(&mut mem);
    let mut cpu = Cpu::new(ELF_BASE, STACK_TOP);
    loop {
        match step(&mut cpu, &mut mem) {
            Ok(true) => break,
            Ok(false) => {}
            Err(t) => panic!("unexpected trap {t:?}"),
        }
    }
    (cpu, mem)
}

fn exec_trap(insts: &[u32], setup: impl FnOnce(&mut Mem)) -> Trap {
    let mut mem = Mem::new();
    load_program(&mut mem, insts);
    setup(&mut mem);
    let mut cpu = Cpu::new(ELF_BASE, STACK_TOP);
    loop {
        match step(&mut cpu, &mut mem) {
            Ok(true) => panic!("expected a trap, got halt"),
            Ok(false) => {}
            Err(t) => return t,
        }
    }
}

#[test]
fn arithmetic_basics() {
    let (cpu, _) = exec(
        &[
            i_type(7, 0, 0, 5, OPIMM),
            i_type(-3, 0, 0, 6, OPIMM),
            r_type(0, 6, 5, 0, 7, OP),           // add
            r_type(0b0100000, 6, 5, 0, 8, OP),   // sub
            ebreak(),
        ],
        |_| {},
    );
    assert_eq!(cpu.get(5), 7);
    assert_eq!(cpu.get(6), (-3i64) as u64);
    assert_eq!(cpu.get(7), 4);
    assert_eq!(cpu.get(8), 10);
}

#[test]
fn lui_auipc_slli() {
    let (cpu, _) = exec(
        &[
            u_type(0xdeadb, 5, 0b0110111), // lui → sign-extended 0xFFFFFFFF_DEADB000
            i_type(5, 0, 0, 6, OPIMM),     // x6 = 5
            i_type(4, 6, 1, 6, OPIMM),     // x6 = 80
            u_type(1, 7, 0b0010111),       // auipc at ELF_BASE+12 → +0x1000
            ebreak(),
        ],
        |_| {},
    );
    assert_eq!(cpu.get(5), 0xFFFF_FFFF_DEAD_B000);
    assert_eq!(cpu.get(6), 80);
    assert_eq!(cpu.get(7), ELF_BASE + 12 + 0x1000);
}

#[test]
fn mul_high_bits() {
    // x5 = 2^32: lui gives 0x10000, shift left 16 more
    // mulhu(2^32, 2^32) = high(2^64) = 1, mulh (both positive) = 1
    // (x5·x5 low bits would be 0 — the high multiply must use the
    // same full-width operands, not the truncated product.)
    let (cpu, _) = exec(
        &[
            u_type(0x10, 5, 0b0110111),
            i_type(16, 5, 1, 5, OPIMM),
            r_type(1, 5, 5, 0, 6, OP),
            r_type(1, 5, 5, 3, 7, OP),
            r_type(1, 5, 5, 1, 8, OP),
            ebreak(),
        ],
        |_| {},
    );
    assert_eq!(cpu.get(5), 1u64 << 32);
    assert_eq!(cpu.get(6), 0);
    assert_eq!(cpu.get(7), 1);
    assert_eq!(cpu.get(8), 1);
}

#[test]
fn mul_high_negative_operands() {
    // Regression (found by the QEMU conformance differential): u64 as
    // i128 zero-extends, which silently turned mulh into mulhu for
    // negative operands. mulh(-1, -1) = high(1) = 0;
    // mulhsu(-1, u64::MAX) = high(-(2^64-1)) = all ones;
    // mulh(i64::MIN, i64::MIN) = high(2^126) = 2^62.
    let (cpu, _) = exec(
        &[
            i_type(-1, 0, 0, 5, OPIMM),
            r_type(1, 5, 5, 1, 6, OP),
            r_type(1, 5, 5, 2, 7, OP),
            i_type(63, 5, 1, 11, OPIMM),
            r_type(1, 11, 11, 1, 12, OP),
            ebreak(),
        ],
        |_| {},
    );
    assert_eq!(cpu.get(6), 0);
    assert_eq!(cpu.get(7), u64::MAX);
    assert_eq!(cpu.get(11), i64::MIN as u64);
    assert_eq!(cpu.get(12), 1u64 << 62);
}

#[test]
fn division_by_zero() {
    let (cpu, _) = exec(
        &[
            i_type(-5, 0, 0, 5, OPIMM),            // x5 = -5
            i_type(7, 0, 0, 7, OPIMM),             // x7 = 7
            i_type(-3, 0, 0, 8, OPIMM),            // x8 = -3
            r_type(1, 0, 5, 4, 9, OP),             // div  x9  = -5 / 0 → -1
            r_type(1, 0, 5, 6, 10, OP),            // rem  x10 = -5 % 0 → -5
            r_type(1, 8, 7, 4, 11, OP),            // div  x11 = 7 / -3 → -2 (truncate to zero)
            r_type(1, 8, 7, 6, 12, OP),            // rem  x12 = 7 % -3 → 1
            ebreak(),
        ],
        |_| {},
    );
    assert_eq!(cpu.get(9), u64::MAX);
    assert_eq!(cpu.get(10), (-5i64) as u64);
    assert_eq!(cpu.get(11), (-2i64) as u64);
    assert_eq!(cpu.get(12), 1);
}

#[test]
fn div_signed_overflow() {
    let (cpu, _) = exec(
        &[
            i_type(-1, 0, 0, 5, OPIMM),          // x5 = -1
            i_type(63, 5, 1, 11, OPIMM),         // slli x11, x5, 63 → i64::MIN
            r_type(1, 5, 11, 4, 12, OP),         // div x12, x11, x5 = MIN / -1 → MIN
            r_type(1, 5, 11, 6, 13, OP),         // rem x13, x11, x5 = MIN % -1 → 0
            r_type(1, 0, 11, 4, 14, OP),         // div x14, x11, x0 = MIN / 0 → -1
            r_type(1, 0, 11, 6, 15, OP),         // rem x15, x11, x0 = MIN % 0 → MIN
            ebreak(),
        ],
        |_| {},
    );
    assert_eq!(cpu.get(11), i64::MIN as u64);
    assert_eq!(cpu.get(12), i64::MIN as u64);
    assert_eq!(cpu.get(13), 0);
    assert_eq!(cpu.get(14), u64::MAX);
    assert_eq!(cpu.get(15), i64::MIN as u64);
}

#[test]
fn w_form_sign_extension() {
    let (cpu, _) = exec(
        &[
            i_type(-1, 0, 0, 5, OPIMM32),               // addiw → 0xFFFFFFFFFFFFFFFF
            i_type(1, 5, 1, 6, OPIMM32),                // slliw → 0xFFFFFFFFFFFFFFFE
            i_type(28, 6, 5, 7, OPIMM32),               // srliw → (0xFFFFFFFE >> 28) = 0xF
            i_type((0b0100000 << 5) | 31, 6, 0b101, 8, OPIMM32), // sraiw x8, x6, 31 → -1
            ebreak(),
        ],
        |_| {},
    );
    assert_eq!(cpu.get(5), u64::MAX);
    assert_eq!(cpu.get(6), 0xFFFFFFFF_FFFFFFFE);
    assert_eq!(cpu.get(7), 15);
    assert_eq!(cpu.get(8), u64::MAX);
}

#[test]
fn loads_stores_roundtrip() {
    let (cpu, mem) = exec(
        &[
            u_type(0x40000, 5, 0b0110111), // x5 = 0x4000_0000
            i_type(-2, 0, 0, 6, OPIMM),    // x6 = -2
            s_type(0, 6, 5, 2, STORE),     // sw [x5] = 0xFFFFFFFE
            r_type(0, 5, 5, 3, 7, OP),     // x7 = 0x8000_0000
            i_type(0, 5, 2, 8, LOAD),      // lw x8 → sign-extended -2
            s_type(0, 6, 7, 0, STORE),     // sb [x7] = 0xFE
            i_type(0, 7, 0, 9, LOAD),      // lb x9 → -2
            ebreak(),
        ],
        |_| {},
    );
    assert_eq!(cpu.get(8), (-2i64) as u64);
    assert_eq!(cpu.get(9), (-2i64) as u64);
    assert_eq!(mem.read(0x4000_0000, 4).unwrap(), 0xFFFF_FFFEu64);
}

#[test]
fn branches_and_jumps() {
    let (cpu, _) = exec(
        &[
            i_type(5, 0, 0, 5, OPIMM),  // x5 = 5
            b_type(8, 0, 5, 0b000),     // beq x5, x0, +8 → not taken
            i_type(1, 0, 0, 6, OPIMM),  // executed
            j_type(8, 1),               // jal x1 → skip next
            i_type(99, 0, 0, 7, OPIMM), // skipped
            ebreak(),
        ],
        |_| {},
    );
    assert_eq!(cpu.get(6), 1);
    assert_eq!(cpu.get(7), 0);
    // jal is the 4th instruction (ELF_BASE+12); its link value is pc+4.
    assert_eq!(cpu.get(1), ELF_BASE + 4 * 4);
}

#[test]
fn sltiu_compares_against_sign_extended_imm() {
    let (cpu, _) = exec(&[i_type(-1, 0, 0b011, 5, OPIMM), ebreak()], |_| {});
    assert_eq!(cpu.get(5), 1); // 0 < u64::MAX
}

#[test]
fn misaligned_load_supported() {
    // The platform supports misaligned accesses (spike/QEMU behavior):
    // the split read returns the correct composed value.
    let (cpu, _) = exec(
        &[
            u_type(0x000ab, 6, 0b0110111), // lui a2, 0xab — data base 0xab000
            i_type(1, 6, 2, 7, LOAD),      // lw a3, 1(a2) — misaligned
            ebreak(),
        ],
        |mem| {
            mem.write(0x000a_b001, &[0x01, 0x02, 0x03, 0x04]).unwrap();
        },
    );
    assert_eq!(cpu.get(7), 0x0403_0201);
}

#[test]
fn illegal_instruction_traps() {
    let t = exec_trap(&[0x0000_0000, ebreak()], |_| {});
    assert!(matches!(t, Trap::IllegalInstruction { .. }));
}

#[test]
fn ecall_traps() {
    let t = exec_trap(&[0x0000_0073, ebreak()], |_| {});
    assert!(matches!(t, Trap::Ecall));
}

#[test]
fn chunking_and_determinism() {
    let mut insts = Vec::new();
    for _ in 0..100 {
        insts.push(i_type(1, 5, 0, 5, OPIMM));
    }
    insts.push(ebreak());

    let run_once = |chunk: u64| {
        let mut mem = Mem::new();
        load_program(&mut mem, &insts);
        rvcore::interp::run(
            &mut mem,
            ELF_BASE,
            b"",
            &Config { chunk_size: chunk, max_instructions: 1000, ..Default::default() },
        )
    };

    let a = run_once(7);
    let b = run_once(7);
    assert_eq!(a.status, rvcore::ExitStatus::Halted);
    assert_eq!(a.instructions, 101);
    assert_eq!(a.chunk_hashes, b.chunk_hashes);
    // Boundaries after instructions 7..98 (14 hashes) plus the exit hash.
    assert_eq!(a.chunk_hashes.len(), 15);
    // A different chunk size is a different chain (different boundaries),
    // by construction:
    assert_ne!(a.chunk_hashes, run_once(11).chunk_hashes);
}

#[test]
fn input_output_abi_roundtrip() {
    let insts = vec![
        u_type(0x10000, 5, 0b0110111), // x5 = 0x10000 << 12 = 0x1000_0000 = INPUT_LEN_ADDR
        i_type(0, 5, 3, 6, LOAD),      // x6 = input length
        u_type(0x20000, 7, 0b0110111), // x7 = 0x20000 << 12 = 0x2000_0000 = OUTPUT_LEN_ADDR
        s_type(0, 6, 7, 3, STORE),     // store length to output header
        ebreak(),
    ];
    let mut mem = Mem::new();
    load_program(&mut mem, &insts);
    let input = b"hello deterministic world";
    let out = rvcore::interp::run(
        &mut mem,
        ELF_BASE,
        input,
        &Config { chunk_size: 4, max_instructions: 1000, ..Default::default() },
    );
    assert_eq!(out.status, rvcore::ExitStatus::Halted);
    let output = out.output.expect("output present");
    // The program stored the input length to the OUTPUT_LEN header,
    // which the emulator consumed; the data region itself is zeros.
    assert_eq!(output.len(), input.len());
    assert!(output.iter().all(|&b| b == 0));
    assert_eq!(mem.read(INPUT_LEN_ADDR, 8).unwrap(), input.len() as u64);
    assert_eq!(mem.read(INPUT_DATA_ADDR, 1).unwrap(), b'h' as u64);
    assert_eq!(mem.read(OUTPUT_LEN_ADDR, 8).unwrap(), input.len() as u64);
    // The program only wrote the header; the data region stays zero.
    assert_eq!(mem.read_region(OUTPUT_DATA_ADDR, 8).unwrap(), [0u8; 8].to_vec());
}

#[test]
fn w_form_division_edges() {
    // x11 = i32::MIN via slliw; x8 = -1 (as i32)
    // divw MIN/-1 → i32::MIN (sign-extended); remw MIN/-1 → 0
    // divw by zero → -1; remw by zero → dividend
    let (cpu, _) = exec(
        &[
            i_type(-1, 0, 0, 5, OPIMM32),               // x5 = -1 (sext)
            i_type(31, 5, 1, 11, OPIMM32),              // x11 = slliw(-1, 31) = i32::MIN sext
            r_type(1, 5, 11, 4, 12, OP32),              // divw  x12 = MIN/-1 → MIN sext
            r_type(1, 5, 11, 6, 13, OP32),              // remw  x13 = 0
            r_type(1, 0, 11, 4, 14, OP32),              // divw  x14 = MIN/0 → -1
            r_type(1, 0, 11, 6, 15, OP32),              // remw  x15 = MIN
            ebreak(),
        ],
        |_| {},
    );
    assert_eq!(cpu.get(11), i32::MIN as i64 as u64);
    assert_eq!(cpu.get(12), i32::MIN as i64 as u64);
    assert_eq!(cpu.get(13), 0);
    assert_eq!(cpu.get(14), u64::MAX);
    assert_eq!(cpu.get(15), i32::MIN as i64 as u64);
}

// ---- compressed (16-bit) instruction tests ----

/// Execute a program of 16-bit compressed instructions.
fn exec_c(hws: &[u16], setup: impl FnOnce(&mut Mem)) -> (Cpu, Mem) {
    let mut mem = Mem::new();
    let mut base = ELF_BASE;
    for hw in hws {
        mem.load_image(base, &hw.to_le_bytes()).unwrap();
        base += 2;
    }
    // ebreak (4 bytes) so the program halts cleanly.
    mem.load_image(base, &0x00100073u32.to_le_bytes()).unwrap();
    setup(&mut mem);
    let mut cpu = Cpu::new(ELF_BASE, STACK_TOP);
    loop {
        match step(&mut cpu, &mut mem) {
            Ok(true) => break,
            Ok(false) => {}
            Err(t) => panic!("unexpected trap {t:?}"),
        }
    }
    (cpu, mem)
}

#[test]
fn compressed_li_addi_slli() {
    // c.li a5, 3 ; c.addi a5, 2 ; c.slli a5, 40
    let (cpu, _) = exec_c(
        &[0x478D, 0x0789, 0x17A2],
        |_| {},
    );
    assert_eq!(cpu.get(15), 5u64 << 40);
}

#[test]
fn compressed_slli_40() {
    // c.li a5, 3 ; c.slli a5, 40 → 3 << 40
    let (cpu, _) = exec_c(&[0x478D, 0x17A2], |_| {});
    assert_eq!(cpu.get(15), 3u64 << 40);
}

#[test]
fn compressed_addi4spn() {
    // c.addi4spn x8, 24 → x8 = sp + 24
    let (cpu, _) = exec_c(&[0x0820], |_| {});
    assert_eq!(cpu.get(8), STACK_TOP + 24);
}

#[test]
fn compressed_sub_uses_rs1_prime_destination() {
    // Regression: the Q1 reg-reg group destination is inst[9:7], not
    // inst[4:2]. c.li a4, 10 ; c.li a5, 3 ; c.sub a4, a4, a5 → a4 = 7.
    // c.li a4, 10: op=01 f3=010 rd=14 imm=10 → 0x4729
    // c.li a5, 3:  0x478D
    // c.sub: f3=100 funct2=11 rd'=6(x14) rs2'=7(x15) fn=00 → 0x8F1D
    let (cpu, _) = exec_c(&[0x4729, 0x478D, 0x8F1D], |_| {});
    assert_eq!(cpu.get(14), 7);
    assert_eq!(cpu.get(15), 3);
}

#[test]
fn division_by_zero_unsigned_exact_spec() {
    // Regression (external audit): DIVU by zero returns ALL BITS SET,
    // not the dividend; DIVUW by zero returns sext32(0xFFFFFFFF).
    // REMU by zero returns the (64-bit) dividend; REMUW by zero the
    // sign-extended 32-bit dividend.
    let (cpu, _) = exec(
        &[
            u_type(0x12345, 5, 0b0110111),        // x5 = 0x12345000
            i_type(0x678, 5, 0, 5, OPIMM),        // x5 = 0x12345678
            r_type(1, 0, 5, 5, 9, OP),            // divu  x9,  x5, x0 → u64::MAX
            r_type(1, 0, 5, 7, 10, OP),           // remu  x10, x5, x0 → x5
            r_type(1, 0, 5, 4, 11, OP32),         // divuw x11, x5, x0 → u64::MAX
            r_type(1, 0, 5, 7, 12, OP32),         // remuw x12, x5, x0 → sext32(0x12345678)
            ebreak(),
        ],
        |_| {},
    );
    assert_eq!(cpu.get(9), u64::MAX);
    assert_eq!(cpu.get(10), 0x12345678);
    assert_eq!(cpu.get(11), u64::MAX);
    assert_eq!(cpu.get(12), 0x12345678u32 as i32 as i64 as u64);
}

#[test]
fn compressed_subw_addw() {
    // Regression (external audit): bit12 selects C.SUBW/C.ADDW inside
    // the Q1 f3=100 group; it was ignored, decoding C.SUBW as C.SUB.
    // c.li a2, 5 → 0x4615 ; c.li a3, 3 → 0x468D
    // c.subw a2, a3 → funct4=100111, rd'=4(x12), [6:5]=00, rs2'=5 → 0x9E15 → 2
    let (cpu, _) = exec_c(&[0x4615, 0x468D, 0x9E15], |_| {});
    assert_eq!(cpu.get(13), 3);
    assert_eq!(cpu.get(12) as i32, 2, "c.subw: 5 - 3");
}

#[test]
fn compressed_addw_distinct_from_xor() {
    // C.ADDW (bit12=1, [6:5]=01) must not decode as C.XOR:
    // 5 + 3 = 8 but 5 ^ 3 = 6 — the two must disagree.
    // c.li a2, 5 ; c.li a3, 3 ; c.addw a2, a3 → funct4=100111, [6:5]=01 → 0x9E35
    let (cpu, _) = exec_c(&[0x4615, 0x468D, 0x9E35], |_| {});
    assert_eq!(cpu.get(12), 8, "C.ADDW must add (C.XOR would give 6)");
}
