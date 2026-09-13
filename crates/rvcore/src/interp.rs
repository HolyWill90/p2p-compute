use crate::cpu::Cpu;
use crate::hash::{state_hash, Hash, GENESIS};
use crate::mem::{Mem, ADDR_SPACE};
use abi::{INPUT_DATA_ADDR, INPUT_LEN_ADDR, OUTPUT_DATA_ADDR, OUTPUT_LEN_ADDR, OUTPUT_MAX, STACK_TOP};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trap {
    FetchUnaligned,
    FetchOutOfRange,
    IllegalInstruction { pc: u64, inst: u32 },
    MisalignedLoad { addr: u64 },
    MisalignedStore { addr: u64 },
    LoadOutOfRange { addr: u64 },
    StoreOutOfRange { addr: u64 },
    Ecall,
    OutputTooLarge,
}

/// Execution is pinned to RV64IMC (see abi::ISA): integer,
/// multiply/divide, and compressed instructions. Atomics (lr/sc) and
/// the FP extensions are outside the contract: jobs are compiled with
/// `-C target-feature=-a`. Compressed 16-bit encodings are decoded by
/// `step_c` below.
pub fn step(cpu: &mut Cpu, mem: &mut Mem) -> Result<bool, Trap> {
    step_mode(cpu, mem, false)
}

/// Like [`step`], with the QEMU-compatible syscall environment enabled
/// or disabled. In syscall mode `ecall` dispatches Linux ABIs
/// (write=64, exit=93) instead of trapping, so the same static ELF can
/// run under both this emulator and `qemu-riscv64` for the conformance
/// differential.
pub fn step_mode(cpu: &mut Cpu, mem: &mut Mem, syscalls: bool) -> Result<bool, Trap> {
    let pc = cpu.pc;
    if pc >= ADDR_SPACE {
        return Err(Trap::FetchOutOfRange);
    }
    // C-capable fetch: instructions are 16-bit aligned; a 32-bit
    // instruction additionally requires 4-bit alignment.
    if pc % 2 != 0 {
        return Err(Trap::FetchUnaligned);
    }
    let hw = match mem.read(pc, 2) {
        Ok(v) => v as u16,
        Err(_) => return Err(Trap::FetchOutOfRange),
    };
    if hw & 0b11 != 0b11 {
        return step_c(cpu, mem, pc, hw);
    }
    // 32-bit instruction: with C, 2-byte alignment is legal. The upper
    // half comes from pc+2 (little-endian).
    let inst = ((mem.read(pc + 2, 2).map_err(|_| Trap::FetchOutOfRange)? as u32) << 16) | hw as u32;

    let opcode = inst & 0x7f;
    let rd = (inst >> 7) & 0x1f;
    let f3 = (inst >> 12) & 0x7;
    let rs1 = (inst >> 15) & 0x1f;
    let rs2 = (inst >> 20) & 0x1f;
    let f7 = (inst >> 25) & 0x7f;

    let a = cpu.get(rs1);
    let b = cpu.get(rs2);
    let next_pc = pc.wrapping_add(4);

    // Immediate encoders. All sign extension is done in the widest
    // signed type first so the behavior is exactly the spec.
    let imm_i = (inst as i32 >> 20) as i64;
    let imm_s = ((((inst as i32) >> 20) & !0x1f) as i64) | ((inst >> 7) & 0x1f) as i64;
    let imm_b = {
        let v = (((inst >> 31) & 1) << 12)
            | (((inst >> 7) & 1) << 11)
            | (((inst >> 25) & 0x3f) << 5)
            | (((inst >> 8) & 0xf) << 1);
        ((v << 19) as i32 >> 19) as i64
    };
    let imm_u = ((inst & 0xffff_f000) as u32 as i32) as i64 as u64;
    let imm_j = {
        let v = (((inst >> 31) & 1) << 20)
            | (((inst >> 12) & 0xff) << 12)
            | (((inst >> 20) & 1) << 11)
            | (((inst >> 21) & 0x3ff) << 1);
        ((v << 11) as i32 >> 11) as i64
    };

    match opcode {
        0b0110111 => {
            // LUI
            cpu.set(rd, imm_u);
            cpu.pc = next_pc;
        }
        0b0010111 => {
            // AUIPC
            cpu.set(rd, pc.wrapping_add(imm_u));
            cpu.pc = next_pc;
        }
        0b1101111 => {
            // JAL
            cpu.set(rd, next_pc);
            cpu.pc = pc.wrapping_add(imm_j as u64);
        }
        0b1100111 => {
            if f3 != 0 {
                return Err(illegal(pc, inst));
            }
            // JALR
            let target = a.wrapping_add(imm_i as u64) & !1u64;
            cpu.set(rd, next_pc);
            cpu.pc = target;
        }
        0b1100011 => {
            // Branches
            let taken = match f3 {
                0b000 => a == b,
                0b001 => a != b,
                0b100 => (a as i64) < (b as i64),
                0b101 => (a as i64) >= (b as i64),
                0b110 => a < b,
                0b111 => a >= b,
                _ => return Err(illegal(pc, inst)),
            };
            cpu.pc = if taken { pc.wrapping_add(imm_b as u64) } else { next_pc };
        }
        0b0000011 => {
            // Loads
            let addr = a.wrapping_add(imm_i as u64);
            let (len, sign_ext): (usize, bool) = match f3 {
                0b000 => (1, true),
                0b001 => (2, true),
                0b010 => (4, true),
                0b011 => (8, false),
                0b100 => (1, false),
                0b101 => (2, false),
                0b110 => (4, false),
                _ => return Err(illegal(pc, inst)),
            };
            let val = match mem.read(addr, len) {
                Ok(v) => v,
                Err(e) => return Err(trap_load(e, addr)),
            };
            let val = if sign_ext {
                match len {
                    1 => (val as u8 as i8) as i64 as u64,
                    2 => (val as u16 as i16) as i64 as u64,
                    _ => (val as u32 as i32) as i64 as u64,
                }
            } else {
                val
            };
            cpu.set(rd, val);
            cpu.pc = next_pc;
        }
        0b0100011 => {
            // Stores
            let addr = a.wrapping_add(imm_s as u64);
            let len = match f3 {
                0b000 => 1,
                0b001 => 2,
                0b010 => 4,
                0b011 => 8,
                _ => return Err(illegal(pc, inst)),
            };
            let bytes = b.to_le_bytes();
            match mem.write(addr, &bytes[..len]) {
                Ok(()) => {}
                Err(e) => return Err(trap_store(e, addr)),
            }
            cpu.pc = next_pc;
        }
        0b0010011 => {
            // OP-IMM
            let val = match f3 {
                0b000 => a.wrapping_add(imm_i as u64),
                0b010 => (((a as i64) < imm_i) as u64),
                0b011 => (a < imm_i as u64) as u64,
                0b100 => a ^ (imm_i as u64),
                0b110 => a | (imm_i as u64),
                0b111 => a & (imm_i as u64),
                0b001 => {
                    // RV64: 6-bit shamt lives at [25:20]; the shift funct
                    // is bits [31:26] — NOT the 7-bit f7, which overlaps
                    // shamt bit 5.
                    if (inst >> 26) & 0x3f != 0 {
                        return Err(illegal(pc, inst));
                    }
                    a.wrapping_shl((inst >> 20) as u32 & 63)
                }
                0b101 => match (inst >> 26) & 0x3f {
                    0b000000 => a.wrapping_shr((inst >> 20) as u32 & 63),
                    0b010000 => ((a as i64) >> ((inst >> 20) as u32 & 63)) as u64,
                    _ => return Err(illegal(pc, inst)),
                },
                _ => unreachable!(),
            };
            cpu.set(rd, val);
            cpu.pc = next_pc;
        }
        0b0011011 => {
            // OP-IMM-32 (W-form immediates)
            let val = match f3 {
                0b000 => ((a as u32).wrapping_add(imm_i as u32)) as i32 as u64,
                0b001 => {
                    if f7 != 0 {
                        return Err(illegal(pc, inst));
                    }
                    (((a as u32).wrapping_shl((inst >> 20) as u32 & 31)) as i32) as u64
                }
                0b101 => match f7 {
                    0b0000000 => (((a as u32).wrapping_shr((inst >> 20) as u32 & 31)) as i32) as u64,
                    0b0100000 => (((a as i32) >> ((inst >> 20) as u32 & 31)) as i32) as u64,
                    _ => return Err(illegal(pc, inst)),
                },
                _ => return Err(illegal(pc, inst)),
            };
            cpu.set(rd, val);
            cpu.pc = next_pc;
        }
        0b0110011 => {
            // OP (register-register)
            let val = match (f7, f3) {
                (0b0000000, 0b000) => a.wrapping_add(b),
                (0b0100000, 0b000) => a.wrapping_sub(b),
                (0b0000000, 0b001) => a.wrapping_shl((b & 63) as u32),
                (0b0000000, 0b010) => ((a as i64) < (b as i64)) as u64,
                (0b0000000, 0b011) => (a < b) as u64,
                (0b0000000, 0b100) => a ^ b,
                (0b0000000, 0b101) => a.wrapping_shr((b & 63) as u32),
                (0b0100000, 0b101) => ((a as i64) >> (b & 63)) as u64,
                (0b0000000, 0b110) => a | b,
                (0b0000000, 0b111) => a & b,
                (0b0000001, 0b000) => a.wrapping_mul(b),
                (0b0000001, 0b001) => (((a as i64 as i128) * (b as i64 as i128)) >> 64) as u64,
                // mulhsu: rs1 signed, rs2 unsigned — u64→i128 zero-extends,
                // which is exactly right for the unsigned operand, while
                // u64→i64→i128 sign-extends the signed one.
                (0b0000001, 0b010) => {
                    (((a as i64 as i128).wrapping_mul(b as i128)) >> 64) as u64
                }
                (0b0000001, 0b011) => ((a as u128 * b as u128) >> 64) as u64,
                (0b0000001, 0b100) => match (a as i64).checked_div(b as i64) {
                    Some(q) => q as u64,
                    None if b == 0 => u64::MAX,
                    None => i64::MIN as u64, // MIN / -1
                },
                (0b0000001, 0b101) => if b == 0 { u64::MAX } else { a / b },
                (0b0000001, 0b110) => match (a as i64).checked_rem(b as i64) {
                    Some(r) => r as u64,
                    None if b == 0 => a,           // rem by zero: dividend
                    None => 0,                     // MIN % -1
                },
                (0b0000001, 0b111) => if b == 0 { a } else { a % b },
                _ => return Err(illegal(pc, inst)),
            };
            cpu.set(rd, val);
            cpu.pc = next_pc;
        }
        0b0111011 => {
            // OP-32
            let val = match (f7, f3) {
                (0b0000000, 0b000) => ((a as u32).wrapping_add(b as u32)) as i32 as u64,
                (0b0100000, 0b000) => ((a as u32).wrapping_sub(b as u32)) as i32 as u64,
                (0b0000000, 0b001) => (((a as u32).wrapping_shl((b & 31) as u32)) as i32) as u64,
                (0b0000000, 0b101) => (((a as u32) >> (b & 31)) as i32) as u64,
                (0b0100000, 0b101) => (((a as i32) >> (b & 31)) as i32) as u64,
                (0b0000001, 0b000) => ((a as i32).wrapping_mul(b as i32)) as i32 as u64,
                (0b0000001, 0b100) => match (a as i32).checked_div(b as i32) {
                    Some(q) => q as i64 as u64,
                    None if b == 0 => u64::MAX, // -1 sign-extended
                    None => i32::MIN as i64 as u64,
                },
                (0b0000001, 0b101) => if b == 0 { u64::MAX } else { ((a as u32) / (b as u32)) as i32 as u64 },
                (0b0000001, 0b110) => match (a as i32).checked_rem(b as i32) {
                    Some(r) => r as i64 as u64,
                    None if b == 0 => (a as i32) as i64 as u64, // sext32(dividend)
                    None => 0,
                },
                (0b0000001, 0b111) => {
                    if b == 0 {
                        (a as u32) as i32 as u64 // sext32(dividend)
                    } else {
                        ((a as u32) % (b as u32)) as i32 as u64
                    }
                }
                _ => return Err(illegal(pc, inst)),
            };
            cpu.set(rd, val);
            cpu.pc = next_pc;
        }
        0b0001111 => {
            // FENCE: no-op in the single-hart deterministic model
            cpu.pc = next_pc;
        }
        0b1110011 => {
            if f3 != 0 {
                return Err(illegal(pc, inst));
            }
            match inst >> 20 {
                0 => {
                    if syscalls {
                        return do_syscall(cpu, mem);
                    }
                    return Err(Trap::Ecall);
                }
                1 => return Ok(true), // EBREAK: clean halt, pc stays put
                _ => return Err(illegal(pc, inst)),
            }
        }
        _ => return Err(illegal(pc, inst)),
    }
    Ok(false)
}

fn illegal(pc: u64, inst: u32) -> Trap {
    Trap::IllegalInstruction { pc, inst }
}

/// Compressed (16-bit) instruction decode, RV64C subset of the pin:
/// integer register/compressed-register ops only; the FP compressed
/// encodings are illegal. Hint encodings (rd = x0) execute as nops,
/// reserved encodings trap — both choices are deterministic.
fn step_c(cpu: &mut Cpu, mem: &mut Mem, pc: u64, hw: u16) -> Result<bool, Trap> {
    let bad = || Trap::IllegalInstruction { pc, inst: hw as u32 };
    let next_pc = pc.wrapping_add(2);
    // Compressed register fields: rs1'/rd' map onto x8..x15.
    let creg = |i: u16| 8 + i as u32;
    let op = hw & 0b11;
    let f3 = (hw >> 13) & 0b111;

    // Fetch operands shared across quadrants.
    let rd_c = creg((hw >> 2) & 0b111);
    let rs1_c = creg((hw >> 7) & 0b111);
    let rs2_c = creg((hw >> 2) & 0b111);
    let sp = cpu.get(2);

    match op {
        0b00 => {
            // Q0: c.addi4spn, then SP-less loads/stores on compressed regs.
            if f3 == 0b000 {
                // c.addi4spn: nzuimm[5:4|9:6|2|3]; imm == 0 is reserved.
                let imm = (((hw >> 11) & 0x3) << 4)
                    | (((hw >> 7) & 0xf) << 6)
                    | (((hw >> 6) & 0x1) << 2)
                    | (((hw >> 5) & 0x1) << 3);
                if imm == 0 {
                    return Err(bad());
                }
                cpu.set(rd_c, sp.wrapping_add(imm as u64));
                cpu.pc = next_pc;
                return Ok(false);
            }
            match f3 {
                0b001 | 0b101 => Err(bad()), // c.fld / c.fsd: FP, not in the pin
                0b010 => {
                    // c.lw: uimm[5:3|2|6]
                    let imm = (((hw >> 10) & 0x7) << 3)
                        | (((hw >> 6) & 0x1) << 2)
                        | (((hw >> 5) & 0x1) << 6);
                    let addr = cpu.get(rs1_c).wrapping_add(imm as u64);
                    let v = mem.read(addr, 4).map_err(|e| trap_load(e, addr))?;
                    cpu.set(rd_c, (v as u32 as i32) as i64 as u64);
                    cpu.pc = next_pc;
                    Ok(false)
                }
                0b011 => {
                    // c.ld: uimm[5:3|7:6]
                    let imm = (((hw >> 10) & 0x7) << 3) | (((hw >> 5) & 0x3) << 6);
                    let addr = cpu.get(rs1_c).wrapping_add(imm as u64);
                    let v = mem.read(addr, 8).map_err(|e| trap_load(e, addr))?;
                    cpu.set(rd_c, v);
                    cpu.pc = next_pc;
                    Ok(false)
                }
                0b110 => {
                    // c.sw: same immediate layout as c.lw
                    let imm = (((hw >> 10) & 0x7) << 3)
                        | (((hw >> 6) & 0x1) << 2)
                        | (((hw >> 5) & 0x1) << 6);
                    let addr = cpu.get(rs1_c).wrapping_add(imm as u64);
                    let b = cpu.get(rs2_c).to_le_bytes();
                    mem.write(addr, &b[..4]).map_err(|e| trap_store(e, addr))?;
                    cpu.pc = next_pc;
                    Ok(false)
                }
                0b111 => {
                    // c.sd: same immediate layout as c.ld
                    let imm = (((hw >> 10) & 0x7) << 3) | (((hw >> 5) & 0x3) << 6);
                    let addr = cpu.get(rs1_c).wrapping_add(imm as u64);
                    let b = cpu.get(rs2_c).to_le_bytes();
                    mem.write(addr, &b).map_err(|e| trap_store(e, addr))?;
                    cpu.pc = next_pc;
                    Ok(false)
                }
                _ => Err(bad()),
            }
        }
        0b01 => {
            let rd = ((hw >> 7) & 0x1f) as u32;
            // 6-bit signed immediate shared by c.addi/c.li/c.addiw:
            // nzimm[5] = inst[12], nzimm[4:0] = inst[6:2].
            let imm6 = (((hw >> 12) & 0x1) as i64 * -32 + ((hw >> 2) & 0x1f) as i64) as u64;
            match f3 {
                0b001 => {
                    // c.addiw (RV64): 32-bit add, sign-extend result.
                    if rd == 0 {
                        cpu.pc = next_pc;
                        return Ok(false); // hint
                    }
                    let v = ((cpu.get(rd) as u32).wrapping_add(imm6 as u32)) as i32 as u64;
                    cpu.set(rd, v);
                    cpu.pc = next_pc;
                    Ok(false)
                }
                0b010 => {
                    // c.li
                    cpu.set(rd, imm6);
                    cpu.pc = next_pc;
                    Ok(false)
                }
                0b011 => {
                    if rd == 2 {
                        // c.addi16sp: nzimm[9|4|6|8:7|5]
                        let imm = ((((hw >> 12) & 0x1) as u64) << 9)
                            | ((((hw >> 6) & 0x1) as u64) << 4)
                            | ((((hw >> 5) & 0x1) as u64) << 6)
                            | ((((hw >> 3) & 0x3) as u64) << 7)
                            | ((((hw >> 2) & 0x1) as u64) << 5);
                        let imm = ((imm << 54) as i64) >> 54; // sext 10 bits
                        if imm == 0 {
                            return Err(bad());
                        }
                        cpu.set(2, sp.wrapping_add(imm as u64));
                    } else {
                        // c.lui: nzimm[17|16:12] → value = sext(imm17)
                        if rd == 0 {
                            cpu.pc = next_pc;
                            return Ok(false); // hint
                        }
                        let imm = ((((hw >> 12) & 0x1) as u64) << 17)
                            | ((((hw >> 2) & 0x1f) as u64) << 12);
                        let imm = ((imm << 46) as i64) >> 46; // sext 18 bits
                        if imm == 0 {
                            return Err(bad());
                        }
                        cpu.set(rd, imm as u64);
                    }
                    cpu.pc = next_pc;
                    Ok(false)
                }
                0b100 => {
                    // Arithmetic on compressed registers. The destination
                    // is rs1' (inst[9:7]) here — NOT inst[4:2], which is
                    // the rd' field of the Q0 loads and the shamt/rs2'
                    // operand of this very group.
                    let dest = rs1_c;
                    match (hw >> 10) & 0b11 {
                        0b00 | 0b01 => {
                            // c.srli / c.srai: shamt = inst[12]:5 bits (RV64 6-bit)
                            let shamt = (((hw >> 12) & 0x1) << 5) | ((hw >> 2) & 0x1f) as u16;
                            if shamt == 0 {
                                return Err(bad()); // reserved in RV64
                            }
                            let a = cpu.get(dest);
                            let v = match (hw >> 10) & 0b11 {
                                0b00 => a.wrapping_shr(shamt as u32),
                                _ => ((a as i64) >> shamt) as u64,
                            };
                            cpu.set(dest, v);
                        }
                        0b10 => {
                            // c.andi: 6-bit signed immediate
                            cpu.set(dest, (cpu.get(dest) & imm6) as u64);
                        }
                        _ => {
                            // bit12=0: c.sub/c.xor/c.or/c.and;
                            // bit12=1 (RV64C): c.subw/c.addw, 10/11 reserved.
                            let b = cpu.get(rs2_c);
                            let a = cpu.get(dest);
                            if (hw >> 12) & 0x1 == 0 {
                                let v = match (hw >> 5) & 0b11 {
                                    0b00 => a.wrapping_sub(b),
                                    0b01 => a ^ b,
                                    0b10 => a | b,
                                    _ => a & b,
                                };
                                cpu.set(dest, v);
                            } else {
                                match (hw >> 5) & 0b11 {
                                    0b00 => cpu.set(dest, ((a as u32).wrapping_sub(b as u32)) as i32 as u64),
                                    0b01 => cpu.set(dest, ((a as u32).wrapping_add(b as u32)) as i32 as u64),
                                    _ => return Err(bad()),
                                }
                            }
                        }
                    }
                    cpu.pc = next_pc;
                    Ok(false)
                }
                0b101 => {
                    // c.j: CJ-format immediate
                    cpu.pc = pc.wrapping_add(cj_imm(hw) as u64);
                    Ok(false)
                }
                0b110 | 0b111 => {
                    // c.beqz / c.bnez on rs1'
                    let taken = match f3 {
                        0b110 => cpu.get(rs1_c) == 0,
                        _ => cpu.get(rs1_c) != 0,
                    };
                    if taken {
                        cpu.pc = pc.wrapping_add(cb_imm(hw) as u64);
                    } else {
                        cpu.pc = next_pc;
                    }
                    Ok(false)
                }
                _ => {
                    // 0b000: c.addi (rd == 0 → c.nop hint)
                    if rd != 0 {
                        cpu.set(rd, cpu.get(rd).wrapping_add(imm6));
                    }
                    cpu.pc = next_pc;
                    Ok(false)
                }
            }
        }
        _ => {
            // Quadrant 2 (op = 0b10): SP-relative loads/stores and reg-reg ops.
            let rd = ((hw >> 7) & 0x1f) as u32;
            let rs2 = ((hw >> 2) & 0x1f) as u32;
            match f3 {
                0b000 => {
                    // c.slli: 6-bit shamt; rd == 0 → hint
                    let shamt = (((hw >> 12) & 0x1) << 5) | ((hw >> 2) & 0x1f) as u16;
                    if rd != 0 {
                        cpu.set(rd, cpu.get(rd).wrapping_shl(shamt as u32));
                    }
                    cpu.pc = next_pc;
                    Ok(false)
                }
                0b010 => {
                    // c.lwsp: uimm[5|4:2|7:6], rd != 0
                    if rd == 0 {
                        return Err(bad());
                    }
                    let imm = (((hw >> 12) & 0x1) << 5)
                        | (((hw >> 4) & 0x7) << 2)
                        | (((hw >> 2) & 0x3) << 6);
                    let addr = sp.wrapping_add(imm as u64);
                    let v = mem.read(addr, 4).map_err(|e| trap_load(e, addr))?;
                    cpu.set(rd, (v as u32 as i32) as i64 as u64);
                    cpu.pc = next_pc;
                    Ok(false)
                }
                0b011 => {
                    // c.ldsp: uimm[5|4:3|8:6], rd != 0
                    if rd == 0 {
                        return Err(bad());
                    }
                    let imm = (((hw >> 12) & 0x1) << 5)
                        | (((hw >> 5) & 0x3) << 3)
                        | (((hw >> 2) & 0x7) << 6);
                    let addr = sp.wrapping_add(imm as u64);
                    let v = mem.read(addr, 8).map_err(|e| trap_load(e, addr))?;
                    cpu.set(rd, v);
                    cpu.pc = next_pc;
                    Ok(false)
                }
                0b100 => {
                    let bit12 = (hw >> 12) & 0x1;
                    if bit12 == 0 {
                        if rs2 == 0 {
                            // c.jr: rs1 != 0 required
                            if rd == 0 {
                                return Err(bad());
                            }
                            cpu.pc = cpu.get(rd) & !1u64;
                            Ok(false)
                        } else {
                            // c.mv: rd == 0 → hint
                            if rd != 0 {
                                cpu.set(rd, cpu.get(rs2));
                            }
                            cpu.pc = next_pc;
                            Ok(false)
                        }
                    } else if rs2 == 0 {
                        if rd == 0 {
                            // c.ebreak: clean halt
                            Ok(true)
                        } else {
                            // c.jalr: rs1 != 0 required (rs1 = rd field here)
                            if rd == 0 {
                                return Err(bad());
                            }
                            let target = cpu.get(rd) & !1u64;
                            cpu.set(1, next_pc);
                            cpu.pc = target;
                            Ok(false)
                        }
                    } else {
                        // c.add: rd == 0 → hint
                        if rd != 0 {
                            let v = cpu.get(rd).wrapping_add(cpu.get(rs2));
                            cpu.set(rd, v);
                        }
                        cpu.pc = next_pc;
                        Ok(false)
                    }
                }
                0b110 => {
                    // c.swsp: uimm[5:2|7:6], rs2 is a full 5-bit register
                    let imm = (((hw >> 9) & 0xf) << 2) | (((hw >> 7) & 0x3) << 6);
                    let addr = sp.wrapping_add(imm as u64);
                    let b = cpu.get(rs2).to_le_bytes();
                    mem.write(addr, &b[..4]).map_err(|e| trap_store(e, addr))?;
                    cpu.pc = next_pc;
                    Ok(false)
                }
                0b111 => {
                    // c.sdsp: uimm[5:3|8:6]
                    let imm = (((hw >> 10) & 0x7) << 3) | (((hw >> 7) & 0x7) << 6);
                    let addr = sp.wrapping_add(imm as u64);
                    let b = cpu.get(rs2).to_le_bytes();
                    mem.write(addr, &b).map_err(|e| trap_store(e, addr))?;
                    cpu.pc = next_pc;
                    Ok(false)
                }
                _ => Err(bad()), // 0b001/0b101: FP loads/stores, not in the pin
            }
        }
    }
}

/// CJ-format immediate (c.j): scrambled but fully specified.
fn cj_imm(hw: u16) -> i64 {
    let v = ((((hw >> 12) & 0x1) as u64) << 11)
        | ((((hw >> 8) & 0x1) as u64) << 10)
        | ((((hw >> 9) & 0x3) as u64) << 8)
        | ((((hw >> 6) & 0x1) as u64) << 7)
        | ((((hw >> 7) & 0x1) as u64) << 6)
        | ((((hw >> 2) & 0x1) as u64) << 5)
        | ((((hw >> 11) & 0x1) as u64) << 4)
        | ((((hw >> 3) & 0x7) as u64) << 1);
    ((v << 52) as i64) >> 52 // sext 12 bits
}

/// CB-format immediate (c.beqz/c.bnez).
fn cb_imm(hw: u16) -> i64 {
    let v = ((((hw >> 12) & 0x1) as u64) << 8)
        | ((((hw >> 5) & 0x3) as u64) << 6)
        | ((((hw >> 2) & 0x1) as u64) << 5)
        | ((((hw >> 10) & 0x3) as u64) << 3)
        | ((((hw >> 3) & 0x3) as u64) << 1);
    ((v << 55) as i64) >> 55 // sext 9 bits
}

/// QEMU/Linux RISC-V syscall ABI subset: write(64) and exit(93) only.
/// Anything else is a trap. The write log lives in `mem.syscall_log`
/// and is excluded from the state hash by design.
fn do_syscall(cpu: &mut Cpu, mem: &mut Mem) -> Result<bool, Trap> {
    match cpu.get(17) {
        64 => {
            let fd = cpu.get(10);
            let buf = cpu.get(11);
            let len = cpu.get(12);
            if fd != 1 || len > (1 << 20) {
                return Err(Trap::Ecall);
            }
            let bytes = mem.read_region(buf, len as usize).map_err(|_| Trap::Ecall)?;
            mem.syscall_log.extend_from_slice(&bytes);
            cpu.set(10, len); // a0 = bytes written
            cpu.pc += 4; // ecall is a 4-byte instruction: advance past it
            Ok(false)
        }
        93 => Ok(true), // exit(code): clean halt, code remains in a0
        _ => Err(Trap::Ecall),
    }
}

/// One judged chunk: restore an (untrusted) snapshot, execute at most
/// `chunk_size` instructions or until halt/trap, and return the
/// resulting state hash chained onto `prev`. The CALLER must verify the
/// snapshot's hash against the agreed chain prefix before trusting the
/// verdict computed from it.
pub enum ChunkEnd {
    Boundary,
    Halted,
    Trapped(Trap),
}

pub fn execute_chunk_from(
    snapshot: &[u8],
    prev: &Hash,
    chunk_size: u64,
) -> Result<(Hash, ChunkEnd, u64), String> {
    let (mut cpu, mut mem) = crate::snapshot::restore(snapshot)?;
    let mut n: u64 = 0;
    let mut in_chunk: u64 = 0;
    loop {
        match step(&mut cpu, &mut mem) {
            Ok(true) => {
                n += 1;
                let h = state_hash(prev, &cpu, &mem);
                return Ok((h, ChunkEnd::Halted, n));
            }
            Ok(false) => {
                n += 1;
                in_chunk += 1;
                if in_chunk == chunk_size {
                    let h = state_hash(prev, &cpu, &mem);
                    return Ok((h, ChunkEnd::Boundary, n));
                }
            }
            Err(t) => {
                let h = state_hash(prev, &cpu, &mem);
                return Ok((h, ChunkEnd::Trapped(t), n));
            }
        }
    }
}

fn trap_load(e: crate::mem::MemError, addr: u64) -> Trap {
    match e {
        crate::mem::MemError::Misaligned => Trap::MisalignedLoad { addr },
        crate::mem::MemError::OutOfRange => Trap::LoadOutOfRange { addr },
    }
}

fn trap_store(e: crate::mem::MemError, addr: u64) -> Trap {
    match e {
        crate::mem::MemError::Misaligned => Trap::MisalignedStore { addr },
        crate::mem::MemError::OutOfRange => Trap::StoreOutOfRange { addr },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Halted,
    InstructionLimit,
    Trapped(Trap),
}

#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub status: ExitStatus,
    /// Chunk hash chain. A hash is emitted after every `chunk_size`
    /// instructions AND at the moment of exit (halt or trap), so the
    /// chain always covers the full execution.
    pub chunk_hashes: Vec<Hash>,
    pub instructions: u64,
    pub output: Option<Vec<u8>>,
    /// Bytes written via the write syscall in syscall mode. Empty
    /// unless syscalls are enabled; excluded from the state hash.
    pub syscall_log: Vec<u8>,
}

fn write_snapshot(cfg: &Config, index: usize, snap: &Option<Vec<u8>>) {
    if let (Some(dir), Some(bytes)) = (&cfg.snapshot_dir, snap) {
        std::fs::create_dir_all(dir).ok();
        std::fs::write(dir.join(format!("snap-{index}.bin")), bytes).ok();
    }
}

pub struct Config {
    pub chunk_size: u64,
    pub max_instructions: u64,
    /// QEMU-compatible syscall environment (write/exit) instead of
    /// trapping on ecall. Used by the conformance differential.
    pub syscalls: bool,
    /// When set, serialize the full machine state to
    /// `<dir>/snap-<chain index>.bin` at every chunk boundary and at
    /// exit. Snapshots power the dispute fast path.
    pub snapshot_dir: Option<std::path::PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            chunk_size: 1 << 20,
            max_instructions: 4_000_000_000,
            syscalls: false,
            snapshot_dir: None,
        }
    }
}

/// Set up memory for a job image and run to completion.
pub fn run(mem: &mut Mem, entry: u64, input: &[u8], cfg: &Config) -> RunOutcome {
    let mut cpu = Cpu::new(entry, STACK_TOP);
    let mut prev = GENESIS;
    let mut chain: Vec<Hash> = Vec::new();
    let push_hash = |prev: &mut Hash, cpu: &Cpu, mem: &Mem, chain: &mut Vec<Hash>| {
        *prev = state_hash(prev, cpu, mem);
        chain.push(*prev);
    };

    // Install input. A failed install here is a programming error in
    // the host, not a job behavior — panic is fine and deterministic.
    mem.write(INPUT_LEN_ADDR, &(input.len() as u64).to_le_bytes()).unwrap();
    mem.write(INPUT_DATA_ADDR, input).unwrap();

    let mut n: u64 = 0;
    let mut in_chunk: u64 = 0;
    let mut status = ExitStatus::InstructionLimit;
    // Progress telemetry for hung-run diagnosis (off unless requested).
    let progress_every: u64 = std::env::var("RVCORE_PROGRESS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    loop {
        if progress_every > 0 && n % progress_every == 0 && n > 0 {
            eprintln!("[rvcore] pc {:#x} inst {}", cpu.pc, n);
        }
        if n >= cfg.max_instructions {
            push_hash(&mut prev, &cpu, mem, &mut chain);
            break;
        }
        let step_res = step_mode(&mut cpu, mem, cfg.syscalls);
        // Snapshot before the hash is pushed: the snapshot's chain
        // index is chain.len() (the index it is about to get).
        let mut snap = None;
        if cfg.snapshot_dir.is_some() {
            let at_boundary = match step_res {
                Ok(false) => in_chunk + 1 == cfg.chunk_size,
                _ => true,
            };
            if at_boundary {
                snap = Some(crate::snapshot::capture(&cpu, mem));
            }
        }
        match step_res {
            Ok(true) => {
                n += 1;
                write_snapshot(cfg, chain.len(), &snap);
                push_hash(&mut prev, &cpu, mem, &mut chain);
                status = ExitStatus::Halted;
                break;
            }
            Ok(false) => {
                n += 1;
                in_chunk += 1;
                if in_chunk == cfg.chunk_size {
                    write_snapshot(cfg, chain.len(), &snap);
                    push_hash(&mut prev, &cpu, mem, &mut chain);
                    in_chunk = 0;
                }
            }
            Err(t) => {
                write_snapshot(cfg, chain.len(), &snap);
                push_hash(&mut prev, &cpu, mem, &mut chain);
                status = ExitStatus::Trapped(t);
                break;
            }
        }
    }

    let output = if status == ExitStatus::Halted {
        let len = mem.read(OUTPUT_LEN_ADDR, 8).unwrap_or(0);
        if len > OUTPUT_MAX {
            // Rewrite status as a trap: an out-of-contract output
            // length is job misbehavior.
            chain.pop();
            status = ExitStatus::Trapped(Trap::OutputTooLarge);
            None
        } else {
            mem.read_region(OUTPUT_DATA_ADDR, len as usize).ok()
        }
    } else {
        None
    };

    let syscall_log = std::mem::take(&mut mem.syscall_log);
    RunOutcome { status, chunk_hashes: chain, instructions: n, output, syscall_log }
}
