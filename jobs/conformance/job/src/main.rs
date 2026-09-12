#![no_std]
#![no_main]

//! ISA conformance program. Every case is an explicit inline-asm
//! instruction (or compressed pair) with fixed inputs, so the result
//! depends only on the ISA semantics — not on what the compiler chose
//! to emit. The (case-id, value) pairs are written with the Linux
//! write syscall and the program exits with the exit syscall, so the
//! SAME ELF runs under this project's emulator (syscall mode) and
//! under `qemu-riscv64`; byte-equal outputs prove the two independent
//! implementations agree on the pinned ISA.

use core::arch::asm;
use core::ptr;

static mut OUT_BUF: [u64; 512] = [0; 512];
static mut OUT_N: usize = 0;
static mut SCRATCH: [u64; 8] = [0; 8];

unsafe fn push(id: u64, v: u64) {
    let n = ptr::addr_of_mut!(OUT_N);
    let i = n.read();
    let buf = ptr::addr_of_mut!(OUT_BUF);
    (*buf)[i] = id;
    (*buf)[i + 1] = v;
    n.write(i + 2);
}

unsafe fn sys_write(buf: *const u8, len: usize) {
    let code: i64;
    asm!(
        "ecall",
        in("a7") 64usize,
        in("a0") 1usize,
        inlateout("a1") buf as usize => code,
        in("a2") len,
        lateout("a0") _,
    );
    let _ = code;
}

unsafe fn sys_exit(code: usize) -> ! {
    asm!("ecall", in("a7") 93usize, in("a0") code, options(noreturn))
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { sys_exit(2) }
}

macro_rules! pair {
    ($a:expr, $b:expr) => {{
        let lo: u64;
        let hi: u64;
        asm!(
            concat!($a, " {lo}, {x}, {y}"),
            concat!($b, " {hi}, {x}, {y}"),
            x = in(reg) 0x8000_0000_0000_0000u64,
            y = in(reg) 2u64,
            lo = out(reg) lo,
            hi = out(reg) hi,
        );
        (lo, hi)
    }};
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        let mut v;
        let mut r;
        let mut link;
        // ---- integer ALU, 64-bit ----
        asm!("add {v}, t0, t1", v = out(reg) v, in("t0") 0x7fff_ffff_ffff_ffffu64, in("t1") 1u64);
        push(1, v); // signed overflow wraps: 0x8000..0
        asm!("sub {v}, zero, t0", v = out(reg) v, in("t0") 1u64);
        push(2, v); // -1
        asm!("xor {v}, t0, t1", v = out(reg) v, in("t0") 0x0f0fu64, in("t1") 0x00ffu64);
        push(3, v);
        asm!("or {v}, t0, t1", v = out(reg) v, in("t0") 0x0f0fu64, in("t1") 0x00ffu64);
        push(4, v);
        asm!("and {v}, t0, t1", v = out(reg) v, in("t0") 0x0f0fu64, in("t1") 0x00ffu64);
        push(5, v);

        // ---- shifts across the 6-bit shamt boundary ----
        let (lo, hi) = pair!("sll", "srl"); // 0x8000..0 << 2 and >> 2
        push(6, lo);
        push(7, hi);
        asm!("sll {v}, t0, t1", v = out(reg) v, in("t0") 1u64, in("t1") 63u64);
        push(8, v); // 1 << 63
        asm!("sll {v}, t0, t1", v = out(reg) v, in("t0") 1u64, in("t1") 32u64);
        push(9, v); // 1 << 32 (RV64 shamt 6 bits)
        asm!("sra {v}, t0, t1", v = out(reg) v, in("t0") 0x8000_0000_0000_0000u64 as i64 as u64, in("t1") 63u64);
        push(10, v); // arithmetic: -1
        asm!("srl {v}, t0, t1", v = out(reg) v, in("t0") 0x8000_0000_0000_0000u64, in("t1") 63u64);
        push(11, v); // logical: 1

        // ---- comparisons ----
        asm!("slt {v}, t0, t1", v = out(reg) v, in("t0") (-1i64) as u64, in("t1") 1u64);
        push(12, v); // signed: 1
        asm!("sltu {v}, t0, t1", v = out(reg) v, in("t0") (-1i64) as u64, in("t1") 1u64);
        push(13, v); // unsigned: 0
        asm!("sltiu {v}, t0, -1", v = out(reg) v, in("t0") 0u64);
        push(14, v); // imm sign-extends then unsigned: 0 < 2^64-1 → 1

        // ---- W-form immediates: sign extension of 32-bit results ----
        asm!("addiw {v}, t0, 1", v = out(reg) v, in("t0") 0x7fff_ffffu64);
        push(15, v); // sext32(0x80000000)
        asm!("slliw {v}, t0, 1", v = out(reg) v, in("t0") 0x8000_0000u64);
        push(16, v); // sext32(0x1_00000000 low 32 = 0)
        asm!("sraiw {v}, t0, 1", v = out(reg) v, in("t0") 0x8000_0000u64 as i32 as u64);
        push(17, v); // sext32(0xC0000000)
        asm!("srliw {v}, t0, 1", v = out(reg) v, in("t0") 0x8000_0000u64);
        push(18, v); // sext32(0x40000000)

        // ---- M extension edges ----
        asm!("mul {v}, t0, t1", v = out(reg) v, in("t0") 0x1234_5678_9au64, in("t1") 0x9abc_def0_1u64);
        push(20, v);
        asm!("mulh {v}, t0, t1", v = out(reg) v, in("t0") (-1i64) as u64, in("t1") (-1i64) as u64);
        push(21, v); // high((-1)*(-1)) = 0
        asm!("mulhsu {v}, t0, t1", v = out(reg) v, in("t0") (-1i64) as u64, in("t1") (-1i64) as u64);
        push(22, v); // signed x unsigned: high(-1 * (2^64-1)) = all ones
        asm!("mulhu {v}, t0, t1", v = out(reg) v, in("t0") (-1i64) as u64, in("t1") (-1i64) as u64);
        push(23, v); // high((2^64-1)^2) = 2^64-2
        asm!("div {v}, t0, t1", v = out(reg) v, in("t0") i64::MIN as u64, in("t1") (-1i64) as u64);
        push(24, v); // overflow → i64::MIN
        asm!("div {v}, t0, t1", v = out(reg) v, in("t0") 5u64, in("t1") 0u64);
        push(25, v); // ÷0 → -1
        asm!("rem {v}, t0, t1", v = out(reg) v, in("t0") 5u64, in("t1") 0u64);
        push(26, v); // %0 → dividend
        asm!("divu {v}, t0, t1", v = out(reg) v, in("t0") (-1i64) as u64, in("t1") 2u64);
        push(27, v);
        asm!("divw {v}, t0, t1", v = out(reg) v, in("t0") i32::MIN as u32 as u64, in("t1") (-1i64) as u64);
        push(28, v); // 32-bit overflow → sext32(i32::MIN)
        asm!("remw {v}, t0, t1", v = out(reg) v, in("t0") i32::MIN as u32 as u64, in("t1") (-1i64) as u64);
        push(29, v); // → 0
        asm!("divuw {v}, t0, t1", v = out(reg) v, in("t0") (-1i64) as u64, in("t1") 2u64);
        push(30, v); // unsigned 32-bit: 0xFFFFFFFF/2 = 0x7FFFFFFF, sext positive
        asm!("remw {v}, t0, t1", v = out(reg) v, in("t0") (-5i64) as u64, in("t1") 0u64);
        push(31, v); // 32-bit %0 → dividend sext

        // ---- upper immediates ----
        asm!("lui {v}, 0xDEADB", v = out(reg) v);
        push(32, v); // RV64 lui sign-extends: 0xFFFFFFFFDEADB000
        asm!("auipc {v}, 0", v = out(reg) v);
        push(33, v); // pc of this instruction — fixed by the ELF layout

        // ---- loads/stores of every width over a known pattern ----
        let scratch = ptr::addr_of_mut!(SCRATCH);
        asm!("sd t0, 0({s})", s = in(reg) scratch, in("t0") (-1i64) as u64);
        asm!("ld {v}, 0({s})", v = out(reg) v, s = in(reg) scratch);
        push(40, v);
        asm!("sb t0, 9({s})", s = in(reg) scratch, in("t0") 0x80u64);
        asm!("lb {v}, 9({s})", v = out(reg) v, s = in(reg) scratch);
        push(41, v); // sign-extended 0x80
        asm!("lbu {v}, 9({s})", v = out(reg) v, s = in(reg) scratch);
        push(42, v);
        asm!("sh t0, 16({s})", s = in(reg) scratch, in("t0") 0x8000u64);
        asm!("lh {v}, 16({s})", v = out(reg) v, s = in(reg) scratch);
        push(43, v); // sext 0x8000
        asm!("lhu {v}, 16({s})", v = out(reg) v, s = in(reg) scratch);
        push(44, v);
        asm!("sw t0, 24({s})", s = in(reg) scratch, in("t0") 0x8000_0000u64);
        asm!("lw {v}, 24({s})", v = out(reg) v, s = in(reg) scratch);
        push(45, v); // sext 0x80000000
        asm!("lwu {v}, 24({s})", v = out(reg) v, s = in(reg) scratch);
        push(46, v); // zero-extended

        // ---- branches and jumps ----
        asm!(
            "li {r}, 0",
            "beq t0, t1, 1f",
            "addi {r}, {r}, 1",
            "1:",
            r = out(reg) r,
            in("t0") 5u64,
            in("t1") 5u64,
        );
        push(48, r); // taken → 0
        asm!(
            "li {r}, 0",
            "bltu t0, t1, 1f",
            "addi {r}, {r}, 1",
            "1:",
            r = out(reg) r,
            in("t0") (-1i64) as u64,
            in("t1") 1u64,
        );
        push(49, r); // unsigned 2^64-1 < 1 → not taken → 1
        asm!(
            "jal {link}, 2f",
            "nop",
            "2:",
            link = out(reg) link,
        );
        push(50, link); // link = pc of the nop — fixed by the ELF
        asm!(
            "la t0, 3f",
            "ori t0, t0, 1",
            "jalr {link}, 0(t0)",
            "nop",
            "3:",
            lateout("t0") _,
            link = out(reg) link,
        );
        push(51, link); // jalr clears bit 0 of the target, link = pc+4

        // ---- compressed instructions ----
        asm!("c.li {v}, -1", v = out(reg) v);
        push(60, v); // sext 6-bit immediate
        asm!("c.addi {v}, 31", v = inlateout(reg) 0x7fff_ffff_ffff_ffe2u64 => v);
        push(61, v); // wraps past 2^63 boundary
        asm!("c.lui {v}, 0xfffff", v = out(reg) v);
        push(62, v); // sext(0b111111)<<12

        // SP-relative compressed instructions. sp is referenced but
        // never left modified: the addi16sp deltas round-trip to zero,
        // and the swsp/ldsp roundtrips land ABOVE the current frame
        // (sp+252 / sp+480), where both implementations have mapped,
        // unused stack.
        let (rel4, rel16up, rel16back): (u64, u64, u64);
        let mut sp0: u64 = 0;
        asm!(
            "mv {sp0}, sp",
            "c.addi4spn a0, sp, 16",
            "sub {rel4}, a0, {sp0}",
            "c.addi16sp sp, 496",
            "sub {rel16up}, sp, {sp0}",
            "c.addi16sp sp, -496",
            "sub {rel16back}, sp, {sp0}",
            sp0 = inout(reg) sp0,
            rel4 = out(reg) rel4,
            rel16up = out(reg) rel16up,
            rel16back = out(reg) rel16back,
            lateout("a0") _,
        );
        push(63, rel4);      // 16
        push(64, rel16up);   // 496
        push(65, rel16back); // 0
        let (lw, ld): (u64, u64);
        asm!(
            "li t2, 0x123456789abcdef0",
            "c.swsp t2, 252(sp)",
            "c.lwsp t0, 252(sp)",
            "li a7, 0x0badc0dedeadf00d",
            "c.sdsp a7, 480(sp)",
            "c.ldsp t1, 480(sp)",
            lateout("t0") lw,
            lateout("t1") ld,
            lateout("t2") _,
            lateout("a7") _,
        );
        push(66, lw); // c.swsp/c.lwsp roundtrip
        push(67, ld); // c.sdsp/c.ldsp roundtrip
        let (mut lo, mut hi);
        asm!(
            "c.li a2, 16",
            "c.li a3, 15",
            "c.sub a2, a3",
            "mv {lo}, a2",
            "c.li a2, 16",
            "c.xor a2, a3",
            "mv {hi}, a2",
            lo = out(reg) lo,
            hi = out(reg) hi,
        );
        push(67, lo); // 1
        push(68, hi); // 31
        let (mut lo2, mut hi2);
        asm!(
            "c.li a2, -16",
            "c.li a3, 3",
            "c.or a2, a3",
            "mv {lo2}, a2",
            "c.li a2, -16",
            "c.and a2, a3",
            "mv {hi2}, a2",
            lo2 = out(reg) lo2,
            hi2 = out(reg) hi2,
        );
        push(69, lo2); // -13
        push(70, hi2); // -16
        asm!(
            "c.li a2, 16",
            "c.srli a2, 4",
            "mv {v}, a2",
            v = out(reg) v,
        );
        push(71, v); // 1
        asm!(
            "c.li a2, -16",
            "c.srai a2, 2",
            "mv {v}, a2",
            v = out(reg) v,
        );
        push(72, v); // -4
        asm!(
            "c.li a2, 1",
            "c.slli a2, 33",
            "mv {v}, a2",
            v = out(reg) v,
        );
        push(73, v); // 1 << 33 — RV64 6-bit compressed shamt
        asm!(
            "c.li a2, 31",
            "c.andi a2, -16",
            "mv {v}, a2",
            v = out(reg) v,
        );
        push(74, v); // 16
        asm!(
            "c.li a4, 31",
            "c.mv {v}, a4",
            lateout("a4") _,
            v = out(reg) v,
        );
        push(75, v);
        asm!(
            "c.li a4, 31",
            "c.add {v}, a4",
            lateout("a4") _,
            v = out(reg) v,
        );
        push(76, v); // 0x66
        asm!(
            "li a4, 32767",
            "c.addiw a4, 1",
            "mv {v}, a4",
            lateout("a4") _,
            v = out(reg) v,
        );
        push(77, v); // sext32(0x8000)
        asm!(
            "c.li {r}, 0",
            "c.li s1, 0",
            "c.beqz s1, 4f",
            "addi {r}, {r}, 1",
            "4:",
            r = out(reg) r,
            in("t0") 0u64,
        );
        push(78, r); // taken → 0
        asm!(
            "c.li {r}, 0",
            "c.li s1, 1",
            "c.bnez s1, 5f",
            "addi {r}, {r}, 1",
            "5:",
            r = out(reg) r,
            in("t0") 1u64,
        );
        push(79, r); // taken → 0
        asm!(
            "la t0, 6f",
            "ori t0, t0, 1",
            "c.jalr t0",
            "nop",
            "6:",
            lateout("t0") _,
            out("ra") link,
        );
        push(80, link); // c.jalr: ra = pc+2, target bit 0 cleared

        // Emit the results and exit through the syscall ABI.
        let n = ptr::addr_of_mut!(OUT_N).read();
        let buf = ptr::addr_of_mut!(OUT_BUF) as *const u8;
        sys_write(buf, n * 8);
        sys_exit(0);
    }
}
