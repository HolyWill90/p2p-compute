#![no_std]

//! The job ABI: the single contract between the deterministic emulator,
//! the coordinator, and the programs that run inside jobs.
//!
//! Memory map of a job (flat 4 GiB address space):
//!
//! ```text
//! 0x1000_0000  u64  input length in bytes
//! 0x1000_0008  ...  input bytes
//! 0x2000_0000  u64  output length (written by the program)
//! 0x2000_0008  ...  output bytes
//! 0x8000_0000  ...  ELF image (text/data/bss, linked here by the job linker script)
//! 0x83F0_0000       initial stack pointer, grows down
//! ```
//!
//! A job halts cleanly by executing `ebreak`. `ecall` is a trap.

pub const INPUT_LEN_ADDR: u64 = 0x1000_0000;
pub const INPUT_DATA_ADDR: u64 = 0x1000_0008;
pub const INPUT_MAX: u64 = 64 << 20;

pub const OUTPUT_LEN_ADDR: u64 = 0x2000_0000;
pub const OUTPUT_DATA_ADDR: u64 = 0x2000_0008;
pub const OUTPUT_MAX: u64 = 1 << 20;

pub const ELF_BASE: u64 = 0x8000_0000;
pub const STACK_TOP: u64 = 0x83F0_0000;

/// The pinned instruction set: RV64IMC (integer + multiply/divide +
/// compressed, no atomics, no FP). Jobs are compiled for the
/// `riscv64imac-unknown-none-elf` target with `-a` so no lr/sc is
/// emitted; compressed instructions are fine.
pub const ISA: &str = "rv64imc";

/// Pinned address of the `tohost` symbol for the classic riscv-tests
/// suite: a test writes (payload << 1) | 1 here to exit; payload 1 =
/// pass, anything else = fail. The test link script pins the .tohost
/// section at this address.
pub const TOHOST_ADDR: u64 = 0x8001_0000;
