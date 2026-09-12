use clap::Parser;
use std::path::PathBuf;

/// Conformance differential driver: run the conformance ISA program
/// under this project's emulator, run the SAME static ELF under
/// `qemu-riscv64` (an independent implementation), and require
/// byte-identical syscall output.
#[derive(Parser)]
enum Cmd {
    /// Execute under our emulator (QEMU-compatible syscall mode) and
    /// write the syscall output bytes.
    Emu {
        #[arg(long)]
        elf: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Compare two conformance outputs byte for byte.
    Compare { a: PathBuf, b: PathBuf },
}

fn main() {
    match Cmd::parse() {
        Cmd::Emu { elf, out } => {
            let bytes = std::fs::read(&elf).expect("read elf");
            let image = rvcore::elf::parse(&bytes).expect("parse elf");
            let mut mem = rvcore::Mem::new();
            rvcore::elf::load(&mut mem, &image).expect("load elf");
            let cfg = rvcore::Config { syscalls: true, ..Default::default() };
            let outcome = rvcore::interp::run(&mut mem, image.entry, b"", &cfg);
            println!(
                "emulator: {} after {} instructions, {} output bytes",
                match outcome.status {
                    rvcore::ExitStatus::Halted => "halted",
                    rvcore::ExitStatus::InstructionLimit => "instruction limit",
                    rvcore::ExitStatus::Trapped(t) => {
                        eprintln!("trap: {t:?}");
                        std::process::exit(3);
                    }
                },
                outcome.instructions,
                outcome.syscall_log.len()
            );
            std::fs::write(&out, &outcome.syscall_log).expect("write output");
        }
        Cmd::Compare { a, b } => {
            let a = std::fs::read(&a).expect("read a");
            let b = std::fs::read(&b).expect("read b");
            if a == b {
                println!(
                    "CONFORMANCE PASS: {} bytes identical across independent implementations",
                    a.len()
                );
            } else {
                eprintln!("CONFORMANCE FAIL: outputs differ ({} vs {} bytes)", a.len(), b.len());
                for (i, (x, y)) in a.iter().zip(&b).enumerate() {
                    if x != y {
                        eprintln!("  first difference at byte {i}: {x:#x} vs {y:#x}");
                        break;
                    }
                }
                std::process::exit(1);
            }
        }
    }
}
