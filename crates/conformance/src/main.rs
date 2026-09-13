use clap::Parser;
use std::path::{Path, PathBuf};

/// Conformance differential driver: run the conformance ISA program
/// under this project's emulator, run the SAME static ELF under
/// `qemu-riscv64` (an independent implementation), and require
/// byte-identical syscall output. Also tallies the official
/// riscv-tests suite via the tohost convention.
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
    /// Tally official riscv-tests ELFs via the tohost convention
    /// (1 = pass). Reports the pass rate and lists failures.
    Arch { dir: PathBuf },
}

/// `mode`: Emu runs the QEMU-compatible syscall environment (conformance
/// differential); Arch runs bare-metal — ecall traps into the test's own
/// mtvec handler, and the exit is the tohost device store.
fn run_elf(elf: &Path, syscalls: bool) -> Result<rvcore::RunOutcome, String> {
    let bytes = std::fs::read(elf).map_err(|e| format!("read: {e}"))?;
    let image = rvcore::elf::parse(&bytes).map_err(|e| format!("elf: {e}"))?;
    let mut mem = rvcore::Mem::new();
    rvcore::elf::load(&mut mem, &image).map_err(|e| format!("load: {e}"))?;
    let cfg = rvcore::Config {
        syscalls,
        // The riscv-tests exit by storing to the tohost device word and
        // then self-looping (the host is expected to poll the device);
        // without the address the loop never ends.
        tohost_addr: image.tohost_addr,
        max_instructions: 10_000_000,
        ..Default::default()
    };
    Ok(rvcore::interp::run(&mut mem, image.entry, b"", &cfg))
}

fn main() {
    match Cmd::parse() {
        Cmd::Emu { elf, out } => {
            let outcome = run_elf(&elf, true).unwrap_or_else(|e| {
                eprintln!("error: {e}");
                std::process::exit(2);
            });
            let status_str = match &outcome.status {
                rvcore::ExitStatus::Halted | rvcore::ExitStatus::Tohost(_) => "halted",
                rvcore::ExitStatus::InstructionLimit => "instruction limit",
                rvcore::ExitStatus::Trapped(t) => {
                    eprintln!("trap: {t:?}");
                    std::process::exit(3);
                }
            };
            println!(
                "emulator: {status_str} after {} instructions, {} output bytes",
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
                eprintln!(
                    "CONFORMANCE FAIL: outputs differ ({} vs {} bytes)",
                    a.len(),
                    b.len()
                );
                for (i, (x, y)) in a.iter().zip(&b).enumerate() {
                    if x != y {
                        eprintln!("  first difference at byte {i}: {x:#x} vs {y:#x}");
                        break;
                    }
                }
                std::process::exit(1);
            }
        }
        Cmd::Arch { dir } => {
            let mut elfs: Vec<PathBuf> = std::fs::read_dir(&dir)
                .expect("read dir")
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension().map(|e| e == "elf").unwrap_or(false)
                })
                .collect();
            elfs.sort();
            let mut pass = 0usize;
            let mut fails: Vec<String> = Vec::new();
            for elf in &elfs {
                let name = elf
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                match run_elf(elf, false) {
                    Ok(outcome) => match outcome.status {
                        rvcore::ExitStatus::Tohost(1) => pass += 1,
                        rvcore::ExitStatus::Tohost(v) => {
                            fails.push(format!("{name}: tohost {v:#x} (fail code)"));
                        }
                        other => fails.push(format!("{name}: {other:?}")),
                    },
                    Err(e) => fails.push(format!("{name}: {e}")),
                }
            }
            println!(
                "riscv-tests: {} / {} passed ({:.0}%)",
                pass,
                elfs.len(),
                100.0 * pass as f64 / elfs.len().max(1) as f64
            );
            for f in &fails {
                println!("  FAIL: {f}");
            }
            if pass != elfs.len() {
                std::process::exit(1);
            }
        }
    }
}
