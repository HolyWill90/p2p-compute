#!/usr/bin/env bash
# Conformance differential: the same static RISC-V ELF executed by our
# emulator and by qemu-riscv64 must produce byte-identical output.
set -e
cd "$(dirname "$0")/.."

# 1. Build the conformance job ELF.
(cd jobs/conformance/job && cargo build --release)
cp jobs/conformance/job/target/riscv64imac-unknown-none-elf/release/conformance-isa \
   jobs/conformance/program.elf

# 2. Execute under our emulator (syscall mode).
cargo run --release -p conformance -- emu \
    --elf jobs/conformance/program.elf --out target/conformance-emu.out

# 3. Execute under QEMU (independent implementation) in Linux.
# Git Bash on Windows mangles /ws unless path conversion is disabled.
MSYS_NO_PATHCONV=1 docker run --rm \
    -v "$(pwd -W 2>/dev/null || pwd):/ws" -w /ws ubuntu:24.04 \
    bash -c "apt-get update -qq && apt-get install -y -qq qemu-user && qemu-riscv64 /ws/jobs/conformance/program.elf > /ws/target/conformance-qemu.out"

# 4. Compare.
cargo run --release -p conformance -- compare \
    target/conformance-emu.out target/conformance-qemu.out
