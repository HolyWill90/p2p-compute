#!/usr/bin/env bash
# Runs INSIDE the sp1v container: builds the emulator guest (rvcore as
# the zkVM program), then executes + proves it on the actual smoke-job
# bytes and verifies the receipt against the local rvcore run.
set -e
export PATH="$HOME/.sp1/bin:$PATH"

echo "== building emu guest (rvcore inside the zkVM) =="
cd /ws/sp1-guest
$HOME/.sp1/bin/cargo-prove prove build
EMU_ELF="$(find target -name 'sp1-guest-emu' -type f | head -1)"
echo "guest ELF: $EMU_ELF"
cp "$EMU_ELF" /ws/elf/sp1-guest-emu

echo "== same-ELF prove + verify (receipt) =="
cd /ws/sp1-host
cargo run --release --bin emu -- prove

echo "SP1-EMU-COMPLETE"
