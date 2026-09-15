#!/usr/bin/env bash
# Regenerates the committed same-ELF nano receipt (sp1-artifacts/):
# rebuilds the emulator guest, proves the nano job, saves the receipt
# + guest ELF. ~20 minutes of CPU proving at ~24GB.
set -e
export PATH="/usr/local/cargo/bin:$PATH"
cd /ws/sp1-guest
$HOME/.sp1/bin/cargo-prove prove build
EMU_ELF="$(find target -name 'sp1-guest-emu' -type f | head -1)"
cp "$EMU_ELF" /ws/elf/sp1-guest-emu
cd /ws/sp1-host
cargo run --release --bin emu -- prove ../jobs/demo-hash-nano
echo RECEIPT-REGEN-COMPLETE
