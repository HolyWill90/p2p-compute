#!/usr/bin/env bash
# Runs INSIDE the sp1v container: builds the emulator guest (rvcore as
# the zkVM program), then executes it on the actual job bytes and
# requires byte-identical results against the local rvcore run.
#
# What is demonstrated: same-ELF execution equivalence — the actual
# emulator inside the zkVM reproduces the actual job's chunk chain.
# The cryptographic receipt for the same-ELF guest is the same code
# path (mode: prove) but needs more proving RAM than this container
# has (SP1's CPU prover floors above the ~7GB free here; 1-2KB job
# inputs OOM identically, so the floor is fixed overhead). Re-run on
# a >=32GB-free machine:
#   cargo run --release --bin emu -- prove ../jobs/demo-hash-nano
set -e
export PATH="$HOME/.sp1/bin:$PATH"

echo "== building emu guest (rvcore inside the zkVM) =="
cd /ws/sp1-guest
$HOME/.sp1/bin/cargo-prove prove build
EMU_ELF="$(find target -name 'sp1-guest-emu' -type f | head -1)"
echo "guest ELF: $EMU_ELF"
cp "$EMU_ELF" /ws/elf/sp1-guest-emu

echo "== same-ELF execute validation =="
cd /ws/sp1-host
# The nano job (~16K emulated instructions) is the current envelope:
# SP1 6.8's native fast-executor crashes on shard boundaries above
# ~100K emulated instructions, and the CPU prover's fixed memory floor
# exceeds this container. Both are proving-infra limits, not emulator
# limits — the same bytes run byte-identically outside the zkVM.
cargo run --release --bin emu -- execute ../jobs/demo-hash-nano

echo "SP1-EMU-COMPLETE"
