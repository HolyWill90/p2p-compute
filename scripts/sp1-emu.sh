#!/usr/bin/env bash
# Same-ELF zk tier validation: the pinned emulator (rvcore) compiled
# into the SP1 zkVM, executing the actual demo-hash-nano job ELF, with
# byte-identical results required against the local rvcore run. See
# scripts/sp1-emu-inner.sh for the envelope and the receipt caveat.
set -e
cd "$(dirname "$0")/.."

MSYS_NO_PATHCONV=1 docker start sp1v 2>/dev/null || \
MSYS_NO_PATHCONV=1 docker run -d --name sp1v -v "$(pwd -W 2>/dev/null || pwd):/ws" -w /ws rust:1 sleep infinity
MSYS_NO_PATHCONV=1 docker exec sp1v bash -c "bash /ws/scripts/sp1-emu-inner.sh > /ws/sp1-emu.log 2>&1"
tail -20 sp1-emu.log
grep -q "SP1 EMU EXECUTE PASS" sp1-emu.log && echo "zk tier (same-ELF): VERIFIED"
