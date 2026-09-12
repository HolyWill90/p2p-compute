#!/usr/bin/env bash
# SP1 cross-validation — THE zk tier proof: the same FNV-stream
# algorithm as jobs/demo-hash runs inside the SP1 RISC-V zkVM, and the
# receipt is cryptographically verified. Expected result: the zkVM
# digest equals our emulator's digest for the same input (three-way
# match: emulator == zkVM == host reference).
#
# Runs the whole pipeline in a container (toolchain install ~2 GB on
# first run, then cached in the `sp1v` container):
#   [0] protoc install   [1] sp1up   [2] SP1 toolchain
#   [3] align crate versions with the installed toolchain
#   [4] build the guest ELF   [5] prove + verify via the host
set -e
cd "$(dirname "$0")/.."

MSYS_NO_PATHCONV=1 docker run -d --name sp1v     -v "$(pwd -W 2>/dev/null || pwd):/ws" -w /ws rust:1 sleep infinity
MSYS_NO_PATHCONV=1 docker exec sp1v bash -c     "bash /ws/scripts/sp1-docker-inner.sh > /ws/sp1-run.log 2>&1"
tail -20 sp1-run.log
grep -q "SP1 VALIDATION PASS" sp1-run.log && echo "zk tier: VERIFIED"
