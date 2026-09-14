# Security policy

This project's core claim is deterministic, verifiable execution. If
you find a way to break that — a result that does not correspond to a
real execution, a quorum/dispute bypass, a panic reachable by an
unauthenticated peer, or an emulator correctness bug (any deviation
from RV64IMC semantics as validated by the QEMU differential and the
official riscv-tests suite) — that is a security issue.

## Reporting

Use GitHub's private vulnerability reporting for this repository
(Security → Report a vulnerability). Please do not open a public issue
for anything matching the above.

## Scope

- `crates/rvcore` — the emulator: determinism contract, ISA semantics,
  ELF loading, tohost/syscall devices.
- `crates/coordinator` — quorum counting, signature verification,
  admission proof-of-work, dispute/ledger logic, network handling.
- `crates/wire` — framing, TLS handling, peer protocol.
- `crates/worker`, `crates/contentstore` — blob verification and
  materialization (path confinement, hash checks).

## What is already documented as out of scope

See docs/DESIGN.md ("Known gaps" and the honest-scope notes): bonds
are ledger bookkeeping rather than escrowed stake, the coordinator is
trusted for worker selection, and the zk tier's verified receipt is
demonstrated at the nano-job envelope. Reports within those documented
limits are welcome but the limitation itself is known.

## Supported versions

Only `main` at the latest green CI run is supported.
