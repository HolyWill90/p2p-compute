# p2p-compute

[![CI](https://github.com/HolyWill90/p2p-compute/actions/workflows/ci.yml/badge.svg)](https://github.com/HolyWill90/p2p-compute/actions/workflows/ci.yml)

Deterministic verification substrate for peer-to-peer compute — the
"BitTorrent of processing" foundation: jobs run on untrusted machines, and
the results are verifiable.

The core artifact is a **pinned deterministic RISC-V (RV64IMC) emulator** that
emits a hash of the machine state after every fixed chunk of instructions.
Every verification mechanism consumes that chunk-hash chain:

| Tier | Mechanism | Overhead | Status |
|---|---|---|---|
| Budget | Quorum N=3 → 5, bond slashing | ~3× | implemented |
| Standard | Optimistic acceptance + dispute game (one-chunk judge) | ~1× | implemented |
| Strong | SP1 zkVM proof **of the emulator itself executing the actual job ELF** | 1× + prover tax | **receipt verified** (nano envelope, ~16K instructions; multi-shard proving is an open infra gap) |

See `docs/DESIGN.md` for the decision log and `docs/PILOT.md` for the
product direction.

## Layout

```
crates/abi           job ABI: memory map, halt convention, pinned ISA string
crates/rvcore        the emulator: RV64IMC interpreter + chunk-hash chain (BLAKE3)
crates/jobfmt        job manifest/result formats, signing-message encoding
crates/worker        worker daemon + local runner (a "peer")
crates/coordinator   quorum/dispute/ledger logic + network server (the job client)
crates/wire          transport: length-prefixed JSON frames, TLS, admission PoW
crates/contentstore  BLAKE3-addressed blob store (the torrent layer, seeded)
crates/difftest      differential determinism harness
crates/conformance   conformance driver: QEMU differential + riscv-tests tally
arch-tests/          the official riscv-tests ELFs (rv64ui/um/uc, 67 tests)
jobs/demo-hash       the demo job: no_std Rust, compiled to a RISC-V ELF
jobs/demo-hash-smoke same program, 32 KiB input — powers the fast network tests
jobs/demo-hash-nano  1 KiB input — the same-ELF zk receipt's workload
jobs/conformance     ISA corner-case suite (explicit inline asm, both impls)
jobs/agent-task      the agent-work pilot job (see docs/PILOT.md)
sp1-guest/           SP1 zkVM guests: the algorithm (fnv) and the emulator (emu)
sp1-host/            SP1 SDK host: execute, prove, verify receipts
scripts/             packaging + validation pipelines (Docker-based)
docs/                DESIGN.md decision log + PILOT.md product direction
```

## Quickstart

```bash
# 1. toolchain (rustup) + the RISC-V target
rustup target add riscv64imac-unknown-none-elf

# 2. unit tests: ISA semantics + quorum logic
cargo test --workspace

# 3. build the demo job (RISC-V ELF) and install it into the job dir
cd jobs/demo-hash/job && cargo build --release && cd ../../..
cp jobs/demo-hash/job/target/riscv64imac-unknown-none-elf/release/demo-hash jobs/demo-hash/program.elf

# 4. run one worker on the demo job (2 MiB input, ~33.5M instructions)
cargo run --release -p worker -- run jobs/demo-hash --id solo

# 5. differential determinism: debug vs release must hash identically
cargo run --release -p difftest -- jobs/demo-hash

# 6. cross-platform differential inside Linux (Docker)
cargo run --release -p difftest -- jobs/demo-hash --docker rust:1-slim

# 7. quorum demo: 3 workers with identities, one malicious → escalation + slashing + ledger
cargo run --release -p coordinator -- run jobs/demo-hash --worker target/release/worker.exe --corrupt --identities --ledger ledger.json

# 8. conformance differential: same ELF under our emulator and qemu-riscv64
scripts/qemu-conformance.sh

# 9. official riscv-tests: the full rv64ui/um/uc suites pass 67/67
cargo run --release -p conformance -- arch arch-tests

# 10. dispute game: honest claim vs corrupt counter-result
target/release/worker.exe run jobs/demo-hash --id w1 --out target/a.json --snapshots target/snaps-w1
target/release/worker.exe run jobs/demo-hash --id w2 --out target/b.json --corrupt
target/release/coordinator.exe dispute jobs/demo-hash --a target/a.json --b target/b.json --snapshots target/snaps-w1

# 11. optimistic acceptance (add --challenge to dispute inside the window)
target/release/coordinator.exe optimistic jobs/demo-hash --worker target/release/worker.exe --window-ms 50

# 12. agent-task pilot: deterministic agent-shaped batch work with an audit chain
cargo run --release -p worker -- run jobs/agent-task --id agent

# 13. zk tier, same-ELF: a verified receipt for the emulator itself
#     executing the actual job ELF (Docker + ~24GB RAM for the prover;
#     the SP1 toolchain is cached in the sp1v container)
scripts/sp1-emu.sh

# 14. algorithm-level zk cross-check: the same FNV algorithm as an
#     independent SP1 guest, receipt verified against the host reference
scripts/sp1-validate.sh

# 15. content-addressed store: publish a job, reconstruct it anywhere from hashes
target/release/coordinator.exe publish jobs/demo-hash --store target/store --out target/demo.desc.json
target/release/coordinator.exe fetch --desc target/demo.desc.json --store target/store --out target/materialized
target/release/worker.exe run target/materialized --id from-store   # identical result hash
target/release/coordinator.exe verify --store target/store

# 16. network session: TLS + authenticated identities + admission PoW;
#     serve --tls generates a self-signed coordinator cert on first run;
#     workers pin its fingerprint (--server-cert) — no other server is accepted
target/release/coordinator.exe serve --jobs-dir target/jobs --store target/store --tls --identity-pow-bits 20 --max-jobs 1
target/release/worker.exe daemon --server 127.0.0.1:7777 --id wA --identity wA.key --server-cert target/store/coordinator-cert.der --listen-port 7780

# 17. persistent multi-job session with peer-to-peer blob exchange:
#     terminal A:  coordinator serve --jobs-dir target/jobs --store target/store --pool 2 --max-jobs 3
#     terminal B:  worker daemon --server 127.0.0.1:7777 --id wA --identity wA.key --listen-port 7780
#     then drop descriptor files (from `coordinator publish --out`) into target/jobs;
#     a fresh worker re-running a job pulls its blobs from a peer, not the coordinator
```

On CI (`.github/workflows/ci.yml`), the differential test runs on
Windows/Linux/macOS (x64 + ARM64), a QEMU job cross-checks the emulator
against an independent RISC-V implementation, the official riscv-tests
tally runs everywhere, and a final job asserts all three platforms
produced byte-identical chunk hash chains. All five checks are required
on the protected `main` branch.

## What is verified, and what is not

This project does not oversell its tiers. What the repo actually
demonstrates:

- **Fraud detection over a real network**: two physical machines, TLS
  with pinned fingerprints, proof-of-work-gated authentication, a
  worker that fabricated a result — caught by quorum, excluded from
  acceptance, bond slashed in the ledger.
- **Independent correctness evidence**: the official riscv-tests
  suites (67/67) and a QEMU differential — sampled evidence that the
  platform matches the ISA, not a proof.
- **A verified same-ELF zk receipt**: a cryptographic proof that the
  pinned emulator, compiled inside the zkVM, executed the real job ELF
  and produced the exact chunk chain the local run produced (nano
  envelope). This is the tier that removes trust in workers entirely.

What remains open (full list in `docs/DESIGN.md`): bonds are ledger
bookkeeping rather than escrowed stake; identity cost is
proof-of-work, not capital; the coordinator is trusted for worker
selection; multi-shard zk proving awaits a newer SP1 or a GPU prover;
NAT traversal and internet-scale discovery are unbuilt.

## The determinism contract

A job is a pure function `(program.elf, input.bin) -> (result, chunk hashes)`.
The emulator guarantees:

- entire architectural state = 32 registers + pc + memory (nothing hidden);
- reads of unallocated pages are zero; writes allocate; 4 GiB flat space;
- misaligned loads/stores are supported (deterministic byte-level split,
  matching spike/QEMU); invalid encodings and out-of-range accesses trap;
- `ecall` traps (QEMU-compatible syscall mode for the conformance
  differential); `ebreak` → clean halt; output is read from the ABI's
  output region;
- hash chain: `BLAKE3(prev_hash || registers || pc || mtvec || mepc ||
  mcause || mstatus || memory_root)` emitted every `chunk_size`
  instructions and at exit — every architectural field is bound.

Any two machines that run the same job and disagree on a single chunk hash
have found a bug — the CI differential test exists to make that never happen
silently.

## Job ABI (see `crates/abi`)

```
0x1000_0000  u64 input length, bytes follow
0x2000_0000  u64 output length (written by the job), bytes follow
0x8000_0000  ELF image base (jobs link here)
0x83F0_0000  initial stack pointer
halt: execute `ebreak`   |   ISA pin: rv64imc (no atomics, no FP)
```

## License

Dual-licensed under MIT or Apache-2.0, at your option (see
LICENSE-MIT and LICENSE-APACHE).
