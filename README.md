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
| Strong | SP1 zkVM proof — same algorithm, guest compiled for SP1's RISC-V | 1× + prover tax | receipt verified (three-way digest match on a 4 KiB input; full same-ELF proving not yet automated) |

See `docs/DESIGN.md` for the decision log and `docs/PILOT.md` for the
product direction.

## Layout

```
crates/abi         job ABI: memory map, halt convention, pinned ISA string
crates/rvcore      the emulator: RV64IMC interpreter + chunk-hash chain (BLAKE3)
crates/jobfmt      job manifest/result formats
crates/worker      worker daemon + local runner (a "peer")
crates/coordinator quorum/dispute/ledger logic + network server (the job client)
crates/wire        transport: length-prefixed JSON frames, TLS support, peer protocol
crates/contentstore BLAKE3-addressed blob store (the torrent layer, seeded)
crates/difftest    differential determinism harness
crates/conformance ISA conformance differential driver (emulator vs QEMU)
jobs/demo-hash     the demo job: no_std Rust, compiled to a RISC-V ELF
jobs/conformance   ISA corner-case suite (explicit inline asm, both impls)
jobs/agent-task    the agent-work pilot job (see docs/PILOT.md)
sp1-guest          the demo algorithm as an SP1 zkVM guest (zk tier harness)
sp1-host           SP1 SDK host: execute + verify the guest receipt
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

# 9. dispute game: honest claim vs corrupt counter-result
target/release/worker.exe run jobs/demo-hash --id w1 --out target/a.json --snapshots target/snaps-w1
target/release/worker.exe run jobs/demo-hash --id w2 --out target/b.json --corrupt
target/release/coordinator.exe dispute jobs/demo-hash --a target/a.json --b target/b.json --snapshots target/snaps-w1

# 10. optimistic acceptance (add --challenge to dispute inside the window)
target/release/coordinator.exe optimistic jobs/demo-hash --worker target/release/worker.exe --window-ms 50

# 11. agent-task pilot: deterministic agent-shaped batch work with an audit chain
cargo run --release -p worker -- run jobs/agent-task --id agent

# 12. content-addressed store: publish a job, reconstruct it anywhere from hashes
target/release/coordinator.exe publish jobs/demo-hash --store target/store --out target/demo.desc.json
target/release/coordinator.exe fetch --desc target/demo.desc.json --store target/store --out target/materialized
target/release/worker.exe run target/materialized --id from-store   # identical result hash
target/release/coordinator.exe verify --store target/store

# 13. zk tier (needs the SP1 toolchain, ~2 GB one-time download)
#     verifies the same ALGORITHM as a zkVM guest — not yet the same ELF binary
scripts/sp1-validate.sh

# 14. TLS: serve --tls generates a self-signed coordinator cert on first run;
#     workers pin its fingerprint (--server-cert) — no other server is accepted
target/release/coordinator.exe serve --jobs-dir target/jobs --store target/store --tls --max-jobs 1
target/release/worker.exe daemon --server 127.0.0.1:7777 --id wA --identity wA.key     --server-cert target/store/coordinator-cert.der --listen-port 7780

# 15. persistent multi-job session with peer-to-peer blob exchange:
#     terminal A:  coordinator serve --jobs-dir target/jobs --store target/store --pool 2 --max-jobs 3
#     terminal B:  worker daemon --server 127.0.0.1:7777 --id wA --identity wA.key --listen-port 7780
#     then drop descriptor files (from `coordinator publish --out`) into target/jobs;
#     a fresh worker re-running a job pulls its blobs from a peer, not the coordinator
```

On CI (`.github/workflows/ci.yml`), the differential test runs on
Windows/Linux/macOS (x64 + ARM64), a QEMU job cross-checks the emulator
against an independent RISC-V implementation, and a final job asserts all
three platforms produced byte-identical chunk hash chains.

## The determinism contract

A job is a pure function `(program.elf, input.bin) -> (result, chunk hashes)`.
The emulator guarantees:

- entire architectural state = 32 registers + pc + memory (nothing hidden);
- reads of unallocated pages are zero; writes allocate; 4 GiB flat space;
- misaligned access, invalid encodings, `ecall` → deterministic trap;
- `ebreak` → clean halt; output is read from the ABI's output region;
- hash chain: `BLAKE3(prev_hash || registers || pc || memory_root)` emitted
  every `chunk_size` instructions and at exit.

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
