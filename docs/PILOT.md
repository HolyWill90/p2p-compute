# Pilot: verifiable agent-task execution

## Why this pilot

The 2025–2026 market survey (see the session research) found the demand
converging on one sentence: **prove what an AI agent actually executed.**
Regulatory pressure (EU AI Act, ISO/IEC 42001, NIST AI RMF) is turning agent
audit trails into a compliance requirement; crypto-native demand (Trail of
Bits' Yap SDK, Polyhedra's Proof of Prompt, Gensyn's proof-of-learning) is
pulling the same rope from the other side. Every one of those efforts either
uses TEEs (trust a chip vendor), ZK proofs (20–100× overhead today), or
optimistic games anchored to a chain.

This project's substrate offers the missing cheap tier: **a deterministic
sandbox whose execution produces a cryptographic audit trail for free.** An
agent's batch work (data transforms, computations, file processing) runs as a
job inside the pinned RV64IMC machine; the emulator emits a BLAKE3 chunk-hash
chain covering every instruction. That chain *is* the audit trail:

- any auditor can re-execute the job and compare the chain — bit-for-bit;
- a disputed chain is adjudicated by the dispute game at one-chunk cost;
- when an auditor wants cryptographic, trust-free verification, the same
  ELF compiles for the RISC-V zkVM ecosystem (SP1, RISC Zero, Jolt) and
  carries a proof — the ISA pin was chosen for exactly this.

## What exists in this repo

`jobs/agent-task` is the pilot workload: an agent-shaped batch transform
(records with per-record operations, emitted results, aggregate checksum).
It runs end-to-end through `worker` → chunk-hash chain → `coordinator`
quorum/dispute, and its digest was verified against an independent
implementation. `jobs/conformance` proves the emulator agrees with
`qemu-riscv64` (an independent implementation) on the pinned ISA.

## The pilot product shape

1. **Sandbox SDK**: a Rust crate that lets an agent developer express a task
   as a deterministic job (the `agent-task` pattern: inputs in, transforms,
   outputs + checksum). Non-determinism (clock, RNG, network) is an explicit
   ABI service, never ambient.
2. **Audit artifact**: every task run yields `{job, result, chunk-hash
   chain}` — tamper-evident, independently re-executable, ~100 bytes of
   overhead per million instructions.
3. **Verification tiers by stakes**: quorum for cheap tasks (implemented),
   optimistic + dispute for standard (implemented), zk proof for
   high-stakes (upgrade path reserved, same ELF).
4. **Ledger**: worker identities (Ed25519) and bond balances persist across
   jobs; slashing is bookkeeping, not trust.

## What a production pilot needs beyond this repo

- Networking: real worker machines over TLS instead of local processes (the
  protocol surface — result JSON and hash chains — is unchanged).
- Input/output availability: results reference inputs by hash; a content
  store (the "torrent" layer of this design) makes jobs independently
  re-executable by any auditor.
- A dispute-market layer: bonded watchers paid from slashed stakes, so
  challenge coverage is a priced service rather than an assumption.
- zk tier bring-up: the SP1 cross-validation harness under `scripts/` is the
  first concrete step.
