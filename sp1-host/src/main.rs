//! Host side of the SP1 cross-validation: execute the guest inside the
//! SP1 zkVM, prove the execution, verify the receipt, and compare the
//! committed digest against the host reference for the same input.
//!
//! Uses the `sp1_sdk::blocking` API (sync) from SP1 v6.x. The guest
//! ELF is read from disk at runtime (built into elf/ by the pipeline),
//! so this crate has no compile-time dependency on the guest build.
//!
//! Note: this crate is intentionally OUTSIDE the main workspace (it
//! needs the SP1 SDK and is only built by the SP1 pipeline).

use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
use sp1_sdk::ProvingKey;

const MUL: u64 = 0x100_0000_01b3;

fn host_reference(input: &[u8]) -> [u64; 4] {
    let seeds: [u64; 4] = [
        0xcbf29ce484222325,
        0x9e3779b97f4a7c15,
        0x165667e19a9c2b1d,
        0x27d4eb2f165667c5,
    ];
    let mut acc = seeds;
    for &b in input {
        acc[0] = (acc[0] ^ b as u64).wrapping_mul(MUL);
        acc[1] = (acc[1] ^ b as u64).wrapping_mul(MUL ^ 0x1);
        acc[2] = (acc[2] ^ (b as u64).rotate_left(7)).wrapping_mul(MUL);
        acc[3] = (acc[3] ^ b as u64).wrapping_mul(MUL).rotate_left(13) ^ b as u64;
    }
    acc
}

fn main() {
    // Deterministic prefix of the emulator job's input — small enough
    // that CPU proving stays in the minutes range.
    let full = std::fs::read("../jobs/demo-hash/input.bin").expect("input file");
    let input = &full[..4 * 1024];
    let elf_bytes = std::fs::read("../elf/sp1-guest-fnv").expect("guest ELF (build sp1-guest first)");
    let elf = Elf::Dynamic(elf_bytes.into());

    let prover = ProverClient::builder().cpu().build();

    // Setup: compile the machine for this program (also verifies the ELF).
    let pk = prover.setup(elf.clone()).expect("setup");

    // Prove: run the program inside the zkVM and generate the receipt.
    let mut stdin = SP1Stdin::new();
    stdin.write(&input.to_vec());
    let mut proof = prover.prove(&pk, stdin).compressed().run().expect("proving");

    // The receipt's public values carry what the guest committed.
    let committed: [u64; 4] = proof.public_values.read::<[u64; 4]>();
    let expected = host_reference(input);
    println!("zkVM digest:  {committed:?}");
    println!("host digest:  {expected:?}");
    assert_eq!(committed, expected, "zkVM and host disagree");

    // Cryptographic verification of the receipt against the program's
    // verifying key — trust-free confirmation that THIS program
    // produced THIS digest from THIS input.
    prover
        .verify(&proof, &pk.verifying_key(), None)
        .expect("receipt verification");
    println!("SP1 VALIDATION PASS: receipt verified, digest matches host reference");
}
