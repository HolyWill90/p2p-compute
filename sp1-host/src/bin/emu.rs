//! Same-ELF zk tier validation: run the LOCAL rvcore on the smoke job,
//! then run the SAME emulator compiled as an SP1 guest on the SAME
//! bytes, prove the execution, and verify the receipt. The committed
//! chain, instruction count, and output must equal the local run
//! byte-for-byte. Modes:
//!   emu execute   - fast: zkVM execution without a cryptographic proof
//!   emu prove     - full receipt (slow; minutes of CPU proving)

use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
use sp1_sdk::ProvingKey;

fn local_reference(
    manifest_bytes: &[u8],
    elf_bytes: &[u8],
    input: &[u8],
) -> (u32, u64, Vec<[u8; 32]>, Vec<u8>) {
    let manifest: jobfmt::JobManifest = serde_json::from_slice(manifest_bytes).unwrap();
    let image = rvcore::elf::parse(elf_bytes).unwrap();
    let mut mem = rvcore::Mem::new();
    rvcore::elf::load(&mut mem, &image).unwrap();
    let outcome = rvcore::interp::run(
        &mut mem,
        image.entry,
        input,
        &rvcore::interp::Config {
            chunk_size: manifest.chunk_size,
            max_instructions: manifest.max_instructions,
            ..Default::default()
        },
    );
    let status = match &outcome.status {
        rvcore::interp::ExitStatus::Halted | rvcore::interp::ExitStatus::Tohost(_) => 0,
        rvcore::interp::ExitStatus::InstructionLimit => 1,
        rvcore::interp::ExitStatus::Trapped(_) => 2,
    };
    (status, outcome.instructions, outcome.chunk_hashes.clone(), outcome.output.unwrap_or_default())
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "execute".into());
    assert!(mode == "execute" || mode == "prove", "mode: execute|prove");

    let manifest_bytes = std::fs::read("../jobs/demo-hash-smoke/job.json").expect("manifest");
    let elf_bytes = std::fs::read("../jobs/demo-hash-smoke/program.elf").expect("job elf");
    let input = std::fs::read("../jobs/demo-hash-smoke/input.bin").expect("job input");

    let (status, instructions, chain, output) =
        local_reference(&manifest_bytes, &elf_bytes, &input);
    println!(
        "local rvcore: status {status}, {} instructions, {} chunk(s), result {}",
        instructions,
        chain.len(),
        hex(&chain.last().copied().unwrap_or_default()),
    );

    let guest_bytes = std::fs::read("../elf/sp1-guest-emu").expect("guest ELF (build sp1-guest first)");
    let elf = Elf::Dynamic(guest_bytes.into());
    let prover = ProverClient::builder().cpu().build();
    let pk = prover.setup(elf.clone()).expect("setup");

    let mut stdin = SP1Stdin::new();
    stdin.write(&manifest_bytes);
    stdin.write(&elf_bytes);
    stdin.write(&input);

    if mode == "execute" {
        let (mut pv, _report) = prover.execute(elf.clone(), stdin).run().expect("execute");
        let status_zk: u32 = pv.read();
        let instructions_zk: u64 = pv.read();
        let chain_zk: Vec<[u8; 32]> = pv.read();
        let output_zk: Vec<u8> = pv.read();
        assert_eq!(status_zk, status, "status mismatch");
        assert_eq!(instructions_zk, instructions, "instruction count mismatch");
        assert_eq!(chain_zk, chain, "chunk chain mismatch");
        assert_eq!(output_zk, output, "output mismatch");
        println!("SP1 EMU EXECUTE PASS: same-ELF execution matches local rvcore ({} chunk(s))", chain_zk.len());
        return;
    }

    let mut proof = prover.prove(&pk, stdin).compressed().run().expect("proving");
    let status_zk: u32 = proof.public_values.read();
    let instructions_zk: u64 = proof.public_values.read();
    let chain_zk: Vec<[u8; 32]> = proof.public_values.read();
    let output_zk: Vec<u8> = proof.public_values.read();
    assert_eq!(status_zk, status, "status mismatch");
    assert_eq!(instructions_zk, instructions, "instruction count mismatch");
    assert_eq!(chain_zk, chain, "chunk chain mismatch");
    assert_eq!(output_zk, output, "output mismatch");

    prover
        .verify(&proof, &pk.verifying_key(), None)
        .expect("receipt verification");
    println!(
        "SP1 EMU PROVE PASS: verified receipt - rvcore on the actual job ELF produced {} ({} instruction(s), {} chunk(s))",
        hex(&chain_zk.last().copied().unwrap_or_default()),
        instructions_zk,
        chain_zk.len(),
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
