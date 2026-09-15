//! The zk tier, same-ELF edition: THIS guest is the pinned emulator
//! itself (rvcore) executing the ACTUAL job ELF with the ACTUAL input.
//! A verified receipt attests that rvcore, run inside the zkVM on the
//! committed (manifest, elf, input), produced the committed chunk chain
//! and output — replacing worker consensus with a cryptographic proof.
//! What remains trusted is only the rvcore source (validated by the
//! QEMU differential and the official riscv-tests) and the zkVM
//! soundness itself.

#![no_main]
sp1_zkvm::entrypoint!(main);

use rvcore::{elf, interp, Mem};

fn main() {
    let manifest_bytes: Vec<u8> = sp1_zkvm::io::read();
    let elf_bytes: Vec<u8> = sp1_zkvm::io::read();
    let input: Vec<u8> = sp1_zkvm::io::read();

    // The manifest drives the execution parameters exactly as the
    // worker daemon does: chunk_size and max_instructions come from
    // job.json, everything else is the platform default.
    let manifest: jobfmt::JobManifest =
        serde_json::from_slice(&manifest_bytes).expect("manifest");

    // Job binding: commit the content hashes of (manifest, elf, input)
    // BEFORE executing. The content store's ids are plain BLAKE3 over
    // each blob, so a coordinator holding a descriptor can check the
    // receipt attests THIS job — not merely "some" execution.
    let binding: [[u8; 32]; 3] = [
        blake3::hash(&manifest_bytes).into(),
        blake3::hash(&elf_bytes).into(),
        blake3::hash(&input).into(),
    ];
    sp1_zkvm::io::commit::<[[u8; 32]; 3]>(&binding);

    let image = elf::parse(&elf_bytes).expect("elf");
    let mut mem = Mem::new();
    elf::load(&mut mem, &image).expect("load");

    let outcome = interp::run(
        &mut mem,
        image.entry,
        &input,
        &interp::Config {
            chunk_size: manifest.chunk_size,
            max_instructions: manifest.max_instructions, // BISECT
            ..Default::default()
        },
    );

    let status: u32 = match &outcome.status {
        interp::ExitStatus::Halted | interp::ExitStatus::Tohost(_) => 0,
        interp::ExitStatus::InstructionLimit => 1,
        interp::ExitStatus::Trapped(_) => 2,
    };
    sp1_zkvm::io::commit::<u32>(&status);
    sp1_zkvm::io::commit::<u64>(&outcome.instructions);
    sp1_zkvm::io::commit::<Vec<[u8; 32]>>(&outcome.chunk_hashes);
    sp1_zkvm::io::commit::<Vec<u8>>(&outcome.output.unwrap_or_default());
}
