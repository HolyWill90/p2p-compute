//! The zk tier of the demo-hash job: the SAME FNV-stream algorithm as
//! `jobs/demo-hash`, compiled for the SP1 RISC-V zkVM. Passing this
//! proves the pinned-ISA strategy: one source tree, three execution
//! and verification tiers (quorum here, dispute game here, zk proof
//! there).
//!
//! Built with the SP1 toolchain:
//!   cd sp1-guest && cargo prove build
//! and executed/verified by `sp1-host` (see scripts/sp1-validate.sh).

#![no_main]
sp1_zkvm::entrypoint!(main);

const MUL: u64 = 0x100_0000_01b3;
const SEEDS: [u64; 4] = [
    0xcbf2_9ce4_8422_2325,
    0x9e37_79b9_7f4a_7c15,
    0x1656_67e1_9a9c_2b1d,
    0x27d4_eb2f_1656_67c5,
];

fn main() {
    let input: Vec<u8> = sp1_zkvm::io::read();

    let mut acc = SEEDS;
    for &b in &input {
        acc[0] = (acc[0] ^ b as u64).wrapping_mul(MUL);
        acc[1] = (acc[1] ^ b as u64).wrapping_mul(MUL ^ 0x1);
        acc[2] = (acc[2] ^ (b as u64).rotate_left(7)).wrapping_mul(MUL);
        acc[3] = (acc[3] ^ b as u64).wrapping_mul(MUL).rotate_left(13) ^ b as u64;
    }

    // Commit the digest; the receipt is a succinct proof that THIS
    // program produced it from the committed input.
    sp1_zkvm::io::commit::<[u64; 4]>(&acc);
}
