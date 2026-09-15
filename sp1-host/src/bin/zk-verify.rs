//! Standalone zk receipt verifier (no prover): invoked by the
//! coordinator as an external oracle. Protocol:
//!   argv: <guest-elf> <receipt-file> <binding-hex-1> <2> <3>
//!   stdin: ignored
//!   stdout: one JSON verdict:
//!     {"ok":true,"status":0,"instructions":N,"chain":["hex"],"output_hex":"hex"}
//!     {"ok":false,"error":"..."}
//! The verifying key is re-derived from the committed guest ELF, so a
//! receipt only verifies against the exact emulator binary it claims.

use sp1_sdk::blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin};
use sp1_sdk::{ProvingKey, SP1ProofWithPublicValues};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (guest_elf, receipt_file, binding) = match args.as_slice() {
        [g, r, b1, b2, b3] => (g, r, [b1.clone(), b2.clone(), b3.clone()]),
        _ => {
            println!("{{\"ok\":false,\"error\":\"usage: zk-verify <guest-elf> <receipt-file> <binding-hex-1> <2> <3>\"}}");
            std::process::exit(1);
        }
    };
    match run(&guest_elf, &receipt_file, &binding) {
        Ok(v) => println!("{v}"),
        Err(e) => {
            println!("{{\"ok\":false,\"error\":{}}}", serde_json::to_string(&e).unwrap());
            std::process::exit(1);
        }
    }
}

fn run(guest_elf: &str, receipt_file: &str, binding_hex: &[String; 3]) -> Result<String, String> {
    let decode = |s: &str| -> Result<[u8; 32], String> {
        let bytes = jobfmt::from_hex(s, 32).map_err(|e| format!("binding hex: {e}"))?;
        Ok(bytes.try_into().map_err(|_| "binding hex length".to_string())?)
    };
    let expected_binding = [
        decode(&binding_hex[0])?,
        decode(&binding_hex[1])?,
        decode(&binding_hex[2])?,
    ];

    let mut proof = SP1ProofWithPublicValues::load(receipt_file)
        .map_err(|e| format!("receipt load: {e}"))?;
    let guest_bytes = std::fs::read(guest_elf).map_err(|e| format!("guest ELF: {e}"))?;
    let prover = ProverClient::builder().cpu().build();
    let pk = prover
        .setup(Elf::Dynamic(guest_bytes.into()))
        .map_err(|e| format!("guest setup: {e}"))?;

    let binding: [[u8; 32]; 3] = proof.public_values.read();
    if binding != expected_binding {
        return Err("receipt is not for this job's (manifest, elf, input)".into());
    }
    let status: u32 = proof.public_values.read();
    let instructions: u64 = proof.public_values.read();
    let chain: Vec<[u8; 32]> = proof.public_values.read();
    let output: Vec<u8> = proof.public_values.read();

    prover
        .verify(&proof, &pk.verifying_key(), None)
        .map_err(|e| format!("receipt verification: {e}"))?;

    let chain_hex: Vec<String> = chain.iter().map(|h| hex(h)).collect();
    Ok(format!(
        "{{\"ok\":true,\"status\":{status},\"instructions\":{instructions},\"chain\":{},\"output_hex\":{}}}",
        serde_json::to_string(&chain_hex).unwrap(),
        serde_json::to_string(&hex(&output)).unwrap(),
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

