pub mod dispute;
pub mod ledger;
pub mod net;
pub mod optimistic;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jobfmt::WorkerResult;

/// Quorum decision over a pool of worker results.
///
/// This is the budget tier of verification: it never proves a result
/// correct. It bounds the probability of accepting a wrong answer by
/// independent random sampling (P(all N sampled workers collude) =
/// f^N for a cheating fraction f) and makes detected fraud
/// economically irrational via bonds. The zk tier is what removes the
/// trust assumption entirely; this tier is what runs cheaply today.
#[derive(Debug, Clone)]
pub enum Decision {
    /// Majority hash + the output of the agreeing group + worker ids.
    Accept { hash: String, output_hex: Option<String>, agreed: Vec<String> },
    /// Initial pool was inconclusive; add more workers (escalation).
    Escalate,
    /// No majority in the full pool, or a majority of failed runs:
    /// the job fails and bonds are burned.
    Reject { reason: String },
}

fn group_by<'a>(results: &[&'a WorkerResult]) -> Vec<(String, Vec<&'a WorkerResult>)> {
    let mut groups: Vec<(String, Vec<&WorkerResult>)> = Vec::new();
    for r in results {
        match groups.iter_mut().find(|(h, _)| *h == r.result_hash) {
            Some((_, g)) => g.push(r),
            None => groups.push((r.result_hash.clone(), vec![r])),
        }
    }
    groups
}

/// `pool` is the number of results in this round (3 = initial, 5 =
/// after one escalation). Threshold is a strict majority.
pub fn decide(pool_results: &[WorkerResult]) -> Decision {
    let pool = pool_results.len();
    let threshold = pool / 2 + 1;
    let refs: Vec<&WorkerResult> = pool_results.iter().collect();

    let halted: Vec<&WorkerResult> = refs.iter().copied().filter(|r| r.status == "halted").collect();
    let trapped = pool - halted.len();

    if halted.len() >= threshold {
        let mut groups = group_by(&halted);
        groups.sort_by_key(|(_, g)| std::cmp::Reverse(g.len()));
        let (hash, group) = &groups[0];
        if group.len() >= threshold {
            // Workers that agree on the final hash must agree on the
            // full chain; a disagreement is a dispute condition. The
            // binary-search dispute game is a later milestone; for now
            // an inconsistent winning group is a rejection, never a
            // silent accept.
            let first_chain = &group[0].chunk_hashes;
            let chains_consistent =
                group.iter().all(|r| &r.chunk_hashes == first_chain);
            if chains_consistent {
                return Decision::Accept {
                    hash: hash.clone(),
                    output_hex: group[0].output_hex.clone(),
                    agreed: group.iter().map(|r| r.worker_id.clone()).collect(),
                };
            } else {
                return Decision::Reject {
                    reason: "winning group disagrees on chunk chain (dispute required)".into(),
                };
            }
        }
    }

    if trapped >= threshold {
        return Decision::Reject { reason: "majority of workers trapped: job is broken".into() };
    }

    if pool >= 5 {
        return Decision::Reject {
            reason: "no majority after escalation; bonds burned".into(),
        };
    }

    Decision::Escalate
}

/// Total bond economics placeholder: a worker caught contradicting the
/// accepted majority loses its bond; workers in the winning group get
/// paid. The numbers live with the coordinator's ledger, not here.
pub fn slashing(decision: &Decision, pool_results: &[WorkerResult]) -> Vec<(String, i64)> {
    match decision {
        Decision::Accept { agreed, .. } => pool_results
            .iter()
            .map(|r| {
                let id = r.worker_id.clone();
                if agreed.contains(&id) {
                    (id, 10) // reward units
                } else {
                    (id, -100) // bond burn units
                }
            })
            .collect(),
        _ => pool_results.iter().map(|r| (r.worker_id.clone(), -100)).collect(),
    }
}

/// Verify a worker's Ed25519 signature over its claimed result hash.
/// An unsigned result fails only when the coordinator requires
/// identities — callers decide the policy; this function is the check.
pub fn verify_signature(r: &WorkerResult) -> Result<(), String> {
    let (pk_hex, sig_hex) = match (&r.pubkey_hex, &r.sig_hex) {
        (Some(pk), Some(sig)) => (pk, sig),
        _ => return Err("result is unsigned".into()),
    };
    let decode = |s: &str, expect: usize| -> Result<Vec<u8>, String> {
        if s.len() != expect * 2 {
            return Err(format!("bad length {}/{}", s.len(), expect * 2));
        }
        (0..expect)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string()))
            .collect()
    };
    let pk_bytes = decode(pk_hex, 32).map_err(|e| format!("pubkey: {e}"))?;
    let sig_bytes = decode(sig_hex, 64).map_err(|e| format!("signature: {e}"))?;
    let msg = decode(&r.result_hash, 32).map_err(|e| format!("hash: {e}"))?;
    let vk = VerifyingKey::from_bytes(&pk_bytes.try_into().unwrap())
        .map_err(|e| format!("pubkey: {e}"))?;
    let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());
    vk.verify(&msg, &sig).map_err(|e| format!("signature: {e}"))
}
