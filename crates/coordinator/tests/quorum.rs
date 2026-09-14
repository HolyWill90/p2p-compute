use coordinator::{decide, slashing, Decision};
use jobfmt::WorkerResult;

fn w(id: &str, hash: &str) -> WorkerResult {
    WorkerResult {
        worker_id: id.to_string(),
        job_id: "j".into(),
        status: "halted".into(),
        instructions: 10,
        result_hash: hash.into(),
        chunk_hashes: vec![hash.into()],
        output_hex: Some("abcd".into()),
        trap: None,
        pubkey_hex: None,
        sig_hex: None,
    }
}

fn trapped(id: &str, hash: &str) -> WorkerResult {
    let mut r = w(id, hash);
    r.status = "trap".into();
    r.output_hex = None;
    r
}

#[test]
fn three_way_majority_accepts() {
    let d = decide(&[w("w1", "aaa"), w("w2", "aaa"), w("w3", "bbb")], 3);
    match d {
        Decision::Accept { hash, agreed, .. } => {
            assert_eq!(hash, "aaa");
            assert_eq!(agreed, vec!["w1", "w2"]);
        }
        _ => panic!("expected accept, got {d:?}"),
    }
}

#[test]
fn unanimous_accepts() {
    let d = decide(&[w("w1", "aaa"), w("w2", "aaa"), w("w3", "aaa")], 3);
    assert!(matches!(d, Decision::Accept { .. }));
}

#[test]
fn all_distinct_escalates_then_rejects() {
    let d3 = decide(&[w("w1", "aaa"), w("w2", "bbb"), w("w3", "ccc")], 3);
    assert!(matches!(d3, Decision::Escalate));
    let d5 = decide(&[
        w("w1", "aaa"),
        w("w2", "bbb"),
        w("w3", "ccc"),
        w("w4", "ddd"),
        w("w5", "eee"),
    ], 5);
    assert!(matches!(d5, Decision::Reject { .. }));
}

#[test]
fn escalation_recovers_majority() {
    // 2 honest, 1 corrupt: escalation finds 4/5
    let d = decide(&[
        w("w1", "aaa"),
        w("w2", "bad"),
        w("w3", "aaa"),
        w("w4", "aaa"),
        w("w5", "aaa"),
    ], 5);
    match d {
        Decision::Accept { hash, agreed, .. } => {
            assert_eq!(hash, "aaa");
            assert_eq!(agreed.len(), 4);
        }
        _ => panic!("expected accept"),
    }
}

#[test]
fn minority_corruption_is_slashed() {
    let pool = vec![
        w("w1", "aaa"),
        w("w2", "bad"),
        w("w3", "aaa"),
        w("w4", "aaa"),
        w("w5", "aaa"),
    ];
    let d = decide(&pool, pool.len());
    let ledger = slashing(&d, &pool);
    let w2 = ledger.iter().find(|(id, _)| id == "w2").unwrap();
    assert_eq!(*w2, ("w2".into(), -100));
    let honest = ledger.iter().filter(|(id, v)| id != "w2" && *v == 10).count();
    assert_eq!(honest, 4);
}

#[test]
fn majority_traps_reject_the_job() {
    // The program itself is broken: two of three crash identically.
    let d = decide(&[trapped("w1", "aaa"), trapped("w2", "bbb"), w("w3", "aaa")], 3);
    match d {
        Decision::Reject { reason } => assert!(reason.contains("trapped")),
        _ => panic!("expected reject"),
    }
}

#[test]
fn chain_disagreement_in_winning_group_rejects() {
    // Same final hash but different chunk chains: a dispute condition,
    // never silently accepted.
    let mut liar = w("w2", "aaa");
    liar.chunk_hashes = vec!["zzz".into(), "aaa".into()];
    let d = decide(&[w("w1", "aaa"), liar, w("w3", "bbb")], 3);
    assert!(matches!(d, Decision::Reject { .. }));
}

#[test]
fn trapped_minority_with_majority_accepts() {
    let d = decide(&[w("w1", "aaa"), trapped("w2", "aaa"), w("w3", "aaa")], 3);
    assert!(matches!(d, Decision::Accept { .. }));
}


#[test]
fn duplicate_votes_do_not_stuff_quorum() {
    // One worker's repeated submissions must not manufacture a
    // majority: quorum counts workers, not messages.
    let d = decide(&[w("w1", "aaa"), w("w1", "aaa"), w("w2", "bbb")], 3);
    assert!(matches!(d, Decision::Escalate), "got {d:?}");
    let d = decide(&[w("w2", "bbb"), w("w2", "bbb"), w("w1", "aaa")], 3);
    assert!(matches!(d, Decision::Escalate), "got {d:?}");
}

mod signature_binding {
    use super::*;
    use coordinator::verify_signature;
    use ed25519_dalek::{Signer, SigningKey};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A worker-signed result: the signature covers every field via
    /// jobfmt::signing_message.
    fn signed(id: &str, hash: &str) -> WorkerResult {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut r = w(id, hash);
        r.output_hex = Some("0123abcd".into());
        r.instructions = 42;
        let msg = jobfmt::signing_message(&r);
        let sig = key.sign(&msg);
        r.pubkey_hex = Some(hex(&key.verifying_key().to_bytes()));
        r.sig_hex = Some(hex(&sig.to_bytes()));
        r
    }

    #[test]
    fn signed_result_verifies() {
        assert!(verify_signature(&signed("w1", "aaa")).is_ok());
    }

    #[test]
    fn unsigned_result_fails() {
        assert!(verify_signature(&w("w1", "aaa")).is_err());
    }

    #[test]
    fn tampering_any_field_breaks_verification() {
        let base = signed("w1", "aaa");

        let mut r = base.clone();
        r.output_hex = Some("deadbeef".into());
        assert!(verify_signature(&r).is_err(), "output must be bound");

        let mut r = base.clone();
        r.job_id = "other-job".into();
        assert!(verify_signature(&r).is_err(), "job id must be bound");

        let mut r = base.clone();
        r.chunk_hashes = vec!["bbb".into()];
        assert!(verify_signature(&r).is_err(), "chain must be bound");

        let mut r = base.clone();
        r.instructions = 43;
        assert!(verify_signature(&r).is_err(), "instruction count must be bound");

        let mut r = base.clone();
        r.status = "trap".into();
        assert!(verify_signature(&r).is_err(), "status must be bound");

        let mut r = base.clone();
        r.result_hash = "bbb".into();
        assert!(verify_signature(&r).is_err(), "result hash must be bound");

        let mut r = base.clone();
        r.worker_id = "w2".into();
        assert!(verify_signature(&r).is_err(), "worker id must be bound");
    }

    #[test]
    fn malformed_hex_fails_without_panic() {
        let mut r = signed("w1", "aaa");
        // 64 bytes long in BYTES but containing multi-byte UTF-8: the
        // old byte-offset slicing panicked on this input.
        r.pubkey_hex = Some("é".repeat(32));
        assert!(verify_signature(&r).is_err());
        r = signed("w1", "aaa");
        r.sig_hex = Some("zz".repeat(64));
        assert!(verify_signature(&r).is_err());
        r = signed("w1", "aaa");
        r.sig_hex = Some("a".repeat(63)); // short
        assert!(verify_signature(&r).is_err());
    }
}


#[test]
fn timeout_partial_response_cannot_self_approve() {
    // REGRESSION: decide() used to derive the majority threshold from
    // the RECEIVED results, so if only 1 of 5 dispatched workers
    // answered before the deadline, that lone vote was a "majority"
    // and self-approved. The threshold is anchored to the dispatched
    // pool: partial responses escalate or reject, never accept.
    // Round 1 (3 dispatched, reserves held back): a lone response
    // escalates — the threshold is 2, so one vote cannot self-approve.
    let d = decide(&[w("w1", "aaa")], 3);
    assert!(matches!(d, Decision::Escalate), "1 of 3: {d:?}");
    // Two agreeing votes ARE a strict majority of 3: a legitimate
    // quorum, even though the third worker never answered.
    let d = decide(&[w("w1", "aaa"), w("w2", "aaa")], 3);
    assert!(matches!(d, Decision::Accept { .. }), "2 of 3: {d:?}");
    // Post-escalation (5 dispatched, no reserves left): the threshold
    // is 3 — one or two responses must never accept.
    let d = decide(&[w("w1", "aaa")], 5);
    assert!(!matches!(d, Decision::Accept { .. }), "1 of 5 accepted: {d:?}");
    let d = decide(&[w("w1", "aaa"), w("w2", "aaa")], 5);
    assert!(!matches!(d, Decision::Accept { .. }), "2 of 5 accepted: {d:?}");
    // A full-pool majority still accepts normally.
    let d = decide(&[w("w1", "aaa"), w("w2", "aaa"), w("w3", "aaa")], 3);
    assert!(matches!(d, Decision::Accept { .. }), "3 of 3 must accept");
}

#[test]
fn rejected_jobs_do_not_slash_responders() {
    // REGRESSION: a timeout rejection used to burn every responder's
    // bond, including a lone honest worker whose peers were merely
    // slow. Slashing requires proof: an accepted majority the worker
    // sits outside of. Rejected jobs return bonds untouched.
    let pool = vec![w("w1", "aaa"), w("w2", "bbb")];
    let d = decide(&pool, 3);
    assert!(matches!(d, Decision::Escalate));
    let ledger = slashing(&d, &pool);
    assert!(
        ledger.iter().all(|(_, v)| *v == 0),
        "rejected job must not slash: {ledger:?}"
    );
}
