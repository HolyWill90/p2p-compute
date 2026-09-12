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
    let d = decide(&[w("w1", "aaa"), w("w2", "aaa"), w("w3", "bbb")]);
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
    let d = decide(&[w("w1", "aaa"), w("w2", "aaa"), w("w3", "aaa")]);
    assert!(matches!(d, Decision::Accept { .. }));
}

#[test]
fn all_distinct_escalates_then_rejects() {
    let d3 = decide(&[w("w1", "aaa"), w("w2", "bbb"), w("w3", "ccc")]);
    assert!(matches!(d3, Decision::Escalate));
    let d5 = decide(&[
        w("w1", "aaa"),
        w("w2", "bbb"),
        w("w3", "ccc"),
        w("w4", "ddd"),
        w("w5", "eee"),
    ]);
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
    ]);
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
    let d = decide(&pool);
    let ledger = slashing(&d, &pool);
    let w2 = ledger.iter().find(|(id, _)| id == "w2").unwrap();
    assert_eq!(*w2, ("w2".into(), -100));
    let honest = ledger.iter().filter(|(id, v)| id != "w2" && *v == 10).count();
    assert_eq!(honest, 4);
}

#[test]
fn majority_traps_reject_the_job() {
    // The program itself is broken: two of three crash identically.
    let d = decide(&[trapped("w1", "aaa"), trapped("w2", "bbb"), w("w3", "aaa")]);
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
    let d = decide(&[w("w1", "aaa"), liar, w("w3", "bbb")]);
    assert!(matches!(d, Decision::Reject { .. }));
}

#[test]
fn trapped_minority_with_majority_accepts() {
    let d = decide(&[w("w1", "aaa"), trapped("w2", "aaa"), w("w3", "aaa")]);
    assert!(matches!(d, Decision::Accept { .. }));
}
