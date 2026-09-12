use coordinator::dispute::{decode_chain, first_divergence, verdict_with_truth, Verdict};
use coordinator::ledger::Ledger;
use coordinator::optimistic::{self, State};
use jobfmt::WorkerResult;

fn h(name: &str) -> [u8; 32] {
    // Deterministic pseudo-hashes named per test, not real hashes —
    // the protocol logic under test never executes a job.
    let mut out = [0u8; 32];
    let bytes = name.as_bytes();
    for (i, b) in out.iter_mut().enumerate() {
        *b = bytes[i % bytes.len()].wrapping_add(i as u8);
    }
    out
}

fn hexs(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn divergence_found_at_first_mismatch() {
    let a = vec![h("s0"), h("s1"), h("s2"), h("s3")];
    let mut b = a.clone();
    b[2] = h("evil");
    assert_eq!(first_divergence(&a, &b), Some(2));
    // Truncated chain diverges at its end.
    let short = &a[..2];
    assert_eq!(first_divergence(&a, short), Some(2));
    // Identical chains never diverge.
    assert_eq!(first_divergence(&a, &a), None);
}

#[test]
fn verdict_follows_the_judge() {
    let a = vec![h("s0"), h("s1"), h("s2")];
    let mut b = a.clone();
    b[2] = h("evil");
    let k = first_divergence(&a, &b).unwrap();

    // Judge says the honest value:
    assert_eq!(
        verdict_with_truth(&a, &b, k, Some(a[2])),
        Verdict::ClaimHonest { first_divergence: 2 }
    );
    assert_eq!(
        verdict_with_truth(&a, &b, k, Some(b[2])),
        Verdict::CounterHonest { first_divergence: 2 }
    );
    // Judge says neither committed chain is right:
    assert_eq!(
        verdict_with_truth(&a, &b, k, Some(h("neither"))),
        Verdict::BothDishonest { first_divergence: 2 }
    );
    // Judge has no answer:
    assert!(matches!(verdict_with_truth(&a, &b, k, None), Verdict::Malformed(_)));
}

#[test]
fn decode_chain_rejects_bad_input() {
    assert!(decode_chain(&["zz".into()]).is_err());
    assert!(decode_chain(&[hexs(&h("ok"))]).is_ok());
}

#[test]
fn optimistic_window_transitions() {
    let verdict = Verdict::ClaimHonest { first_divergence: 3 };

    // Accept after expiry:
    let s = optimistic::transition(&State::Awaiting, &optimistic::Event::Expire("abc"), false).unwrap();
    assert_eq!(s, State::Accepted { hash: "abc".into() });

    // Expiry refused while the window is open:
    assert!(optimistic::transition(&State::Awaiting, &optimistic::Event::Expire("abc"), true).is_err());

    // In-time challenge escalates to a dispute:
    let s = optimistic::transition(
        &State::Awaiting,
        &optimistic::Event::Challenge(&verdict),
        true,
    )
    .unwrap();
    assert!(matches!(s, State::Disputed { .. }));

    // Late challenge refused:
    assert!(optimistic::transition(
        &State::Awaiting,
        &optimistic::Event::Challenge(&verdict),
        false
    )
    .is_err());

    // Terminal states take nothing further:
    assert!(optimistic::expire(&s, "abc").is_err());
}

fn wr(id: &str, hash: &str) -> WorkerResult {
    WorkerResult {
        worker_id: id.into(),
        job_id: "j".into(),
        status: "halted".into(),
        instructions: 1,
        result_hash: hash.into(),
        chunk_hashes: vec![hash.into()],
        output_hex: None,
        trap: None,
        pubkey_hex: None,
        sig_hex: None,
    }
}

#[test]
fn ledger_accumulates_balances() {
    let dir = std::env::temp_dir().join("p2pc-ledger-test");
    std::fs::remove_dir_all(&dir).ok(); // isolate from previous runs
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ledger.json");

    let mut led = Ledger::load(&path).unwrap();
    assert!(led.balances.is_empty(), "missing file is an empty ledger");
    led.apply("job-1", "accept", &[("w1".into(), 10), ("w2".into(), -100)]);
    led.save(&path).unwrap();

    let led = Ledger::load(&path).unwrap();
    assert_eq!(led.balances["w1"], 10);
    assert_eq!(led.balances["w2"], -100);
    assert_eq!(led.history.len(), 1);

    // A corrupt ledger must be an error, never a silent reset.
    std::fs::write(&path, b"{not json").unwrap();
    assert!(Ledger::load(&path).is_err());
    let _ = wr("x", "y"); // keep helper used
}
