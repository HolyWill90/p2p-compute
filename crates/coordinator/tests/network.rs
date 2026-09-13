//! The full-network integration test over REAL TCP sockets, three
//! jobs in one persistent session:
//!   job 1: demo-hash-smoke → all workers (quorum accept)
//!   job 2: agent-task → all workers (a second, different job over
//!          the same session — blobs fetched from the coordinator)
//!   job 3: demo-hash-smoke again → targeted at a NEW worker wC with an
//!          empty store, whose only peer hint is wA. The blobs must
//!          arrive worker-to-worker: wA's served counter goes up,
//!          wC's from-server counter stays zero.

use coordinator::net::{self, JobOutcome, ServeConfig};
use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use worker::daemon::{run_daemon, DaemonConfig};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(name);
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Queue a descriptor atomically: the coordinator polls the watched
/// directory continuously, and a plain write truncates the file first
/// — the poll could read an empty or partial descriptor mid-write.
fn queue_desc(jobs_dir: &Path, name: &str, desc: &contentstore::JobDescriptor) {
    let tmp = jobs_dir.join(format!("{name}.queueing"));
    std::fs::write(&tmp, serde_json::to_vec(desc).unwrap()).unwrap();
    std::fs::rename(&tmp, jobs_dir.join(format!("{name}.desc.json"))).unwrap();
}

fn wait_job(rx: &std::sync::mpsc::Receiver<JobOutcome>) -> JobOutcome {
    // Upper bound = the coordinator's own worst case (two full per-job
    // deadline windows: round 1 + escalation) plus slow-runner
    // headroom. Smoke jobs finish in seconds; only a hang trips this.
    rx.recv_timeout(std::time::Duration::from_secs(300))
        .expect("job finished in time")
}

#[test]
fn multi_job_session_with_p2p_blob_exchange() {
    let demo_elf = std::path::Path::new("../../jobs/demo-hash-smoke/program.elf");
    let agent_elf = std::path::Path::new("../../jobs/agent-task/program.elf");
    if !demo_elf.exists() || !agent_elf.exists() {
        eprintln!("SKIP: build the demo-hash-smoke and agent-task jobs first");
        return;
    }
    let root = temp_dir("p2pc-net-multi");
    let jobs_dir = root.join("jobs");
    let store_dir = root.join("store");
    std::fs::create_dir_all(&jobs_dir).unwrap();
    let store = contentstore::Store::open(&store_dir).unwrap();

    // Publish the two distinct jobs into the server's store.
    let desc1 = contentstore::publish(&PathBuf::from("../../jobs/demo-hash-smoke"), &store).unwrap();
    let desc2 = contentstore::publish(&PathBuf::from("../../jobs/agent-task"), &store).unwrap();

    let (bound_tx, bound_rx) = channel();
    let (job_tx, job_rx) = channel::<JobOutcome>();
    let cfg = ServeConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        jobs_dir: jobs_dir.clone(),
        store_dir: store_dir.clone(),
        per_job_deadline: std::time::Duration::from_secs(90),
        ledger: Some(root.join("ledger.json")),
        require_identity: true,
        round1_ids: None,
        pool: Some(2),
        round1_size: None,
        tls: None,
        bound_tx: Some(bound_tx),
        max_jobs: Some(3),
        job_tx: Some(job_tx),
    };

    std::thread::spawn(move || {
        net::serve(cfg).expect("serve");
    });

    let bound = bound_rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap();
    println!("coordinator bound at {bound}");

    // Job 1 queued before any worker connects.
    queue_desc(&jobs_dir, "job1", &desc1);

    let identities = root.join("identities");
    std::fs::create_dir_all(&identities).unwrap();

    // Worker A: serves blobs to peers. Worker B: plain.
    let mut handles = Vec::new();
    {
        let server = bound.to_string();
        let identity = identities.join("wA.key");
        let store_dir = root.join("worker-store-A");
        handles.push(std::thread::spawn(move || {
            run_daemon(&DaemonConfig {
                server,
                worker_id: "wA".into(),
                identity_path: Some(identity),
                store_dir,
                listen_port: Some(0),
                tls: None,
                corrupt: false,
                corrupt_byte: None,
            })
        }));
    }
    {
        let server = bound.to_string();
        let identity = identities.join("wB.key");
        let store_dir = root.join("worker-store-B");
        handles.push(std::thread::spawn(move || {
            run_daemon(&DaemonConfig {
                server,
                worker_id: "wB".into(),
                identity_path: Some(identity),
                store_dir,
                listen_port: None,
                tls: None,
                corrupt: false,
                corrupt_byte: None,
            })
        }));
    }

    // --- job 1: demo-hash-smoke, both workers, quorum accept ---
    let job1 = wait_job(&job_rx);
    assert_eq!(job1.job_id, "demo-hash-smoke-0001");
    assert_eq!(job1.results.len(), 2, "both workers ran job 1");
    assert_eq!(job1.results[0].result_hash, job1.results[1].result_hash);
    let demo_digest = job1.results[0].result_hash.clone();
    let coordinator::Decision::Accept { agreed, .. } = &job1.decision else {
        panic!("job 1 should accept");
    };
    assert_eq!(agreed.len(), 2);

    // --- job 2: agent-task, same session, new blobs from the coordinator ---
    queue_desc(&jobs_dir, "job2", &desc2);
    let job2 = wait_job(&job_rx);
    let coordinator::Decision::Accept { .. } = &job2.decision else {
        panic!("job 2 should accept");
    };
    assert_eq!(job2.results.len(), 2);

    // --- job 3: demo-hash-smoke AGAIN, targeted at a fresh worker wC whose
    // only blob source is worker A (p2p exchange) ---
    let desc3 = contentstore::publish(&PathBuf::from("../../jobs/demo-hash-smoke"), &store).unwrap();
    queue_desc(&jobs_dir, "job3@wC", &desc3);
    {
        let server = bound.to_string();
        let identity = identities.join("wC.key");
        let store_dir = root.join("worker-store-C");
        handles.push(std::thread::spawn(move || {
            run_daemon(&DaemonConfig {
                server,
                worker_id: "wC".into(),
                identity_path: Some(identity),
                store_dir,
                listen_port: None,
                tls: None,
                corrupt: false,
                corrupt_byte: None,
            })
        }));
    }
    let job3 = wait_job(&job_rx);
    assert_eq!(job3.job_id, "demo-hash-smoke-0001");
    assert_eq!(job3.results.len(), 1, "job 3 targeted at wC only");
    assert_eq!(job3.results[0].result_hash, demo_digest, "re-execution matches job 1");
    let coordinator::Decision::Accept { .. } = &job3.decision else {
        panic!("job 3 should accept");
    };

    // Server exits after 3 jobs; daemons report their stats.
    let mut stats: Vec<_> = Vec::new();
    for h in handles {
        match h.join() {
            Ok(Ok(s)) => stats.push(s),
            Ok(Err(e)) => panic!("daemon error: {e}"),
            Err(e) => std::panic::panic_any(e),
        }
    }
    let a = stats.iter().find(|s| s.jobs_done == 2).expect("worker A did 2 jobs");
    let c = stats.iter().find(|s| s.jobs_done == 1).expect("worker C did 1 job");

    // THE P2P ASSERTION: wC's three blobs arrived worker-to-worker —
    // none from the coordinator — and wA served at least those three
    // (it may also have served wB's job-1 fetches, which race wA's own
    // caching; the fallback covers that race).
    assert_eq!(c.blobs_from_peers, 3, "wC fetched all blobs from peers");
    assert_eq!(c.blobs_from_server, 0, "wC never fell back to the coordinator");
    assert!(
        a.blobs_served_to_peers >= 3,
        "wA served the blobs p2p (served: {})",
        a.blobs_served_to_peers
    );

    // Ledger: three jobs recorded.
    let ledger = coordinator::ledger::Ledger::load(&root.join("ledger.json")).unwrap();
    assert_eq!(ledger.history.len(), 3);
}

/// The same session over TLS: coordinator serves with a self-signed
/// certificate, daemons pin its fingerprint, and the full job flow —
/// auth, blob fetch, execution, signed result — runs encrypted.
#[test]
fn tls_network_session() {
    let demo_elf = std::path::Path::new("../../jobs/demo-hash-smoke/program.elf");
    if !demo_elf.exists() {
        eprintln!("SKIP: build the demo job first");
        return;
    }
    let root = temp_dir("p2pc-net-tls");
    let jobs_dir = root.join("jobs");
    let store_dir = root.join("store");
    std::fs::create_dir_all(&jobs_dir).unwrap();
    let store = contentstore::Store::open(&store_dir).unwrap();

    let desc = contentstore::publish(&PathBuf::from("../../jobs/demo-hash-smoke"), &store).unwrap();
    let cert_path = store_dir.join("coordinator-cert.der");

    let (bound_tx, bound_rx) = channel();
    let (job_tx, job_rx) = channel::<JobOutcome>();
    let cfg = ServeConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        jobs_dir: jobs_dir.clone(),
        store_dir: store_dir.clone(),
        per_job_deadline: std::time::Duration::from_secs(90),
        ledger: Some(root.join("ledger.json")),
        require_identity: true,
        round1_ids: None,
        pool: Some(2),
        round1_size: None,
        tls: None,
        bound_tx: Some(bound_tx),
        max_jobs: Some(1),
        job_tx: Some(job_tx),
    };

    // Generate the coordinator certificate up front so the workers can
    // pin it (in production, serve --tls generates it on first run).
    let (cert, key) = wire::tls::generate_self_signed().unwrap();
    std::fs::write(store_dir.join("coordinator-cert.der"), cert.as_ref()).unwrap();
    std::fs::write(store_dir.join("coordinator-key.der"), key.secret_der()).unwrap();
    let cert_der = std::fs::read(&cert_path).unwrap();

    std::thread::spawn(move || {
        let cfg = ServeConfig {
            tls: Some((cert.as_ref().to_vec(), key.secret_der().to_vec())),
            ..cfg
        };
        net::serve(cfg).expect("serve");
    });
    let bound = bound_rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap();

    queue_desc(&jobs_dir, "job1", &desc);

    let identities = root.join("identities");
    std::fs::create_dir_all(&identities).unwrap();
    let cert_copy = root.join("coordinator-cert.der");
    std::fs::copy(store_dir.join("coordinator-cert.der"), &cert_copy).unwrap();

    let mut handles = Vec::new();
    for id in ["wA", "wB"] {
        let server = bound.to_string();
        let identity = identities.join(format!("{id}.key"));
        let store_dir = root.join(format!("worker-store-{id}"));
        let cert_copy = cert_copy.clone();
        handles.push(std::thread::spawn(move || {
            let tls = Some(std::fs::read(&cert_copy).expect("read coordinator cert"));
            run_daemon(&DaemonConfig {
                server,
                worker_id: id.into(),
                identity_path: Some(identity),
                store_dir,
                listen_port: None,
                tls,
                corrupt: false,
                corrupt_byte: None,
            })
        }));
    }

    let job1 = wait_job(&job_rx);
    assert_eq!(job1.job_id, "demo-hash-smoke-0001");
    assert_eq!(job1.results.len(), 2);
    assert_eq!(job1.results[0].result_hash, job1.results[1].result_hash);
    let coordinator::Decision::Accept { hash, agreed, .. } = &job1.decision else {
        panic!("job 1 should accept");
    };
    assert_eq!(agreed.len(), 2, "both TLS workers agreed");

    // Digest sanity: matches the known demo-hash-smoke result.
    assert_eq!(hash, "ec48428c70dc764655f78d63389bd3be14275f129cb72c6fa5c007d8692c8662");

    for h in handles {
        h.join().unwrap().unwrap();
    }
    let _ = cert_der;
}

/// Reserve escalation over the wire: round 1 is named as an honest
/// worker plus a liar (round1_ids), so no majority forms; the honest
/// reserve is held back and the coordinator must escalate to it. The
/// escalated result joins round 1's honest vote for a 2/3 majority,
/// the job is accepted, and the liar's bond burns.
#[test]
fn reserve_escalation_beats_lying_worker() {
    // Regression guard: dispatch waits for full-pool authentication so
    // escalation reserves are populated (see DESIGN.md, RESOLVED entry).
    let demo_elf = std::path::Path::new("../../jobs/demo-hash-smoke/program.elf");
    if !demo_elf.exists() {
        eprintln!("SKIP: build the demo job first");
        return;
    }
    let root = temp_dir("p2pc-net-reserves");
    let jobs_dir = root.join("jobs");
    let store_dir = root.join("store");
    std::fs::create_dir_all(&jobs_dir).unwrap();
    let store = contentstore::Store::open(&store_dir).unwrap();
    let desc = contentstore::publish(&PathBuf::from("../../jobs/demo-hash-smoke"), &store).unwrap();

    let (bound_tx, bound_rx) = channel();
    let (job_tx, job_rx) = channel::<JobOutcome>();
    let cfg = ServeConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        jobs_dir: jobs_dir.clone(),
        store_dir: store_dir.clone(),
        per_job_deadline: std::time::Duration::from_secs(90),
        ledger: Some(root.join("ledger.json")),
        require_identity: true,
        pool: Some(3),
        round1_size: None,
        round1_ids: Some(vec!["wA".into(), "wB".into()]),
        tls: None,
        bound_tx: Some(bound_tx),
        max_jobs: Some(1),
        job_tx: Some(job_tx),
    };
    std::thread::spawn(move || net::serve(cfg).expect("serve"));
    let bound = bound_rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap();

    queue_desc(&jobs_dir, "job1", &desc);

    let identities = root.join("identities");
    std::fs::create_dir_all(&identities).unwrap();
    let mut handles = Vec::new();
    // Pool of 3, round 1 named [wA, wB]: wA honest, wB corrupts its
    // result, wC is the held-back honest reserve. One lie against one
    // honest vote leaves no majority, so the coordinator escalates to
    // wC, whose result joins wA's for the 2/3 accept.
    let spawns: Vec<(&str, bool, Option<u8>)> = vec![
        ("wA", false, None),
        ("wB", true, Some(5)),
        ("wC", false, None),
    ];
    for (id, corrupt, byte) in spawns {
        let server = bound.to_string();
        let identity = identities.join(format!("{id}.key"));
        let store_dir = root.join(format!("worker-store-{id}"));
        handles.push(std::thread::spawn(move || {
            run_daemon(&DaemonConfig {
                server,
                worker_id: id.into(),
                identity_path: Some(identity),
                store_dir,
                listen_port: None,
                tls: None,
                corrupt,
                corrupt_byte: byte,
            })
        }));
    }

    let job1 = wait_job(&job_rx);
    let coordinator::Decision::Accept { hash, agreed, .. } = &job1.decision else {
        panic!("escalation should end in accept, got {:?}", job1.decision);
    };
    assert_eq!(hash, "ec48428c70dc764655f78d63389bd3be14275f129cb72c6fa5c007d8692c8662");
    assert_eq!(agreed, &vec!["wA".to_string(), "wC".to_string()]);
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// A descriptor being written while the coordinator polls the watched
/// directory must not kill the server: the poll skips the unreadable
/// file for the grace window, and the job runs once the write
/// completes. Regression for the mid-write empty-file race that
/// crashed serve ("EOF while parsing a value at line 1 column 0").
#[test]
fn partial_descriptor_write_does_not_kill_server() {
    let smoke_elf = std::path::Path::new("../../jobs/demo-hash-smoke/program.elf");
    if !smoke_elf.exists() {
        eprintln!("SKIP: build the demo-hash-smoke job first");
        return;
    }
    let root = temp_dir("p2pc-net-partial-desc");
    let jobs_dir = root.join("jobs");
    let store_dir = root.join("store");
    std::fs::create_dir_all(&jobs_dir).unwrap();
    let store = contentstore::Store::open(&store_dir).unwrap();
    let desc = contentstore::publish(&PathBuf::from("../../jobs/demo-hash-smoke"), &store).unwrap();

    let (bound_tx, bound_rx) = channel();
    let (job_tx, job_rx) = channel::<JobOutcome>();
    let cfg = ServeConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        jobs_dir: jobs_dir.clone(),
        store_dir: store_dir.clone(),
        per_job_deadline: std::time::Duration::from_secs(90),
        ledger: None,
        require_identity: true,
        pool: Some(1),
        round1_size: None,
        round1_ids: None,
        tls: None,
        bound_tx: Some(bound_tx),
        max_jobs: Some(1),
        job_tx: Some(job_tx),
    };
    std::thread::spawn(move || net::serve(cfg).expect("serve"));
    let bound = bound_rx.recv_timeout(std::time::Duration::from_secs(15)).unwrap();

    // Simulate the mid-write window: an empty file sits where the
    // descriptor will land. The old scan treated this as fatal.
    std::fs::write(jobs_dir.join("job1.desc.json"), b"").unwrap();

    let identities = root.join("identities");
    std::fs::create_dir_all(&identities).unwrap();
    let server = bound.to_string();
    let identity = identities.join("wA.key");
    let store_dir = root.join("worker-store-wA");
    let worker = std::thread::spawn(move || {
        run_daemon(&DaemonConfig {
            server,
            worker_id: "wA".into(),
            identity_path: Some(identity),
            store_dir,
            listen_port: None,
            tls: None,
            corrupt: false,
            corrupt_byte: None,
        })
    });

    // Well inside the grace window: finish the write atomically.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    queue_desc(&jobs_dir, "job1", &desc);

    let job1 = wait_job(&job_rx);
    let coordinator::Decision::Accept { .. } = &job1.decision else {
        panic!("job should accept after the descriptor write completes");
    };
    worker.join().unwrap().unwrap();
}
