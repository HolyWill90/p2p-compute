//! The full-network integration test over REAL TCP sockets, three
//! jobs in one persistent session:
//!   job 1: demo-hash → all workers (quorum accept)
//!   job 2: agent-task → all workers (a second, different job over
//!          the same session — blobs fetched from the coordinator)
//!   job 3: demo-hash again → targeted at a NEW worker wC with an
//!          empty store, whose only peer hint is wA. The blobs must
//!          arrive worker-to-worker: wA's served counter goes up,
//!          wC's from-server counter stays zero.

use coordinator::net::{self, JobOutcome, ServeConfig};
use std::path::PathBuf;
use std::sync::mpsc::channel;
use worker::daemon::{run_daemon, DaemonConfig};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(name);
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn wait_job(rx: &std::sync::mpsc::Receiver<JobOutcome>) -> JobOutcome {
    rx.recv_timeout(std::time::Duration::from_secs(110))
        .expect("job finished in time")
}

#[test]
fn multi_job_session_with_p2p_blob_exchange() {
    let demo_elf = std::path::Path::new("../../jobs/demo-hash/program.elf");
    let agent_elf = std::path::Path::new("../../jobs/agent-task/program.elf");
    if !demo_elf.exists() || !agent_elf.exists() {
        eprintln!("SKIP: build the demo-hash and agent-task jobs first");
        return;
    }
    let root = temp_dir("p2pc-net-multi");
    let jobs_dir = root.join("jobs");
    let store_dir = root.join("store");
    std::fs::create_dir_all(&jobs_dir).unwrap();
    let store = contentstore::Store::open(&store_dir).unwrap();

    // Publish the two distinct jobs into the server's store.
    let desc1 = contentstore::publish(&PathBuf::from("../../jobs/demo-hash"), &store).unwrap();
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
        pool: Some(2),
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
    std::fs::write(
        jobs_dir.join("job1.desc.json"),
        serde_json::to_vec(&desc1).unwrap(),
    )
    .unwrap();

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
                corrupt: false,
                corrupt_byte: None,
            })
        }));
    }

    // --- job 1: demo-hash, both workers, quorum accept ---
    let job1 = wait_job(&job_rx);
    assert_eq!(job1.job_id, "demo-hash-0001");
    assert_eq!(job1.results.len(), 2, "both workers ran job 1");
    assert_eq!(job1.results[0].result_hash, job1.results[1].result_hash);
    let demo_digest = job1.results[0].result_hash.clone();
    let coordinator::Decision::Accept { agreed, .. } = &job1.decision else {
        panic!("job 1 should accept");
    };
    assert_eq!(agreed.len(), 2);

    // --- job 2: agent-task, same session, new blobs from the coordinator ---
    std::fs::write(
        jobs_dir.join("job2.desc.json"),
        serde_json::to_vec(&desc2).unwrap(),
    )
    .unwrap();
    let job2 = wait_job(&job_rx);
    let coordinator::Decision::Accept { .. } = &job2.decision else {
        panic!("job 2 should accept");
    };
    assert_eq!(job2.results.len(), 2);

    // --- job 3: demo-hash AGAIN, targeted at a fresh worker wC whose
    // only blob source is worker A (p2p exchange) ---
    let desc3 = contentstore::publish(&PathBuf::from("../../jobs/demo-hash"), &store).unwrap();
    std::fs::write(
        jobs_dir.join("job3@wC.desc.json"),
        serde_json::to_vec(&desc3).unwrap(),
    )
    .unwrap();
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
                corrupt: false,
                corrupt_byte: None,
            })
        }));
    }
    let job3 = wait_job(&job_rx);
    assert_eq!(job3.job_id, "demo-hash-0001");
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
