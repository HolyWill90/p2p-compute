//! The coordinator's persistent network session: accepts
//! Ed25519-authenticated worker connections indefinitely, watches a
//! jobs directory for descriptors, and processes each job over the
//! wire — dispatch as content-store blobs (with peer hints for the
//! p2p path), collect signed results, decide, update the ledger,
//! broadcast BetweenJobs, move to the next job.

use crate::{decide, slashing, verify_signature, Decision};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use jobfmt::WorkerResult;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use wire::{ClientToServer, ServerToClient};

#[derive(Clone)]
pub struct ServeConfig {
    pub bind: SocketAddr,
    /// Watched for new `*.desc.json` job descriptors. A descriptor
    /// filename `name@w1,w2.desc.json` targets those workers;
    /// otherwise the job goes to every authenticated worker.
    pub jobs_dir: PathBuf,
    pub store_dir: PathBuf,
    /// Deadline for each individual job.
    pub per_job_deadline: Duration,
    pub ledger: Option<PathBuf>,
    pub require_identity: bool,
    /// When set, an "all workers" job waits for this many
    /// authenticated workers before dispatching.
    pub pool: Option<usize>,
    pub bound_tx: Option<Sender<SocketAddr>>,
    /// Stop after this many jobs (None = run until killed).
    pub max_jobs: Option<usize>,
    /// Each finished job is sent here (for tests and monitors).
    pub job_tx: Option<Sender<JobOutcome>>,
    /// When set, worker connections run over TLS with this server
    /// certificate + key (DER).
    pub tls: Option<(Vec<u8>, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub struct JobOutcome {
    pub job_id: String,
    pub decision: Decision,
    pub results: Vec<WorkerResult>,
    pub bond_deltas: Vec<(String, i64)>,
}

pub struct ServeOutcome {
    pub jobs: Vec<JobOutcome>,
}

#[derive(Debug)]
enum Event {
    Hello {
        conn: usize,
        pubkey: String,
        worker_id: String,
        listen_port: Option<u16>,
    },
    NonceSig { conn: usize, sig: String },
    BlobRequest { conn: usize, id: String },
    Result { conn: usize, result: WorkerResult },
    Closed { conn: usize },
}

struct Conn {
    outbound: Sender<ServerToClient>,
    pubkey: Option<String>,
    nonce: Option<Vec<u8>>,
    worker_id: String,
    authed: bool,
    /// p2p blob server advertised by this worker, if any.
    peer_addr: Option<String>,
    /// The worker's IP, captured at accept time.
    peer_ip: String,
}

struct PendingJob {
    descriptor: contentstore::JobDescriptor,
    /// Worker ids targeted (None = all authenticated workers).
    targets: Option<Vec<String>>,
    path: PathBuf,
    dispatched: bool,
    dispatched_ids: Vec<String>,
    results: Vec<WorkerResult>,
    started: Instant,
}

pub fn serve(cfg: ServeConfig) -> Result<ServeOutcome, String> {
    let store = contentstore::Store::open(&cfg.store_dir).map_err(|e| format!("store: {e}"))?;
    let listener = TcpListener::bind(cfg.bind).map_err(|e| format!("bind: {e}"))?;
    let bound = listener.local_addr().map_err(|e| format!("local_addr: {e}"))?;
    println!("coordinator listening on {bound}");
    if let Some(tx) = &cfg.bound_tx {
        tx.send(bound).ok();
    }

    let (event_tx, event_rx) = channel::<Event>();
    let conns: Arc<Mutex<HashMap<usize, Conn>>> = Arc::new(Mutex::new(HashMap::new()));

    // Acceptor: each incoming connection gets a session thread that
    // owns the stream exclusively (polled receive + outbound queue) —
    // one thread per connection works for both plain TCP and TLS,
    // whose streams cannot be split for reader/writer threads.
    static NEXT_CONN: AtomicUsize = AtomicUsize::new(1);
    {
        let event_tx = event_tx.clone();
        let conns = conns.clone();
        let tls_cfg = cfg
            .tls
            .as_ref()
            .map(|(cert, key)| {
                Arc::new(wire::tls::server_config(cert, key).expect("tls server config"))
            });
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(tcp) = stream else { break };
                let id = NEXT_CONN.fetch_add(1, Ordering::SeqCst);
                let (outbound, outbound_rx) = channel::<ServerToClient>();
                let peer_ip = tcp
                    .peer_addr()
                    .map(|a| a.ip().to_string())
                    .unwrap_or_default();
                conns.lock().unwrap().insert(
                    id,
                    Conn {
                        outbound,
                        pubkey: None,
                        nonce: None,
                        worker_id: format!("w{id}"),
                        authed: false,
                        peer_addr: None,
                        peer_ip: peer_ip.clone(),
                    },
                );
                let tx = event_tx.clone();
                let conns2 = conns.clone();
                let tls_cfg = tls_cfg.clone();
                std::thread::spawn(move || {
                    let boxed: wire::BoxedStream = match &tls_cfg {
                        Some(server_cfg) => {
                            let conn = rustls::ServerConnection::new(server_cfg.clone())
                                .expect("tls connection");
                            let (mut conn, mut sock) = rustls::StreamOwned::new(conn, tcp).into_parts();
                            while conn.is_handshaking() {
                                if let Err(e) = conn.complete_io(&mut sock) {
                                    eprintln!("tls handshake failed for conn {id}: {e}");
                                    return;
                                }
                            }
                            let tls = rustls::StreamOwned::new(conn, sock);
                            // The polled receive NEEDS this timeout: it
                            // is what makes idle windows observable so
                            // the outbound queue gets pumped.
                            tls.sock
                                .set_read_timeout(Some(Duration::from_millis(100)))
                                .ok();
                            Box::new(tls)
                        }
                        None => {
                            tcp.set_read_timeout(Some(Duration::from_millis(100))).ok();
                            Box::new(tcp)
                        }
                    };
                    eprintln!("conn {id}: session started ({})", if tls_cfg.is_some() { "tls" } else { "plain" });
                    session_loop(id, boxed, outbound_rx, tx, conns2);
                });
            }
        });
    }

    let mut outcomes: Vec<JobOutcome> = Vec::new();
    let mut pending: Option<PendingJob> = None;
    let mut jobs_done = 0usize;

    loop {
        if let Some(max) = cfg.max_jobs {
            if jobs_done >= max {
                shutdown_all(&conns, "all queued jobs complete");
                return Ok(ServeOutcome { jobs: outcomes });
            }
        }

        // New job descriptors from the watched directory.
        if pending.is_none() {
            if let Some((descriptor, targets, path)) = scan_jobs_dir(&cfg.jobs_dir)? {
                println!(
                    "job queued: {} (target: {})",
                    descriptor.job_id,
                    targets
                        .as_ref()
                        .map(|t| t.join(","))
                        .unwrap_or_else(|| "all".into())
                );
                pending = Some(PendingJob {
                    descriptor,
                    targets,
                    path,
                    dispatched: false,
                    dispatched_ids: Vec::new(),
                    results: Vec::new(),
                    started: Instant::now(),
                });
            }
        }

        // Dispatch a queued job once its targets are all authenticated
        // (or immediately when targeting everyone).
        if let Some(job) = &mut pending {
            if !job.dispatched {
                let map = conns.lock().unwrap();
                let targets_ready = match &job.targets {
                    Some(ids) => ids.iter().all(|id| {
                        map.values().any(|c| c.authed && &c.worker_id == id)
                    }),
                    None => map
                        .values()
                        .filter(|c| c.authed)
                        .count()
                        >= cfg.pool.unwrap_or(1),
                };
                if targets_ready {
                    // Pass 1 (immutable): collect assignees and their
                    // peer hints. Pass 2 (mutable): send.
                    let mut assignments: Vec<(String, Vec<String>)> = Vec::new();
                    for c in map.values() {
                        let eligible = match &job.targets {
                            Some(ids) => ids.contains(&c.worker_id),
                            None => c.authed,
                        };
                        if eligible && c.authed {
                            let hints: Vec<String> = map
                                .values()
                                .filter(|p| {
                                    p.authed
                                        && p.peer_addr.is_some()
                                        && p.worker_id != c.worker_id
                                })
                                .filter_map(|p| p.peer_addr.clone())
                                .collect();
                            assignments.push((c.worker_id.clone(), hints));
                        }
                    }
                    drop(map);
                    let mut map = conns.lock().unwrap();
                    for (wid, hints) in &assignments {
                        if let Some(c) = map.values_mut().find(|c| c.worker_id == *wid) {
                            let _ = c.outbound.send(ServerToClient::JobAssignment {
                                descriptor: job.descriptor.clone(),
                                peer_hints: hints.clone(),
                            });
                            job.dispatched_ids.push(wid.clone());
                        }
                    }
                    job.dispatched = true;
                    println!(
                        "job {} dispatched to [{}]",
                        job.descriptor.job_id,
                        job.dispatched_ids.join(", ")
                    );
                }
            }
        }

        // Per-job deadline and completion.
        let mut job_finished: Option<PendingJob> = None;
        if let Some(job) = &mut pending {
            if job.dispatched {
                let all_in = job.dispatched_ids.iter().all(|id| {
                    job.results.iter().any(|r| &r.worker_id == id)
                });
                if all_in || job.started.elapsed() > cfg.per_job_deadline {
                    job_finished = Some(PendingJob {
                        descriptor: job.descriptor.clone(),
                        targets: job.targets.clone(),
                        path: job.path.clone(),
                        dispatched: true,
                        dispatched_ids: job.dispatched_ids.clone(),
                        results: std::mem::take(&mut job.results),
                        started: job.started,
                    });
                }
            }
        }
        if let Some(job) = job_finished {
            let job_id = job.descriptor.job_id.clone();
            let decision = match decide(&job.results) {
                Decision::Escalate => Decision::Reject {
                    reason: "no majority".into(),
                },
                other => other,
            };
            let deltas = slashing(&decision, &job.results);
            finish_ledger(&cfg, &job_id, &decision, &deltas);
            let outcome = JobOutcome {
                job_id: job_id.clone(),
                decision: decision.clone(),
                results: job.results,
                bond_deltas: deltas,
            };
            if let Some(tx) = &cfg.job_tx {
                tx.send(outcome.clone()).ok();
            }
            outcomes.push(outcome);
            jobs_done += 1;
            let mut done = job.path.clone().into_os_string();
            done.push(".done");
            std::fs::rename(&job.path, done).ok();
            broadcast_between_jobs(&conns);
            pending = None;
            continue;
        }

        // Events (bounded wait so housekeeping keeps running).
        let event = match event_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(e) => e,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err("event channel closed".into())
            }
        };

        match event {
            Event::Hello { conn, pubkey, worker_id, listen_port } => {
                let nonce: [u8; 32] = rand_nonce();
                let nonce_hex = hex(&nonce);
                let mut map = conns.lock().unwrap();
                if let Some(c) = map.get_mut(&conn) {
                    c.pubkey = if pubkey.is_empty() { None } else { Some(pubkey) };
                    if !worker_id.is_empty() {
                        c.worker_id = worker_id;
                    }
                    c.nonce = Some(nonce.to_vec());
                    if let Some(port) = listen_port {
                        c.peer_addr = Some(format!("{}:{port}", c.peer_ip));
                    }
                    let _ = c.outbound.send(ServerToClient::Nonce { hex: nonce_hex });
                }
            }
            Event::NonceSig { conn, sig } => {
                let mut map = conns.lock().unwrap();
                let Some(c) = map.get_mut(&conn) else { continue };
                let auth_ok = match (&c.pubkey, &c.nonce) {
                    (Some(pk), Some(nonce)) => verify_nonce(pk, nonce, &sig).is_ok(),
                    (None, _) => !cfg.require_identity,
                    _ => false,
                };
                if auth_ok {
                    c.authed = true;
                    let wid = c.worker_id.clone();
                    let _ = c.outbound.send(ServerToClient::AuthOk { worker_id: wid.clone() });
                    println!(
                        "worker authenticated: {wid}{} (pool {}/{})",
                        c.peer_addr.as_ref().map(|_| " [p2p]").unwrap_or(""),
                        map.values().filter(|c| c.authed).count(),
                        "open"
                    );
                } else {
                    let _ = c.outbound.send(ServerToClient::AuthFailed {
                        reason: "nonce signature invalid".into(),
                    });
                    let _ = c
                        .outbound
                        .send(ServerToClient::ShutDown { reason: "auth failed".into() });
                }
            }
            Event::BlobRequest { conn, id } => {
                let mut map = conns.lock().unwrap();
                let wid = map.get(&conn).map(|c| c.worker_id.clone()).unwrap_or_default();
                if let Some(c) = map.get_mut(&conn) {
                    let data = contentstore::ContentId::from_hex(&id)
                        .ok()
                        .and_then(|cid| store.get(&cid).ok());
                    println!(
                        "blob request: {} asks {} -> {}",
                        wid,
                        &id[..12.min(id.len())],
                        if data.is_some() { "FOUND" } else { "NOT FOUND" }
                    );
                    let _ = c.outbound.send(ServerToClient::Blob {
                        hex: data.map(|d| hex(&d)),
                    });
                }
            }
            Event::Result { conn, result } => {
                let map = conns.lock().unwrap();
                let has_identity = map.get(&conn).map(|c| c.pubkey.is_some()).unwrap_or(false);
                drop(map);
                let mut result = result;
                if has_identity {
                    if let Err(e) = verify_signature(&result) {
                        println!("SIGNATURE FAILURE from conn {conn}: {e}");
                        result.status = "malformed".into();
                    }
                }
                if let Some(job) = &mut pending {
                    if result.job_id == job.descriptor.job_id {
                        job.results.push(result);
                    }
                }
            }
            Event::Closed { conn } => {
                let wid = conns.lock().unwrap().get(&conn).map(|c| c.worker_id.clone());
                println!(
                    "worker disconnected: {} (conn {conn})",
                    wid.as_deref().unwrap_or("unknown")
                );
                conns.lock().unwrap().remove(&conn);
            }
        }
    }
}

/// Scan the jobs directory for the first unprocessed descriptor.
/// Returns (descriptor, targets, path) and marks the file in use by
/// renaming to `.dispatching` — crash-safe: a renamed file is
/// recovered by the operator, not silently re-run.
fn scan_jobs_dir(
    jobs_dir: &std::path::Path,
) -> Result<Option<(contentstore::JobDescriptor, Option<Vec<String>>, PathBuf)>, String> {
    for entry in std::fs::read_dir(jobs_dir).map_err(|e| format!("jobs dir: {e}"))?.flatten() {
        let path = entry.path();
        let name = path.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
        if name.ends_with(".desc.json") {
            let bytes = std::fs::read(&path).map_err(|e| format!("jobs dir: {e}"))?;
            let descriptor: contentstore::JobDescriptor =
                serde_json::from_slice(&bytes).map_err(|e| format!("descriptor {name}: {e}"))?;
            let stem = name.trim_end_matches(".desc.json");
            let targets: Option<Vec<String>> = stem.split_once('@').map(|(_, ids)| {
                ids.split(',').map(|x| x.trim().to_string()).collect()
            });
            // Mark in use: rename to .dispatching so a crash cannot
            // double-run a job.
            let mut dispatching = path.clone().into_os_string();
            dispatching.push(".dispatching");
            std::fs::rename(&path, &dispatching).map_err(|e| format!("jobs dir: {e}"))?;
            return Ok(Some((descriptor, targets, PathBuf::from(dispatching))));
        }
    }
    Ok(None)
}

fn finish_ledger(
    cfg: &ServeConfig,
    job_id: &str,
    decision: &Decision,
    deltas: &[(String, i64)],
) {
    println!("decision: {decision:?}");
    if let Some(path) = &cfg.ledger {
        let mut led = crate::ledger::Ledger::load(path).unwrap_or_else(|e| {
            println!("ledger load failed ({e}); starting empty");
            Default::default()
        });
        led.apply(job_id, "network-run", deltas);
        if let Err(e) = led.save(path) {
            println!("ledger save failed: {e}");
        }
    }
}

fn broadcast_between_jobs(conns: &Mutex<HashMap<usize, Conn>>) {
    for c in conns.lock().unwrap().values() {
        let _ = c.outbound.send(ServerToClient::BetweenJobs);
    }
}

fn shutdown_all(conns: &Mutex<HashMap<usize, Conn>>, reason: &str) {
    for c in conns.lock().unwrap().values() {
        let _ = c.outbound.send(ServerToClient::ShutDown { reason: reason.into() });
    }
}

fn verify_nonce(pubkey_hex: &str, nonce_hex: &[u8], sig_hex: &str) -> Result<(), String> {
    let decode = |s: &str, n: usize| -> Result<Vec<u8>, String> {
        (0..n)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string()))
            .collect()
    };
    let pk = VerifyingKey::from_bytes(&decode(pubkey_hex, 32)?.try_into().unwrap())
        .map_err(|e| format!("{e}"))?;
    let sig = Signature::from_bytes(&decode(sig_hex, 64)?.try_into().unwrap());
    pk.verify(nonce_hex, &sig).map_err(|e| format!("{e}"))
}

fn rand_nonce() -> [u8; 32] {
    use rand_core::RngCore;
    let mut n = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut n);
    n
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn session_loop(
    conn: usize,
    mut stream: wire::BoxedStream,
    outbound_rx: Receiver<ServerToClient>,
    tx: Sender<Event>,
    conns: Arc<Mutex<HashMap<usize, Conn>>>,
) {
    let peer_ip = conns
        .lock()
        .unwrap()
        .get(&conn)
        .map(|c| c.peer_ip.clone())
        .unwrap_or_default();
    eprintln!("conn {conn}: session loop running");
    loop {
        let frame = wire::receive_polled::<ClientToServer>(&mut stream, Duration::from_millis(100));
        if frame.is_err() {
            eprintln!("conn {conn}: receive error: {:?}", frame.as_ref().err().unwrap());
        }
        match frame {
            Ok(Some(ClientToServer::Hello { pubkey_hex, worker_id, listen_port })) => {
                eprintln!("conn {conn}: Hello received");
                tx.send(Event::Hello { conn, pubkey: pubkey_hex, worker_id, listen_port })
                    .ok();
            }
            Ok(Some(ClientToServer::NonceSignature { sig_hex })) => {
                tx.send(Event::NonceSig { conn, sig: sig_hex }).ok();
            }
            Ok(Some(ClientToServer::BlobRequest { id_hex })) => {
                tx.send(Event::BlobRequest { conn, id: id_hex }).ok();
            }
            Ok(Some(ClientToServer::JobResult { result })) => {
                tx.send(Event::Result { conn, result }).ok();
            }
            Ok(None) => {
                // Idle window: push anything the main loop queued.
                while let Ok(msg) = outbound_rx.try_recv() {
                    if wire::send(&mut stream, &msg).is_err() {
                        conns.lock().unwrap().remove(&conn);
                        tx.send(Event::Closed { conn }).ok();
                        return;
                    }
                }
            }
            Err(e) => {
                let wid = conns
                    .lock()
                    .unwrap()
                    .get(&conn)
                    .map(|c| c.worker_id.clone())
                    .unwrap_or_else(|| format!("conn{conn}"));
                if matches!(e, wire::WireError::ConnectionClosed) {
                    println!("worker {wid}: connection closed by peer");
                } else {
                    // Non-close errors are the diagnostic trail for the
                    // intermittent between-jobs drop.
                    eprintln!("worker {wid}: reader error: {e}");
                }
                conns.lock().unwrap().remove(&conn);
                tx.send(Event::Closed { conn }).ok();
                break;
            }
        }
    }
}
