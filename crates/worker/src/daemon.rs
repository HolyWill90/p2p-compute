//! The worker daemon: connect to a coordinator, authenticate by
//! signing a nonce, then serve jobs indefinitely — fetch the job's
//! blobs from peers first (the p2p path), coordinator as fallback;
//! every byte is content-addressed and verified on arrival. Execute
//! in the deterministic emulator, sign the result, submit. The
//! session persists across many jobs; between jobs the daemon idles
//! on the wire, optionally serving blobs to peers.

use ed25519_dalek::{Signer, SigningKey};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use wire::{ClientToServer, PeerToPeer, ServerToClient};

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub server: String,
    pub worker_id: String,
    pub identity_path: Option<PathBuf>,
    /// Local blob cache (content-addressed; blobs dedup across jobs).
    pub store_dir: PathBuf,
    /// When set, the daemon serves blobs to peers on this port
    /// (port 0 = pick a free one; the real port is reported to the
    /// coordinator in Hello).
    pub listen_port: Option<u16>,
    /// Test hook: corrupt the result like a lying worker would.
    pub corrupt: bool,
    /// With `corrupt`: the hex digit the last hash character becomes,
    /// so two lying workers can fabricate DIFFERENT wrong results.
    pub corrupt_byte: Option<u8>,
}

/// Counters returned when the session ends — the evidence for which
/// fetch path actually moved the bytes.
#[derive(Debug, Default, Clone)]
pub struct DaemonStats {
    pub jobs_done: usize,
    pub blobs_from_peers: usize,
    pub blobs_from_server: usize,
    pub blobs_served_to_peers: usize,
}

#[derive(Default)]
struct Counters {
    jobs: AtomicUsize,
    from_peers: AtomicUsize,
    from_server: AtomicUsize,
    served: AtomicUsize,
}

fn load_or_create_identity(path: &Path) -> SigningKey {
    if let Ok(seed) = std::fs::read(path) {
        if seed.len() == 32 {
            let arr: [u8; 32] = seed.try_into().unwrap();
            return SigningKey::from_bytes(&arr);
        }
    }
    let mut seed = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut seed);
    std::fs::write(path, &seed).expect("write identity file");
    SigningKey::from_bytes(&seed)
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn set_last(s: &mut String, c: char) {
    let bytes = unsafe { s.as_bytes_mut() };
    let n = bytes.len();
    bytes[n - 1] = c as u8;
}

/// Serve blobs to peers until the process ends. Every blob handed out
/// is counted — the p2p exchange is measured, not assumed.
fn spawn_peer_server(listener: TcpListener, store: Arc<contentstore::Store>, counters: Arc<Counters>) {
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let store = store.clone();
            let counters = counters.clone();
            std::thread::spawn(move || {
                let Ok(PeerToPeer::PeerBlobRequest { id_hex }) =
                    wire::receive::<PeerToPeer>(&mut stream)
                else {
                    return;
                };
                let data = contentstore::ContentId::from_hex(&id_hex)
                    .ok()
                    .and_then(|cid| store.get(&cid).ok());
                if data.is_some() {
                    counters.served.fetch_add(1, Ordering::SeqCst);
                }
                let _ = wire::send(
                    &mut stream,
                    &PeerToPeer::PeerBlob { hex: data.as_ref().map(|d| hex(d)) },
                );
            });
        }
    });
}

/// Fetch one blob: peers first (in order), then the coordinator.
/// Every byte received is hash-verified against the requested id
/// before being stored — no trust in any serving peer.
fn fetch_blob(
    stream: &mut TcpStream,
    id_hex: &str,
    peer_hints: &[String],
    store: &contentstore::Store,
    counters: &Counters,
) -> Result<(), String> {
    let id = contentstore::ContentId::from_hex(id_hex)?;
    if store.has(&id)? {
        return Ok(()); // already cached from an earlier job
    }

    for peer in peer_hints {
        let Ok(mut peer_stream) = TcpStream::connect(peer) else { continue };
        peer_stream
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .ok();
        if wire::send(&mut peer_stream, &PeerToPeer::PeerBlobRequest { id_hex: id_hex.to_string() })
            .is_err()
        {
            continue;
        }
        if let Ok(PeerToPeer::PeerBlob { hex: Some(hex) }) =
            wire::receive::<PeerToPeer>(&mut peer_stream)
        {
            let bytes = hex_decode(&hex).ok_or("peer blob: bad hex")?;
            if contentstore::ContentId::from_data(&bytes) != id {
                return Err("peer blob: content does not match requested hash".into());
            }
            store.put(&bytes).map_err(|e| format!("store: {e}"))?;
            counters.from_peers.fetch_add(1, Ordering::SeqCst);
            println!("[p2p] fetched blob {} from peer {peer}", &id_hex[..12]);
            return Ok(());
        }
    }

    // Coordinator fallback.
    wire::send(stream, &ClientToServer::BlobRequest { id_hex: id_hex.to_string() })
        .map_err(|e| e.to_string())?;
    match wire::receive::<ServerToClient>(stream).map_err(|e| e.to_string())? {
        ServerToClient::Blob { hex: Some(hex) } => {
            let bytes = hex_decode(&hex).ok_or("blob: bad hex")?;
            if contentstore::ContentId::from_data(&bytes) != id {
                return Err("blob: content does not match requested hash".into());
            }
            store.put(&bytes).map_err(|e| format!("store: {e}"))?;
            counters.from_server.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        ServerToClient::Blob { hex: None } => Err(format!("blob {id_hex} not found on coordinator")),
        other => Err(format!("expected Blob, got {other:?}")),
    }
}

/// Run the daemon until the server shuts the session down.
pub fn run_daemon(cfg: &DaemonConfig) -> Result<DaemonStats, String> {
    let counters = Arc::new(Counters::default());

    // Optional peer blob server: bound before Hello so the real port
    // can be reported to the coordinator.
    let mut listen_port = cfg.listen_port;
    let peer_server = match cfg.listen_port {
        Some(port) => {
            let listener =
                TcpListener::bind(("0.0.0.0", port)).map_err(|e| format!("peer listen: {e}"))?;
            let actual = listener.local_addr().map_err(|e| e.to_string())?.port();
            listen_port = Some(actual);
            let store =
                Arc::new(contentstore::Store::open(&cfg.store_dir).map_err(|e| e.to_string())?);
            spawn_peer_server(listener, store, counters.clone());
            Some(actual)
        }
        None => None,
    };

    let stream = TcpStream::connect(&cfg.server).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(3600)))
        .ok();
    let mut stream = stream;

    let signing_key = cfg.identity_path.as_ref().map(|p| load_or_create_identity(p));

    // 1. Hello + nonce challenge-response (proves key possession).
    let pubkey_hex = signing_key.as_ref().map(|k| hex(&k.verifying_key().to_bytes()));
    wire::send(
        &mut stream,
        &ClientToServer::Hello {
            pubkey_hex: pubkey_hex.clone().unwrap_or_default(),
            worker_id: cfg.worker_id.clone(),
            listen_port: peer_server,
        },
    )
    .map_err(|e| e.to_string())?;
    let nonce = match wire::receive::<ServerToClient>(&mut stream).map_err(|e| e.to_string())? {
        ServerToClient::Nonce { hex } => hex,
        ServerToClient::AuthFailed { reason } => return Err(format!("auth failed: {reason}")),
        other => return Err(format!("expected Nonce, got {other:?}")),
    };
    if let Some(key) = &signing_key {
        let nonce_bytes = hex_decode(&nonce).ok_or("nonce: bad hex")?;
        wire::send(
            &mut stream,
            &ClientToServer::NonceSignature {
                sig_hex: hex(&key.sign(&nonce_bytes).to_bytes()),
            },
        )
        .map_err(|e| e.to_string())?;
    }

    // 2. Job loop — the session persists across many jobs.
    let store = contentstore::Store::open(&cfg.store_dir).map_err(|e| e.to_string())?;
    let mut submitted = false;
    loop {
        let received = wire::receive::<ServerToClient>(&mut stream);
        if submitted && matches!(received, Err(wire::WireError::ConnectionClosed)) {
            // The server closed right after taking our result — the
            // decision was reached without a formal goodbye.
            println!("[{}] session over: decision reached", cfg.worker_id);
            return Ok(DaemonStats {
                jobs_done: counters.jobs.load(Ordering::SeqCst),
                blobs_from_peers: counters.from_peers.load(Ordering::SeqCst),
                blobs_from_server: counters.from_server.load(Ordering::SeqCst),
                blobs_served_to_peers: counters.served.load(Ordering::SeqCst),
            });
        }
        let message = received.map_err(|e| e.to_string())?;
        match message {
            ServerToClient::AuthOk { worker_id } => {
                println!("[{worker_id}] authenticated, waiting for jobs");
            }
            ServerToClient::BetweenJobs => {
                println!("[{}] between jobs — idle", cfg.worker_id);
            }
            ServerToClient::ShutDown { reason } => {
                println!("[{}] session over: {reason}", cfg.worker_id);
                return Ok(DaemonStats {
                    jobs_done: counters.jobs.load(Ordering::SeqCst),
                    blobs_from_peers: counters.from_peers.load(Ordering::SeqCst),
                    blobs_from_server: counters.from_server.load(Ordering::SeqCst),
                    blobs_served_to_peers: counters.served.load(Ordering::SeqCst),
                });
            }
            ServerToClient::JobAssignment { descriptor, peer_hints } => {
                println!(
                    "[{}] job {} assigned — blobs: peers {:?} then coordinator",
                    cfg.worker_id, descriptor.job_id, peer_hints
                );

                for id in [&descriptor.manifest, &descriptor.elf, &descriptor.input] {
                    fetch_blob(&mut stream, id, &peer_hints, &store, &counters)?;
                }

                // Materialize from the local (hash-verified) store.
                let job_dir =
                    std::env::temp_dir().join(format!("p2pc-worker-{}", descriptor.job_id));
                std::fs::remove_dir_all(&job_dir).ok();
                contentstore::materialize(&descriptor, &store, &job_dir)
                    .map_err(|e| format!("materialize: {e}"))?;
                let job = jobfmt::load_dir(&job_dir).map_err(|e| format!("load: {e}"))?;

                // Execute in the pinned deterministic emulator.
                let image = rvcore::elf::parse(&job.elf).map_err(|e| format!("elf: {e}"))?;
                let mut mem = rvcore::Mem::new();
                rvcore::elf::load(&mut mem, &image).map_err(|e| format!("elf: {e}"))?;
                let outcome = rvcore::interp::run(
                    &mut mem,
                    image.entry,
                    &job.input,
                    &rvcore::Config {
                        chunk_size: job.manifest.chunk_size,
                        max_instructions: job.manifest.max_instructions,
                        ..Default::default()
                    },
                );

                let status = match &outcome.status {
                    rvcore::ExitStatus::Halted => "halted",
                    rvcore::ExitStatus::InstructionLimit => "instruction_limit",
                    rvcore::ExitStatus::Trapped(_) => "trap",
                };
                let trap = match outcome.status {
                    rvcore::ExitStatus::Trapped(t) => Some(format!("{t:?}")),
                    _ => None,
                };
                let mut chunk_hashes: Vec<String> =
                    outcome.chunk_hashes.iter().map(|h| hex(h)).collect();
                let mut result_hash =
                    chunk_hashes.last().cloned().unwrap_or_else(|| hex(&rvcore::GENESIS));
                if cfg.corrupt && !chunk_hashes.is_empty() {
                    let replacement = match cfg.corrupt_byte {
                        Some(b) => format!("{:x}", b & 0xF).pop().unwrap(),
                        None => '1',
                    };
                    set_last(&mut result_hash, replacement);
                    set_last(chunk_hashes.last_mut().unwrap(), replacement);
                }

                let (pubkey_hex, sig_hex) = match &signing_key {
                    Some(key) => {
                        let msg = hex_decode(&result_hash).ok_or("hash: bad hex")?;
                        let sig = key.sign(&msg);
                        (Some(hex(&key.verifying_key().to_bytes())), Some(hex(&sig.to_bytes())))
                    }
                    None => (None, None),
                };

                let result = jobfmt::WorkerResult {
                    worker_id: cfg.worker_id.clone(),
                    job_id: job.manifest.id,
                    status: status.to_string(),
                    instructions: outcome.instructions,
                    result_hash,
                    chunk_hashes,
                    output_hex: outcome.output.as_ref().map(|o| hex(o)),
                    trap,
                    pubkey_hex,
                    sig_hex,
                };
                counters.jobs.fetch_add(1, Ordering::SeqCst);
                println!(
                    "[{}] submitting result: {} after {} instructions",
                    cfg.worker_id,
                    &result.result_hash[..16.min(result.result_hash.len())],
                    result.instructions
                );
                wire::send(&mut stream, &ClientToServer::JobResult { result })
                    .map_err(|e| e.to_string())?;
                submitted = true;
            }
            other => return Err(format!("unexpected server message: {other:?}")),
        }
    }
}
