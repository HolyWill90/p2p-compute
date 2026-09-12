//! The wire protocol: length-prefixed JSON frames over a byte stream.
//!
//! Deliberately boring: the verification surface of this project is
//! the signed result JSON and the chunk-hash chains, so the transport
//! only has to move those reliably between peers. TLS and fancier
//! framings layer on top later; nothing here changes.

use std::io::{Read, Write};
use std::time::Duration;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub mod tls;

/// Any byte stream the wire protocol can run over: plain TCP or TLS.
pub trait ByteStream: Read + Write + Send {}
impl<T: Read + Write + Send> ByteStream for T {}

/// A boxed stream for sessions that may run over either transport.
pub type BoxedStream = Box<dyn ByteStream>;

/// Hard cap on a single frame's payload — a peer claiming a 4 GB
/// message is either broken or hostile.
pub const MAX_FRAME: u32 = 64 << 20;

#[derive(Debug)]
pub enum WireError {
    Io(std::io::Error),
    Malformed(String),
    ConnectionClosed,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Io(e) => write!(f, "wire i/o: {e}"),
            WireError::Malformed(s) => write!(f, "wire: {s}"),
            WireError::ConnectionClosed => write!(f, "wire: connection closed"),
        }
    }
}

pub fn send<T: Serialize>(stream: &mut impl Write, msg: &T) -> Result<(), WireError> {
    let json = serde_json::to_vec(msg).map_err(|e| WireError::Malformed(e.to_string()))?;
    if json.len() as u64 > MAX_FRAME as u64 {
        return Err(WireError::Malformed(format!(
            "frame too large: {} bytes",
            json.len()
        )));
    }
    stream
        .write_all(&(json.len() as u32).to_le_bytes())
        .map_err(WireError::Io)?;
    stream.write_all(&json).map_err(WireError::Io)?;
    stream.flush().map_err(WireError::Io)?;
    Ok(())
}

/// Polled receive: waits up to `idle` for a frame to START, then
/// reads the rest of the frame to completion (tolerating transient
/// WouldBlocks). Returns `Ok(None)` when idle — no frame started —
/// so the caller can interleave other work (outbound sends, polling)
/// on the same stream. Required for TLS, whose streams cannot be
/// cloned for reader/writer threads.
pub fn receive_polled<T: DeserializeOwned>(
    stream: &mut impl Read,
    idle: Duration,
) -> Result<Option<T>, WireError> {
    let started_at = std::time::Instant::now();
    let mut prefix = [0u8; 4];
    let mut got = 0usize;
    while got < 4 {
        match stream.read(&mut prefix[got..]) {
            Ok(0) => return Err(WireError::ConnectionClosed),
            Ok(n) => got += n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if got == 0 && started_at.elapsed() >= idle {
                    return Ok(None); // idle: nothing pending
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(WireError::Io(e)),
        }
    }
    read_frame_body::<T>(stream, u32::from_le_bytes(prefix)).map(Some)
}

fn read_frame_body<T: DeserializeOwned>(
    stream: &mut impl Read,
    len: u32,
) -> Result<T, WireError> {
    if len > MAX_FRAME {
        return Err(WireError::Malformed(format!(
            "peer announced a {len}-byte frame; limit is {MAX_FRAME}"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    let mut got = 0usize;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while got < buf.len() {
        match stream.read(&mut buf[got..]) {
            Ok(0) => return Err(WireError::ConnectionClosed),
            Ok(n) => got += n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if std::time::Instant::now() > deadline {
                    return Err(WireError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "frame body stalled",
                    )));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(WireError::Io(e)),
        }
    }
    serde_json::from_slice(&buf).map_err(|e| WireError::Malformed(e.to_string()))
}

pub fn receive<T: DeserializeOwned>(stream: &mut impl Read) -> Result<T, WireError> {
    let mut len_buf = [0u8; 4];
    match stream.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(WireError::ConnectionClosed)
        }
        Err(e) => return Err(WireError::Io(e)),
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(WireError::Malformed(format!(
            "peer announced a {len}-byte frame; limit is {MAX_FRAME}"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).map_err(WireError::Io)?;
    serde_json::from_slice(&buf).map_err(|e| WireError::Malformed(e.to_string()))
}

/// Messages sent by a worker (client) to the coordinator.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ClientToServer {
    /// Introduce the worker's Ed25519 public key; the server replies
    /// with Nonce to prove key possession.
    Hello {
        pubkey_hex: String,
        worker_id: String,
        /// When set, the daemon serves blobs to peers on this port.
        listen_port: Option<u16>,
    },
    /// Signature over the nonce bytes the server issued.
    NonceSignature { sig_hex: String },
    /// Fetch a content-store blob by hash (the torrent layer online).
    BlobRequest { id_hex: String },
    /// A completed, signed execution result.
    JobResult { result: jobfmt::WorkerResult },
}

/// Messages sent by the coordinator to a worker.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ServerToClient {
    /// Random bytes: sign these to prove possession of the Hello key.
    Nonce { hex: String },
    /// Identity verified; the server assigned this worker id.
    AuthOk { worker_id: String },
    AuthFailed { reason: String },
    /// Execute this job. The worker materializes the descriptor's
    /// blobs (peers first, coordinator as fallback) and reads the
    /// manifest for execution parameters.
    JobAssignment {
        descriptor: content_descriptor::JobDescriptor,
        /// Connected peers that may already hold the blobs — the
        /// p2p fetch path ahead of the coordinator fallback.
        peer_hints: Vec<String>,
    },
    /// Response to a BlobRequest; None = unknown hash.
    Blob { hex: Option<String> },
    /// A job batch ended; stay connected, more jobs may come.
    BetweenJobs,
    /// Final message: the session is over.
    ShutDown { reason: String },
}

/// Direct worker-to-worker blob exchange (the p2p path). A daemon
/// with `listen_port` set runs a tiny server speaking this protocol.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PeerToPeer {
    PeerBlobRequest { id_hex: String },
    PeerBlob { hex: Option<String> },
}

/// The descriptor lives with the content store conceptually, but the
/// wire needs it too — re-export to keep one definition.
pub use content_descriptor::JobDescriptor;

/// Placeholder module trick avoided: JobDescriptor is defined in
/// contentstore; wire depends on it for the protocol.
pub mod content_descriptor {
    pub use contentstore::JobDescriptor;
}
