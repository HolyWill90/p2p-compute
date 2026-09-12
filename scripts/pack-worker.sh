#!/usr/bin/env bash
# Package the worker-only source tree for a second machine: a small
# tarball containing everything a peer needs to build the worker
# daemon (no RISC-V toolchain required — job ELFs arrive over the wire
# from the coordinator, hash-verified).
set -e
cd "$(dirname "$0")/.."

OUT="${1:-p2pc-worker.tar.gz}"
STAGE="$(mktemp -d)/p2pc-worker"
mkdir -p "$STAGE/crates"

# Pruned workspace: worker-side crates only.
cat > "$STAGE/Cargo.toml" <<'EOF'
[workspace]
resolver = "2"
members = [
    "crates/abi",
    "crates/rvcore",
    "crates/jobfmt",
    "crates/contentstore",
    "crates/wire",
    "crates/worker",
]

[workspace.package]
version = "0.1.0"
edition = "2021"

[workspace.dependencies]
abi = { path = "crates/abi" }
rvcore = { path = "crates/rvcore" }
jobfmt = { path = "crates/jobfmt" }
contentstore = { path = "crates/contentstore" }
wire = { path = "crates/wire" }
worker = { path = "crates/worker" }
blake3 = { version = "1", default-features = false }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
clap = { version = "4", features = ["derive"] }
ed25519-dalek = { version = "2", features = ["rand_core"] }
rand_core = { version = "0.6", features = ["getrandom"] }
EOF

cp -r crates/abi crates/rvcore crates/jobfmt crates/contentstore crates/wire crates/worker "$STAGE/crates/"
find "$STAGE" -name target -type d -exec rm -rf {} + 2>/dev/null || true

# One-command run script for the peer machine.
cat > "$STAGE/run-worker.sh" <<'EOF'
#!/usr/bin/env bash
# usage: ./run-worker.sh <coordinator-ip:port> <worker-id>
set -e
cd "$(dirname "$0")"
cargo build --release -p worker
./target/release/worker daemon \
    --server "${1:?coordinator address, e.g. 192.168.1.10:7777}" \
    --id "${2:-worker}" \
    --identity identity.key \
    --store-dir worker-store
EOF
chmod +x "$STAGE/run-worker.sh"

tar -czf "$OUT" -C "$(dirname "$STAGE")" p2pc-worker
echo "packaged: $OUT ($(du -h "$OUT" | cut -f1))"
