#!/usr/bin/env bash
# Runs INSIDE the container (mounted at /ws): installs the SP1
# toolchain, builds the guest, then executes + verifies it via the
# host. Exits 0 only on a fully verified receipt.
set -e
export PATH="$HOME/.sp1/bin:$PATH"

echo "== [0/6] installing protoc (sp1-sdk build dependency) =="
if ! command -v protoc >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq protobuf-compiler
else
  echo "protoc present, skipping"
fi

echo "== [1/6] installing sp1up =="
if [ ! -x "$HOME/.sp1/bin/sp1up" ]; then
  curl -L https://sp1.succinct.xyz | bash
else
  echo "sp1up already present, skipping"
fi

echo "== [2/6] installing SP1 toolchain (large download) =="
if ! "$HOME/.sp1/bin/cargo-prove" prove --version >/dev/null 2>&1; then
  sp1up
else
  echo "SP1 toolchain already installed, skipping"
fi

echo "== [3/6] aligning crate versions with the installed toolchain =="
# Authoritative source: the latest sp1-zkvm version published on
# crates.io (the toolchain probe output can contain download noise).
VERSION="$(cargo search sp1-zkvm --limit 1 --color never 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  VERSION="6.8.0"
fi
echo "detected SP1 version: $VERSION"
sed -i "s/sp1-zkvm = \"[^\"]*\"/sp1-zkvm = \"$VERSION\"/" /ws/sp1-guest/Cargo.toml
sed -i "s/sp1-sdk = \"[^\"]*\"/sp1-sdk = \"$VERSION\"/" /ws/sp1-host/Cargo.toml
sed -i "s/sp1-build = \"[^\"]*\"/sp1-build = \"$VERSION\"/" /ws/sp1-host/Cargo.toml
echo "manifest now: $(grep sp1-zkvm /ws/sp1-guest/Cargo.toml)"

echo "== [4/6] building guest =="
cd /ws/sp1-guest
$HOME/.sp1/bin/cargo-prove prove build
mkdir -p /ws/elf
GUEST_ELF="$(find target -name 'sp1-guest-fnv' -type f | head -1)"
echo "guest ELF: $GUEST_ELF"
cp "$GUEST_ELF" /ws/elf/sp1-guest-fnv

echo "== [5/6] executing + verifying via host =="
cd /ws/sp1-host
cargo run --release

echo "SP1-VALIDATION-COMPLETE"
