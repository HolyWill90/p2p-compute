#!/usr/bin/env bash
# Runs INSIDE the container: builds the official riscv-tests user-level
# suites (rv64ui, rv64um, rv64uc) into ELFs for the emulator.
set -e
apt-get update -qq
apt-get install -y -qq git gcc-riscv64-unknown-elf >/dev/null 2>&1
[ -d /opt/rt/.git ] || git clone -q --depth 1 https://github.com/riscv/riscv-tests.git /opt/rt
[ -d /opt/rt-env/.git ] || git clone -q --depth 1 https://github.com/riscv/riscv-test-env.git /opt/rt-env

mkdir -p /ws/arch-tests
BUILT=0
for suite in rv64ui rv64um rv64uc; do
  for t in /opt/rt/isa/$suite/*.S; do
    name=$(basename "$t" .S)
    out="/ws/arch-tests/$suite-$name.elf"
    march=rv64imac_zicsr
    case $suite in
      rv64ui) march=rv64imc_zicsr ;;
      rv64um) march=rv64imc_zicsr ;;
      rv64uc) march=rv64imc_zicsr ;;
    esac
    if riscv64-unknown-elf-gcc -march=$march -mabi=lp64 -static -mcmodel=medany \
        -nostdlib -nostartfiles -I/opt/rt-env/p -I/opt/rt/isa/macros/scalar \
        -T/opt/rt-env/p/link.ld "$t" -o "$out" 2>/dev/null; then
      BUILT=$((BUILT+1))
    else
      echo "SKIP: $suite-$name"
    fi
  done
done
echo "built: $BUILT ELFs"
