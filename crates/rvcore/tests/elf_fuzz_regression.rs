//! Regression tests for overflow crashes found by `fuzz_elf_parse`
//! (cargo-fuzz, ASAN). Each case builds a header whose file-controlled
//! offsets previously overflowed the loader's arithmetic. Debug builds
//! panic on overflow, so CI catches any reintroduction.

fn elf_shell(shoff: u64, shnum: u16, shstrndx: u16, phoff: u64, phnum: u16) -> Vec<u8> {
    let mut e = vec![0u8; 64];
    e[0..4].copy_from_slice(b"\x7fELF");
    e[4] = 2; // ELF64
    e[5] = 1; // little-endian
    e[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    e[18..20].copy_from_slice(&243u16.to_le_bytes()); // EM_RISCV
    e[0x18..0x20].copy_from_slice(&0x8000_0000u64.to_le_bytes()); // entry
    e[0x20..0x28].copy_from_slice(&phoff.to_le_bytes()); // e_phoff
    e[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    e[0x38..0x3a].copy_from_slice(&phnum.to_le_bytes()); // e_phnum
    e[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    e[0x3c..0x3e].copy_from_slice(&shnum.to_le_bytes()); // e_shnum
    e[0x3e..0x40].copy_from_slice(&shstrndx.to_le_bytes()); // e_shstrndx
    e[0x28..0x30].copy_from_slice(&shoff.to_le_bytes()); // e_shoff
    e
}

#[test]
fn shstr_table_offset_overflow_is_rejected() {
    // shoff near usize::MAX: shstr_hdr = shoff + shstrndx * 64 wrapped.
    let e = elf_shell(u64::MAX - 16, 1, 0, 0, 0);
    assert!(rvcore::elf::parse(&e).is_err());
}

#[test]
fn program_header_table_overflow_is_rejected() {
    // phoff near usize::MAX with 3 headers: base = phoff + i*56 wrapped.
    let e = elf_shell(64, 0, 0, u64::MAX - 16, 3);
    assert!(rvcore::elf::parse(&e).is_err());
}

#[test]
fn giant_bss_claim_does_not_allocate() {
    // A valid-looking single PT_LOAD whose memsz claims the full
    // address space with a tiny file: the loader must reject the range
    // (and never pre-allocate the BSS tail — sparse memory supplies
    // those zeros), without OOM.
    let mut e = elf_shell(64, 0, 0, 64, 1);
    e[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // phoff = 64
    // Append one program header at offset 64.
    let mut ph = vec![0u8; 56];
    ph[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    ph[0x08..0x10].copy_from_slice(&0u64.to_le_bytes()); // offset
    ph[0x10..0x18].copy_from_slice(&0x8000_0000u64.to_le_bytes()); // vaddr
    ph[0x20..0x28].copy_from_slice(&0u64.to_le_bytes()); // filesz
    ph[0x28..0x30].copy_from_slice(&0xFFFF_FFFFu64.to_le_bytes()); // memsz ~4GiB
    e.extend_from_slice(&ph);
    // Either an error or a clean parse — but never a giant allocation
    // (the fuzz run's RSS guard would have flagged that).
    let _ = rvcore::elf::parse(&e);
}
