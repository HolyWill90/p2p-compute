use crate::mem::Mem;

/// Minimal ELF64 loader for the pinned job ABI.
///
/// Accepts exactly: little-endian ELF64 RISC-V static executables
/// (ET_EXEC) with PT_LOAD segments. Everything else is rejected — the
/// loader exists to place an image, not to interpret one.
pub struct ElfImage {
    pub entry: u64,
    /// (vaddr, bytes) for each PT_LOAD segment; memsz > filesz implies
    /// zero-filled BSS tail.
    pub segments: Vec<(u64, Vec<u8>)>,
    /// Address of the `tohost` symbol, parsed from the section headers
    /// (.tohost section). None if the ELF has no tohost.
    pub tohost_addr: Option<u64>,
}

const PT_LOAD: u32 = 1;
const EM_RISCV: u16 = 243;
const ET_EXEC: u16 = 2;

pub fn parse(bytes: &[u8]) -> Result<ElfImage, String> {
    if bytes.len() < 64 {
        return Err("elf: too short".into());
    }
    if &bytes[0..4] != b"\x7fELF" {
        return Err("elf: bad magic".into());
    }
    if bytes[4] != 2 {
        return Err("elf: not ELF64".into());
    }
    if bytes[5] != 1 {
        return Err("elf: not little-endian".into());
    }
    let u16le = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]);
    let u32le = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
    let u64le = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());

    if u16le(0x12) != EM_RISCV {
        return Err(format!("elf: machine {} is not RISC-V", u16le(0x12)));
    }
    if u16le(0x10) != ET_EXEC {
        return Err("elf: not a static executable".into());
    }
    let entry = u64le(0x18);
    let e_shoff = u64le(0x28);
    let e_shentsize = u16le(0x3a) as usize;
    let e_shnum = u16le(0x3c) as usize;
    let e_shstrndx = u16le(0x3e) as usize;
    let tohost_addr = find_tohost_section(bytes, e_shoff as usize, e_shentsize, e_shnum, e_shstrndx);
    let phoff = u64le(0x20);
    let phentsize = u16le(0x36) as usize;
    let phnum = u16le(0x38) as usize;
    if phentsize != 56 {
        return Err(format!("elf: phentsize {} != 56", phentsize));
    }

    let mut segments = Vec::new();
    let phoff_us = phoff as usize;
    for i in 0..phnum {
        // phoff and i*56 are file-controlled: checked, like every
        // other offset in this parser (fuzz-found overflow class).
        let base = match phoff_us.checked_add(i.checked_mul(56).ok_or("elf: program header table overflows")?) {
            Some(b) => b,
            None => return Err("elf: program header table overflows".into()),
        };
        let base_end = match base.checked_add(56) {
            Some(e) => e,
            None => return Err("elf: program header table overflows".into()),
        };
        if base_end > bytes.len() {
            return Err("elf: truncated program headers".into());
        }
        if u32le(base) != PT_LOAD {
            continue;
        }
        let offset = u64le(base + 8);
        let vaddr = u64le(base + 16);
        let filesz = u64le(base + 32);
        let memsz = u64le(base + 40);
        if filesz > memsz {
            return Err("elf: filesz > memsz".into());
        }
        // The segment must fit the pinned 4 GiB space. All arithmetic
        // is checked — the fields are file-controlled (a fuzz-found
        // overflow lived here).
        let mem_end = match vaddr.checked_add(memsz) {
            Some(e) => e,
            None => return Err("elf: segment range overflows".into()),
        };
        if mem_end > crate::mem::ADDR_SPACE {
            return Err("elf: segment exceeds the pinned address space".into());
        }
        let off = offset as usize;
        let file_end = match off.checked_add(filesz as usize) {
            Some(e) => e,
            None => return Err("elf: segment beyond file end".into()),
        };
        if file_end > bytes.len() {
            return Err("elf: segment beyond file end".into());
        }
        // Only the FILE bytes are loaded. The BSS tail (memsz > filesz)
        // is intentionally NOT pre-allocated: sparse memory reads
        // unallocated pages as zeros, so pre-resizing would let a
        // hostile memsz claim gigabytes of allocation for nothing.
        let data = bytes[off..file_end].to_vec();
        segments.push((vaddr, data));
    }
    if segments.is_empty() {
        return Err("elf: no PT_LOAD segments".into());
    }
    Ok(ElfImage { entry, segments, tohost_addr })
}

/// Scan section headers for `.tohost` and return its virtual address.
fn find_tohost_section(
    data: &[u8],
    shoff: usize,
    shentsize: usize,
    shnum: usize,
    shstrndx: usize,
) -> Option<u64> {
    if shoff == 0 || shnum == 0 || shentsize == 0 {
        return None;
    }
    // Every offset here derives from file-controlled header fields: all
    // arithmetic is checked, and all file access goes through bounds-
    // checked `get` (a fuzz-found overflow lived here — see the fuzz
    // target `fuzz_elf_parse`).
    let checked = |a: usize, b: usize| -> Option<usize> { a.checked_add(b) };
    let shstr_hdr = checked(shoff, shstrndx.checked_mul(shentsize)?)?;
    // The shstrtab header's sh_offset field: read exactly its 8 bytes.
    // (A whole-tail `get(start..)` would not convert to [u8; 8] unless
    // the header happened to end the file, silently yielding None.)
    let shstr_offset = u64::from_le_bytes(
        data.get(checked(shstr_hdr, 24)?..checked(shstr_hdr, 32)?)?.try_into().ok()?,
    ) as usize;
    for i in 0..shnum {
        let base = checked(shoff, i.checked_mul(shentsize)?)?;
        let base_end = checked(base, 64)?;
        if base_end > data.len() {
            break;
        }
        let sec_name = u32::from_le_bytes(data.get(base..base + 4)?.try_into().ok()?);
        let sec_type = u32::from_le_bytes(data.get(base + 4..base + 8)?.try_into().ok()?);
        let sec_addr = u64::from_le_bytes(data.get(base + 16..base + 24)?.try_into().ok()?);
        if sec_type != 1 {
            continue;
        }
        let name_start = checked(shstr_offset, sec_name as usize)?;
        let name_end = data.get(name_start..)?
            .iter().position(|&b| b == 0)
            .map(|p| name_start + p)
            .unwrap_or(name_start);
        if data.get(name_start..name_end)? == b".tohost" {
            return Some(sec_addr);
        }
    }
    None
}

/// Place the image into memory.
pub fn load(mem: &mut Mem, elf: &ElfImage) -> Result<(), String> {
    for (vaddr, data) in &elf.segments {
        mem.load_image(*vaddr, data).map_err(|e| format!("elf: load at {vaddr:#x}: {e:?}"))?;
    }
    Ok(())
}
