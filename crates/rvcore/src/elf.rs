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
    let phoff = u64le(0x20);
    let phentsize = u16le(0x36) as usize;
    let phnum = u16le(0x38) as usize;
    if phentsize != 56 {
        return Err(format!("elf: phentsize {} != 56", phentsize));
    }

    let mut segments = Vec::new();
    for i in 0..phnum {
        let base = phoff as usize + i * 56;
        if base + 56 > bytes.len() {
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
        let off = offset as usize;
        if off + filesz as usize > bytes.len() {
            return Err("elf: segment beyond file end".into());
        }
        let mut data = bytes[off..off + filesz as usize].to_vec();
        data.resize(memsz as usize, 0); // BSS tail is zeros
        segments.push((vaddr, data));
    }
    if segments.is_empty() {
        return Err("elf: no PT_LOAD segments".into());
    }
    Ok(ElfImage { entry, segments })
}

/// Place the image into memory.
pub fn load(mem: &mut Mem, elf: &ElfImage) -> Result<(), String> {
    for (vaddr, data) in &elf.segments {
        mem.load_image(*vaddr, data).map_err(|e| format!("elf: load at {vaddr:#x}: {e:?}"))?;
    }
    Ok(())
}
