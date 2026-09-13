// read/write sit on the per-instruction fetch and load/store paths:
// `%` lowers to a single AND, while is_multiple_of stays an
// out-of-line call in debug builds.
#![allow(clippy::manual_is_multiple_of)]

use std::collections::BTreeMap;

pub const PAGE_SIZE: usize = 4096;
/// The emulator pins a flat 4 GiB address space (32-bit effective).
/// Any access computing an address at or above this bound is a trap.
pub const ADDR_SPACE: u64 = 1 << 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemError {
    OutOfRange,
}

type Page = Box<[u8; PAGE_SIZE]>;

/// Sparse paged memory. Reads of unallocated pages return zero
/// (canonical); writes allocate. Memory is part of the hashed state,
/// so allocation order must never influence the hash: the Merkle root
/// is computed over pages in sorted index order.
///
/// `syscall_log` collects bytes written via the QEMU-compatible write
/// syscall in syscall mode. It is deliberately NOT part of the hashed
/// state: the hash covers the machine, not its I/O effects. Log
/// equality across independent implementations is checked by the
/// conformance differential instead.
pub struct Mem {
    pages: BTreeMap<u32, Page>,
    pub syscall_log: Vec<u8>,
}

impl Default for Mem {
    fn default() -> Self {
        Self::new()
    }
}

impl Mem {
    pub fn new() -> Self {
        Mem { pages: BTreeMap::new(), syscall_log: Vec::new() }
    }

    fn page_of(&self, addr: u64) -> Option<&Page> {
        self.pages.get(&((addr / PAGE_SIZE as u64) as u32))
    }

    fn page_mut(&mut self, addr: u64) -> &mut Page {
        let idx = (addr / PAGE_SIZE as u64) as u32;
        self.pages.entry(idx).or_insert_with(|| Box::new([0; PAGE_SIZE]))
    }

    /// Little-endian read of `len` (1, 2, 4 or 8) bytes. Unallocated
    /// pages read as zeros.
    pub fn read(&self, addr: u64, len: usize) -> Result<u64, MemError> {
        if len != 1 && len != 2 && len != 4 && len != 8 {
            return Err(MemError::OutOfRange);
        }
        // checked_add: `addr` is guest-controlled and can be near
        // u64::MAX — a wrapping sum could pass this check and address
        // pages far outside the pinned space (debug would panic).
        let end = match addr.checked_add(len as u64) {
            Some(e) => e,
            None => return Err(MemError::OutOfRange),
        };
        if end > ADDR_SPACE {
            return Err(MemError::OutOfRange);
        }
        // Misaligned accesses are supported: the byte loop splits
        // them across pages, which is fully deterministic. This
        // matches the spike/QEMU platform behavior the conformance
        // differentials validate against.
        let mut val = 0u64;
        for i in 0..len {
            let a = addr + i as u64;
            let b = match self.page_of(a) {
                Some(p) => p[(a % PAGE_SIZE as u64) as usize],
                None => 0,
            };
            val |= (b as u64) << (8 * i);
        }
        Ok(val)
    }

    /// Little-endian write of `bytes`. Allocates pages as needed.
    pub fn write(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MemError> {
        let end = match addr.checked_add(bytes.len() as u64) {
            Some(e) => e,
            None => return Err(MemError::OutOfRange),
        };
        if end > ADDR_SPACE {
            return Err(MemError::OutOfRange);
        }
        for (i, &b) in bytes.iter().enumerate() {
            let a = addr + i as u64;
            self.page_mut(a)[(a % PAGE_SIZE as u64) as usize] = b;
        }
        Ok(())
    }

    pub fn load_image(&mut self, base: u64, bytes: &[u8]) -> Result<(), MemError> {
        self.write(base, bytes)
    }

    pub fn read_region(&self, addr: u64, len: usize) -> Result<Vec<u8>, MemError> {
        // checked_add: `addr` is guest-controlled and can be near
        // u64::MAX — a wrapping sum could pass this check and address
        // pages far outside the pinned space (debug would panic).
        let end = match addr.checked_add(len as u64) {
            Some(e) => e,
            None => return Err(MemError::OutOfRange),
        };
        if end > ADDR_SPACE {
            return Err(MemError::OutOfRange);
        }
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            let a = addr + i as u64;
            out.push(match self.page_of(a) {
                Some(p) => p[(a % PAGE_SIZE as u64) as usize],
                None => 0,
            });
        }
        Ok(out)
    }

    /// Root of the memory state: BLAKE3 over each allocated page
    /// (index in LE, then the full 4 KiB), pages in sorted order.
    /// Unallocated pages contribute nothing, and reads of them are
    /// defined as zero, so the mapping is a pure function of the
    /// semantics — an emulator that allocated differently would still
    /// have to produce this exact root.
    pub fn merkle_root(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for (&idx, page) in &self.pages {
            h.update(&idx.to_le_bytes());
            h.update(page.as_slice());
        }
        h.finalize().into()
    }

    pub fn allocated_pages(&self) -> usize {
        self.pages.len()
    }

    /// Iterate allocated pages in canonical (sorted) order — used by
    /// the snapshot serializer.
    pub(crate) fn page_iter(&self) -> impl Iterator<Item = (u32, &Page)> {
        self.pages.iter().map(|(&i, p)| (i, p))
    }

    pub(crate) fn insert_page(&mut self, idx: u32, page: Page) {
        self.pages.insert(idx, page);
    }
}
