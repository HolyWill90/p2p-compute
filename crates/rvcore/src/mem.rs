// read/write sit on the per-instruction fetch and load/store paths:
// `%` lowers to a single AND, while is_multiple_of stays an
// out-of-line call in debug builds.
#![allow(clippy::manual_is_multiple_of)]

pub const PAGE_SIZE: usize = 4096;
/// The emulator pins a flat 4 GiB address space (32-bit effective).
/// Any access computing an address at or above this bound is a trap.
pub const ADDR_SPACE: u64 = 1 << 32;
/// Total pages in the pinned space (2^32 / 4096).
pub const PAGE_COUNT: usize = (ADDR_SPACE / PAGE_SIZE as u64) as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemError {
    OutOfRange,
}

type Page = Box<[u8; PAGE_SIZE]>;
const UNALLOCATED: u32 = u32::MAX;

/// Sparse paged memory. Reads of unallocated pages return zero
/// (canonical); writes allocate. Memory is part of the hashed state,
/// so allocation order must never influence the hash: the Merkle root
/// is computed over pages in sorted index order.
///
/// Layout: `page_index` maps page number -> slot in `pages` (O(1)
/// lookups on the per-instruction fetch/load/store paths, versus the
/// O(log n) BTreeMap this used to be). `page_index` grows lazily to
/// cover the highest allocated page; a 4 MiB fully-populated job pays
/// ~2 KiB of index. Unallocated slots are UNALLOCATED sentinels.
///
/// `syscall_log` collects bytes written via the QEMU-compatible write
/// syscall in syscall mode. It is deliberately NOT part of the hashed
/// state: the hash covers the machine, not its I/O effects. Log
/// equality across independent implementations is checked by the
/// conformance differential instead.
pub struct Mem {
    pages: Vec<Page>,
    page_index: Vec<u32>,
    pub syscall_log: Vec<u8>,
}

impl Default for Mem {
    fn default() -> Self {
        Self::new()
    }
}

impl Mem {
    pub fn new() -> Self {
        Mem { pages: Vec::new(), page_index: Vec::new(), syscall_log: Vec::new() }
    }

    fn slot_of(&self, page: u32) -> Option<usize> {
        let slot = *self.page_index.get(page as usize)?;
        if slot == UNALLOCATED {
            None
        } else {
            Some(slot as usize)
        }
    }

    fn slot_mut_or_alloc(&mut self, page: u32) -> usize {
        if page as usize >= self.page_index.len() {
            self.page_index.resize(page as usize + 1, UNALLOCATED);
        }
        let slot = self.page_index[page as usize];
        if slot == UNALLOCATED {
            let s = self.pages.len();
            self.pages.push(Box::new([0; PAGE_SIZE]));
            self.page_index[page as usize] = s as u32;
            s
        } else {
            slot as usize
        }
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
            let b = match self.slot_of((a / PAGE_SIZE as u64) as u32) {
                Some(s) => self.pages[s][(a % PAGE_SIZE as u64) as usize],
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
            let slot = self.slot_mut_or_alloc((a / PAGE_SIZE as u64) as u32);
            self.pages[slot][(a % PAGE_SIZE as u64) as usize] = b;
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
            out.push(match self.slot_of((a / PAGE_SIZE as u64) as u32) {
                Some(s) => self.pages[s][(a % PAGE_SIZE as u64) as usize],
                None => 0,
            });
        }
        Ok(out)
    }

    /// Root of the memory state: BLAKE3 over each allocated page
    /// (index in LE, then the full 4 KiB), pages in sorted index
    /// order. `page_index` is inherently sorted by page number, so the
    /// iteration order matches the BTreeMap-based implementation this
    /// replaced byte-for-byte.
    pub fn merkle_root(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for (page, &slot) in self.page_index.iter().enumerate() {
            if slot != UNALLOCATED {
                h.update(&(page as u32).to_le_bytes());
                h.update(self.pages[slot as usize].as_slice());
            }
        }
        h.finalize().into()
    }

    pub fn allocated_pages(&self) -> usize {
        self.pages.len()
    }

    /// Iterate allocated pages in canonical (sorted) order — used by
    /// the snapshot serializer.
    pub(crate) fn page_iter(&self) -> impl Iterator<Item = (u32, &Page)> {
        self.page_index
            .iter()
            .enumerate()
            .filter(|(_, &slot)| slot != UNALLOCATED)
            .map(|(page, &slot)| (page as u32, &self.pages[slot as usize]))
    }

    pub(crate) fn insert_page(&mut self, idx: u32, page: Page) {
        if idx as usize >= self.page_index.len() {
            self.page_index.resize(idx as usize + 1, UNALLOCATED);
        }
        let slot = self.page_index[idx as usize];
        match slot {
            UNALLOCATED => {
                let s = self.pages.len();
                self.pages.push(page);
                self.page_index[idx as usize] = s as u32;
            }
            s => self.pages[s as usize] = page,
        }
    }
}
