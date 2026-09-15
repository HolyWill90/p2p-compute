// read/write sit on the per-instruction fetch and load/store paths:
// `%` lowers to a single AND, while is_multiple_of stays an
// out-of-line call in debug builds.
#![allow(clippy::manual_is_multiple_of)]

use std::collections::BTreeMap;

pub const PAGE_SIZE: usize = 4096;
/// The emulator pins a flat 4 GiB address space (32-bit effective).
/// Any access computing an address at or above this bound is a trap.
pub const ADDR_SPACE: u64 = 1 << 32;
/// Direct-mapped lookaside size. Covers every hot page of our jobs
/// (demo-hash touches ~520) with a single tagged probe.
const LOOKASIDE_SLOTS: usize = 2048;
const NO_SLOT: u32 = u32::MAX;
const NO_PAGE: u32 = u32::MAX;

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
/// Layout: `page_dir` is the canonical sparse map (page -> slot, the
/// sorted iteration order for hashing and snapshots); `page_slots`
/// holds the pages (append-only — slots are stable for the life of
/// the Mem). `lookaside` is a tagged direct-mapped cache over the
/// directory so the per-instruction fetch/load/store path probes one
/// array entry instead of walking the map. It deliberately replaces
/// the flat page-index this used to be: a flat index spanning the
/// ABI's address layout (stack at 0x83F0_0000 vs image at 0x8000_0000)
/// zeroes ~2 MB on first touch, which inside the zkVM guest crossed a
/// proving-shard boundary and made receipts unprovable (measured).
///
/// `syscall_log` collects bytes written via the QEMU-compatible write
/// syscall in syscall mode. It is deliberately NOT part of the hashed
/// state: the hash covers the machine, not its I/O effects. Log
/// equality across independent implementations is checked by the
/// conformance differential instead.
pub struct Mem {
    page_slots: Vec<Page>,
    page_dir: BTreeMap<u32, usize>,
    lookaside: Vec<(u32, u32)>, // (page tag, slot); NO_PAGE = empty
    pub syscall_log: Vec<u8>,
}

impl Default for Mem {
    fn default() -> Self {
        Self::new()
    }
}

impl Mem {
    pub fn new() -> Self {
        Mem {
            page_slots: Vec::new(),
            page_dir: BTreeMap::new(),
            lookaside: vec![(NO_PAGE, NO_SLOT); LOOKASIDE_SLOTS],
            syscall_log: Vec::new(),
        }
    }

    /// O(1) on a lookaside hit; O(log n) directory walk on a miss
    /// (which then fills the lookaside — callers hold `&mut`).
    fn slot_of(&mut self, page: u32) -> Option<usize> {
        let idx = (page as usize) % LOOKASIDE_SLOTS;
        let (tag, slot) = self.lookaside[idx];
        if tag == page {
            return if slot == NO_SLOT { None } else { Some(slot as usize) };
        }
        let slot = *self.page_dir.get(&page)?;
        self.lookaside[idx] = (page, slot as u32);
        Some(slot)
    }

    /// Read-only probe: same as `slot_of` but without filling the
    /// lookaside (for `&self` paths, which are rare).
    fn slot_of_ro(&self, page: u32) -> Option<usize> {
        let idx = (page as usize) % LOOKASIDE_SLOTS;
        let (tag, slot) = self.lookaside[idx];
        if tag == page {
            return if slot == NO_SLOT { None } else { Some(slot as usize) };
        }
        self.page_dir.get(&page).copied()
    }

    fn slot_mut_or_alloc(&mut self, page: u32) -> usize {
        let idx = (page as usize) % LOOKASIDE_SLOTS;
        let (tag, slot) = self.lookaside[idx];
        if tag == page && slot != NO_SLOT {
            return slot as usize;
        }
        let slot = match self.page_dir.get(&page) {
            Some(&s) => s,
            None => {
                let s = self.page_slots.len();
                self.page_slots.push(Box::new([0; PAGE_SIZE]));
                self.page_dir.insert(page, s);
                s
            }
        };
        self.lookaside[idx] = (page, slot as u32);
        slot
    }

    /// Little-endian read of `len` (1, 2, 4 or 8) bytes. Unallocated
    /// pages read as zeros.
    pub fn read(&mut self, addr: u64, len: usize) -> Result<u64, MemError> {
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
                Some(s) => self.page_slots[s][(a % PAGE_SIZE as u64) as usize],
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
            self.page_slots[slot][(a % PAGE_SIZE as u64) as usize] = b;
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
            out.push(match self.slot_of_ro((a / PAGE_SIZE as u64) as u32) {
                Some(s) => self.page_slots[s][(a % PAGE_SIZE as u64) as usize],
                None => 0,
            });
        }
        Ok(out)
    }

    /// Root of the memory state: BLAKE3 over each allocated page
    /// (index in LE, then the full 4 KiB), pages in sorted index
    /// order — `page_dir` iterates sorted, matching every earlier
    /// implementation byte-for-byte.
    pub fn merkle_root(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for (&idx, page) in &self.page_dir {
            h.update(&idx.to_le_bytes());
            h.update(self.page_slots[*page].as_slice());
        }
        h.finalize().into()
    }

    pub fn allocated_pages(&self) -> usize {
        self.page_dir.len()
    }

    /// Iterate allocated pages in canonical (sorted) order — used by
    /// the snapshot serializer.
    pub(crate) fn page_iter(&self) -> impl Iterator<Item = (u32, &Page)> {
        self.page_dir.iter().map(|(&i, &s)| (i, &self.page_slots[s]))
    }

    pub(crate) fn insert_page(&mut self, idx: u32, page: Page) {
        match self.page_dir.get(&idx) {
            Some(&s) => self.page_slots[s] = page,
            None => {
                let s = self.page_slots.len();
                self.page_slots.push(page);
                self.page_dir.insert(idx, s);
            }
        }
        // The lookaside may hold a stale (page, NO_SLOT) probe for a
        // page that was unallocated until now.
        self.lookaside[(idx as usize) % LOOKASIDE_SLOTS] = (NO_PAGE, NO_SLOT);
    }
}
