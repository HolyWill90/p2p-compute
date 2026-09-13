/// The machine state: 32 integer registers, the program counter, and
/// the few machine CSRs the test suites exercise (mtvec/mepc/mcause/
/// mstatus). All of it is hashed: the CSR writes are architectural.
/// There is no hidden state (no flags, no clock).
#[derive(Clone, Debug)]
pub struct Cpu {
    pub x: [u64; 32],
    pub pc: u64,
    /// Machine trap-vector base (mtvec, CSR 0x305); direct-mode base.
    pub mtvec: u64,
    /// Machine exception program counter (mepc, CSR 0x341).
    pub mepc: u64,
    /// Machine cause register (mcause, CSR 0x342).
    pub mcause: u64,
    /// Machine status (mstatus, CSR 0x300), stored raw.
    pub mstatus: u64,
    /// tohost device latch: the last value written to the tohost
    /// address. NOT part of the hashed state — it is an I/O effect,
    /// like the syscall log.
    pub tohost: Option<u64>,
}

impl Cpu {
    pub fn new(pc: u64, sp: u64) -> Self {
        let mut x = [0u64; 32];
        x[2] = sp; // x2 is the stack pointer
        Cpu { x, pc, mtvec: 0, mepc: 0, mcause: 0, mstatus: 0, tohost: None }
    }

    #[inline]
    pub fn set(&mut self, reg: u32, val: u64) {
        if reg != 0 {
            self.x[reg as usize] = val;
        }
    }

    #[inline]
    pub fn get(&self, reg: u32) -> u64 {
        self.x[reg as usize]
    }
}
