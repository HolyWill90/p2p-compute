/// The machine state: 32 integer registers plus the program counter.
///
/// This is the entire architectural state, which is what makes the
/// state hash canonical: registers + pc + memory root, nothing else.
/// There is no hidden state (no flags, no mode bits, no clock).
#[derive(Clone, Debug)]
pub struct Cpu {
    pub x: [u64; 32],
    pub pc: u64,
}

impl Cpu {
    pub fn new(pc: u64, sp: u64) -> Self {
        let mut x = [0u64; 32];
        x[2] = sp; // x2 is the stack pointer
        Cpu { x, pc }
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
