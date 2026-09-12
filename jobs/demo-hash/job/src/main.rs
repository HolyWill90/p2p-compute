#![no_std]
#![no_main]

//! The demo job: four seeded FNV-1a streams over the input, folded
//! into a 32-byte digest. Chosen over real SHA-256 for the scaffold
//! because every line is inspectable integer code; the verification
//! story is identical for any deterministic program.

use core::arch::asm;
use core::panic::PanicInfo;
use core::ptr;

const MUL: u64 = 0x100_0000_01b3;
const SEEDS: [u64; 4] = [
    0xcbf2_9ce4_8422_2325,
    0x9e37_79b9_7f4a_7c15,
    0x1656_67e1_9a9c_2b1d,
    0x27d4_eb2f_1656_67c5,
];

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe { asm!("ebreak", options(noreturn)) }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        // Note: no `la gp` here. Jobs are linked with -mno-relax, so no
        // code is gp-relative and the register stays zero. The emulator
        // pins sp (see abi::STACK_TOP) before the first instruction.

        let in_len = ptr::read_volatile(abi::INPUT_LEN_ADDR as *const u64) as usize;
        let in_ptr = abi::INPUT_DATA_ADDR as *const u8;

        let mut acc = SEEDS;
        for i in 0..in_len {
            let b = ptr::read_volatile(in_ptr.add(i)) as u64;
            // Per-stream multiplier differs by one bit so four
            // identical-structure streams cannot converge.
            acc[0] = (acc[0] ^ b).wrapping_mul(MUL);
            acc[1] = (acc[1] ^ b).wrapping_mul(MUL ^ 0x1);
            acc[2] = (acc[2] ^ b.rotate_left(7)).wrapping_mul(MUL);
            acc[3] = (acc[3] ^ b).wrapping_mul(MUL).rotate_left(13) ^ b;
        }

        ptr::write_volatile(abi::OUTPUT_LEN_ADDR as *mut u64, 32);
        for s in 0..4 {
            ptr::write_volatile((abi::OUTPUT_DATA_ADDR as *mut u64).add(s), acc[s].to_le());
        }

        asm!("ebreak", options(noreturn))
    }
}
