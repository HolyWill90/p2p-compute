#![no_std]
#![no_main]

//! The agent-task pilot: deterministic agent-shaped batch work.
//!
//! Input: a batch of records {id, value, op}. The "agent's" task is a
//! data transformation: apply each record's op (keep / double / zero /
//! negate) and emit the transformed records plus an aggregate
//! (count + FNV checksum). Everything is integer-only and
//! deterministic, so the chunk-hash chain the emulator produces is a
//! complete audit trail of what the agent actually did to the data.

use core::arch::asm;
use core::panic::PanicInfo;
use core::ptr;

const MAX_RECORDS: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy)]
struct Record {
    id: u32,
    value: i32,
    op: u8,
    _pad: [u8; 7],
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    unsafe { asm!("ebreak", options(noreturn)) }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        let in_len = ptr::read_volatile(abi::INPUT_LEN_ADDR as *const u64) as usize;
        let in_ptr = abi::INPUT_DATA_ADDR as *const u8;

        // Header: u32 record count, u32 ops count (must match).
        if in_len < 8 {
            write_output_header(0, 0);
            asm!("ebreak", options(noreturn))
        }
        let n = ptr::read_volatile(in_ptr as *const u32) as usize;
        let m = ptr::read_volatile(in_ptr.add(4) as *const u32) as usize;
        let n = if n > MAX_RECORDS { MAX_RECORDS } else { n };
        let _ = m;

        let mut out_n: usize = 0;
        let mut checksum: u64 = 0xcbf2_9ce4_8422_2325;
        let out_base = (abi::OUTPUT_DATA_ADDR + 24) as *mut u8;

        for i in 0..n {
            let rec = in_ptr.add(8 + i * 16) as *const Record;
            let rec = rec.read_volatile();
            let value = match rec.op {
                1 => rec.value.wrapping_mul(2),
                2 => 0,
                3 => rec.value.wrapping_neg(),
                _ => rec.value,
            };
            // Emit {id u32, value i32} = 8 bytes per transformed record.
            ptr::write_volatile(out_base.add(out_n) as *mut u32, rec.id);
            ptr::write_volatile(out_base.add(out_n + 4) as *mut i32, value);
            out_n += 8;

            // FNV over the transformed value bytes.
            let bytes = value.to_le_bytes();
            for b in bytes {
                checksum ^= b as u64;
                checksum = checksum.wrapping_mul(0x100_0000_01b3);
            }
        }

        write_output_header(out_n as u64, checksum);
        asm!("ebreak", options(noreturn))
    }
}

/// Output layout: u32 byte length, u64 checksum, then the records.
unsafe fn write_output_header(byte_len: u64, checksum: u64) {
    ptr::write_volatile(abi::OUTPUT_LEN_ADDR as *mut u64, byte_len + 24);
    ptr::write_volatile((abi::OUTPUT_DATA_ADDR as *mut u64).add(0), byte_len);
    ptr::write_volatile((abi::OUTPUT_DATA_ADDR as *mut u64).add(1), checksum);
}
