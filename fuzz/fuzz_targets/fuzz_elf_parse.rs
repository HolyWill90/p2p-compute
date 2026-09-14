#![no_main]
// The ELF parser is the first thing an attacker-supplied job touches:
// every byte of the image is file-controlled. A crash here is a
// remote denial of service on every worker.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(image) = rvcore::elf::parse(data) {
        // A parseable image must also load without panicking: every
        // segment is placed into the pinned flat address space.
        let mut mem = rvcore::Mem::new();
        let _ = rvcore::elf::load(&mut mem, &image);
    }
});
