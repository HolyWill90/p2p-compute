use rvcore::Mem;

#[test]
fn guest_address_near_u64_max_does_not_wrap() {
    let mut mem = Mem::new();
    // Without checked arithmetic, addr + len wraps on 64-bit: a debug
    // build panicked here and a release build silently addressed
    // wrapped (i.e. wrong) pages.
    assert!(mem.write(u64::MAX - 4, &[0u8; 8]).is_err());
    assert!(mem.read(u64::MAX - 4, 8).is_err());
    assert!(mem.read_region(u64::MAX - 4, 8).is_err());
    // The extreme first byte too.
    assert!(mem.read(u64::MAX, 1).is_err());
}

#[test]
fn out_of_range_still_traps() {
    let mut mem = Mem::new();
    assert!(mem.write(1u64 << 32, &[0u8]).is_err());
    assert!(mem.read(1u64 << 32, 1).is_err());
    // The last valid byte remains writable.
    assert!(mem.write((1u64 << 32) - 1, &[0x42]).is_ok());
}
