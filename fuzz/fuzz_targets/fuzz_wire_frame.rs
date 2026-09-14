#![no_main]
// The coordinator decodes length-prefixed JSON frames from
// connections that have NOT authenticated yet: arbitrary bytes must
// yield a message or a clean error, never a panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut cursor = std::io::Cursor::new(data);
    let _ = wire::receive::<wire::ServerToClient>(&mut cursor);
});
