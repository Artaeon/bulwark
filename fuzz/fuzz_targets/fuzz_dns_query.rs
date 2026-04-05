#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic, regardless of input.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = bulwark::net_util::build_dns_query(0x1234, s);
    }
});
