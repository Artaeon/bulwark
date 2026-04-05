#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic, regardless of input.
    let _ = bulwark::detectors::dhcp::parse_dhcp_offer(data);
});
