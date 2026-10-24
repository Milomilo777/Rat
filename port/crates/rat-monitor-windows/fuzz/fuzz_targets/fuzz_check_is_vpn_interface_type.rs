#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (u32, &[u8])| {
    if let Ok(s) = std::str::from_utf8(data.1) {
        rat_monitor_windows::check_is_vpn_interface_type(data.0, s);
    }
});
