#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() == 4 {
        let mut arr = [0u8; 4];
        arr.copy_from_slice(data);
        let u = u32::from_ne_bytes(arr);
        rat_monitor_windows::convert_ipv4_addr(u);
    } else if data.len() == 16 {
        let mut arr = [0u8; 16];
        arr.copy_from_slice(data);
        rat_monitor_windows::convert_ipv6_addr(&arr);
    }
});
