#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        rat_monitor_windows::extract_process_name_from_path(Some(std::path::Path::new(s)));
    }
});
