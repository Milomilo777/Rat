#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Just provide it as line to parse
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join("fuzz_zone_tab.tab");
        if let Ok(_) = std::fs::write(&file_path, s) {
            let _ = rat_geo::TimeZoneLocator::lookup_in_zone_tab("Anything", file_path.to_str().unwrap());
            let _ = std::fs::remove_file(file_path);
        }
    }
});
