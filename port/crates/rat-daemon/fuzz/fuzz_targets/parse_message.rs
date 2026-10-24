#![no_main]

use libfuzzer_sys::fuzz_target;
use rat_daemon::msg::Message;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Message::from_json_str(s);
    }
});
