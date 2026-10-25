#![no_main]

use libfuzzer_sys::fuzz_target;
use rat_daemon::msg::{ClientMessage, ServerMessage};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // The daemon parses CLIENT messages; the GUI parses SERVER messages.
        // Both directions must survive arbitrary input without crashing.
        let _ = ClientMessage::from_json_str(s);
        let _ = ServerMessage::from_json_str(s);
    }
});
