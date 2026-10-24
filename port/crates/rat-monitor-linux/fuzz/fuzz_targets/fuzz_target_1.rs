#![no_main]
use libfuzzer_sys::fuzz_target;
use rat_monitor_linux::proc;
use rat_types::Protocol;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = proc::parse_proc_net(s, Protocol::Tcp);
    }
});
