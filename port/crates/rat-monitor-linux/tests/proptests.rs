use proptest::prelude::*;
use rat_monitor_linux::proc;
use rat_types::Protocol;

proptest! {
    #[test]
    fn parses_without_crashing(s in "\\PC*") {
        let _ = proc::parse_proc_net(&s, Protocol::Tcp);
    }
}
