use proptest::prelude::*;
use rat_daemon::msg::Message;

proptest! {
    #[test]
    fn doesnt_crash(s in "\\PC*") {
        let _ = Message::from_json_str(&s);
    }

    #[test]
    fn parses_all_valid_messages(msg_str in ".*") {
        let _ = Message::from_json_str(&msg_str);
    }
}
