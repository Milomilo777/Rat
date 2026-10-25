use proptest::prelude::*;
use rat_daemon::msg::{ClientMessage, ServerMessage};

proptest! {
    #[test]
    fn doesnt_crash_client(s in "\\PC*") {
        let _ = ClientMessage::from_json_str(&s);
    }

    #[test]
    fn doesnt_crash_server(s in "\\PC*") {
        let _ = ServerMessage::from_json_str(&s);
    }

    #[test]
    fn parses_all_valid_client_messages(msg_str in ".*") {
        let _ = ClientMessage::from_json_str(&msg_str);
    }

    #[test]
    fn parses_all_valid_server_messages(msg_str in ".*") {
        let _ = ServerMessage::from_json_str(&msg_str);
    }
}
