use rat_core::{Lifetime, Rule, Verdict};
use rat_ledger::{Alert, AnswerScope};
use rat_types::Connection;
use serde::{Deserialize, Serialize};

/// PROPOSALS #15: bumped on every breaking protocol change. The FIRST client
/// message must be `Hello { protocol_version }`; a mismatched client is
/// answered with `Error` and closed (see ipc::handle_connection).
pub const PROTOCOL_VERSION: u32 = 1;

/// PROPOSALS #16: everything an IPC CLIENT may send. Split from the one
/// `Message` enum so a connected client cannot send server-side message
/// types (update-08 S10) and the daemon never parses its own output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClientMessage {
    Hello {
        protocol_version: u32,
    },
    SetRules {
        /// rat-core rule objects in the v2 wire format (camelCase, same JSON
        /// the Swift app persists — see rat-types/golden vectors).
        rules: Vec<Rule>,
    },
    AlertAnswer {
        /// The id of the AlertRequest being answered; stale ids are ignored.
        id: u64,
        verdict: Verdict,
        scope: AnswerScope,
        lifetime: Lifetime,
    },
}

/// PROPOSALS #16: everything the DAEMON sends. No ServerMessage reaches a
/// client before its Hello completed (#15).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServerMessage {
    HelloAck { protocol_version: u32 },
    Snapshot { connections: Vec<Connection> },
    // Boxed: Alert dwarfs the other variants; serde serializes it unchanged.
    AlertRequest { id: u64, alert: Box<Alert> },
    Error { message: String },
}

#[derive(Debug, thiserror::Error)]
pub enum MsgError {
    #[error("Failed to serialize message: {0}")]
    SerializeError(#[from] serde_json::Error),
}

impl ClientMessage {
    pub fn to_string(&self) -> Result<String, MsgError> {
        serde_json::to_string(self).map_err(MsgError::SerializeError)
    }

    pub fn from_json_str(s: &str) -> Result<Self, MsgError> {
        serde_json::from_str(s).map_err(MsgError::SerializeError)
    }
}

impl ServerMessage {
    pub fn to_string(&self) -> Result<String, MsgError> {
        serde_json::to_string(self).map_err(MsgError::SerializeError)
    }

    pub fn from_json_str(s: &str) -> Result<Self, MsgError> {
        serde_json::from_str(s).map_err(MsgError::SerializeError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rat_types::{ProcessInfo, Protocol};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;

    fn sample_connection() -> Connection {
        Connection {
            process: ProcessInfo {
                pid: 1234,
                exe: Some(PathBuf::from(r"C:\Program Files\App\app.exe")),
                name: "test".to_string(),
                user: None,
            },
            protocol: Protocol::Tcp,
            local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            remote: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                443,
            )),
            listening: false,
            bytes_in: Some(100),
            bytes_out: Some(200),
            via_vpn: false,
        }
    }

    #[test]
    fn test_client_message_roundtrip() {
        let msgs = vec![
            ClientMessage::Hello {
                protocol_version: PROTOCOL_VERSION,
            },
            ClientMessage::SetRules { rules: vec![] },
            ClientMessage::AlertAnswer {
                id: 7,
                verdict: Verdict::Deny,
                scope: AnswerScope::Any,
                lifetime: Lifetime::Forever,
            },
        ];
        for msg in msgs {
            let serialized = msg.to_string().expect("serialize client message");
            let deserialized =
                ClientMessage::from_json_str(&serialized).expect("deserialize client message");
            assert_eq!(msg, deserialized);
        }
    }

    #[test]
    fn test_server_message_roundtrip() {
        let alert = Alert {
            app: r"C:\Program Files\App\app.exe".to_string(),
            app_name: "app".to_string(),
            host: "203.0.113.9".to_string(),
            remote: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 443),
            proto: Protocol::Tcp,
            details: rat_ledger::ConnectionDetails::default(),
            reported_ms: 42,
        };
        let msgs = vec![
            ServerMessage::HelloAck {
                protocol_version: PROTOCOL_VERSION,
            },
            ServerMessage::Snapshot {
                connections: vec![sample_connection()],
            },
            ServerMessage::AlertRequest {
                id: 1,
                alert: Box::new(alert),
            },
            ServerMessage::Error {
                message: "bad".to_string(),
            },
        ];
        for msg in msgs {
            let serialized = msg.to_string().expect("serialize server message");
            let deserialized =
                ServerMessage::from_json_str(&serialized).expect("deserialize server message");
            assert_eq!(msg, deserialized);
        }
    }

    #[test]
    fn test_bad_input() {
        let err = ClientMessage::from_json_str("not json");
        assert!(err.is_err());
        let err2 = ClientMessage::from_json_str(r#"{"BadVariant": 123}"#);
        assert!(err2.is_err());

        let err = ServerMessage::from_json_str("not json");
        assert!(err.is_err());
        let err2 = ServerMessage::from_json_str(r#"{"BadVariant": 123}"#);
        assert!(err2.is_err());
    }

    // PROPOSALS #16: the split must be real — a client message type must not
    // decode as a server message and vice versa.
    #[test]
    fn test_directions_do_not_cross() {
        let hello = ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
        }
        .to_string()
        .unwrap();
        assert!(
            ServerMessage::from_json_str(&hello).is_err(),
            "ClientMessage::Hello must not decode as a ServerMessage"
        );
        let snapshot = ServerMessage::Snapshot {
            connections: vec![],
        }
        .to_string()
        .unwrap();
        assert!(
            ClientMessage::from_json_str(&snapshot).is_err(),
            "ServerMessage::Snapshot must not decode as a ClientMessage"
        );
    }
}
