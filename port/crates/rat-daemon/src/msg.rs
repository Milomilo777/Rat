use rat_core::{Lifetime, Rule, Verdict};
use rat_ledger::{Alert, AnswerScope};
use rat_types::Connection;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// bumped on every breaking protocol change. The FIRST client
/// message must be `Hello { protocol_version }`; a mismatched client is
/// answered with `Error` and closed (see ipc::handle_connection).
pub const PROTOCOL_VERSION: u32 = 1;

/// everything an IPC CLIENT may send. Split from the one
/// `Message` enum so a connected client cannot send server-side message
/// types and the daemon never parses its own output.
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
    /// Ask for the daemon's current in-memory rule set; answered with
    /// `ServerMessage::Rules`. The daemon is the single source of rules: a
    /// client must not read the rules file itself.
    GetRules,
    /// Add ONE rule to the daemon's in-memory set, or replace the rule with
    /// the same id (an incremental edit — `SetRules` stays the whole-list
    /// replace and the bulk/import path). Saved like `SetRules`.
    /// Boxed: Rule dwarfs the other variants; serde serializes it unchanged.
    AddRule {
        rule: Box<Rule>,
    },
    /// Remove ONE rule by id (an incremental edit). An unknown id is logged
    /// by the daemon and changes nothing.
    RemoveRule {
        id: Uuid,
    },
}

/// everything the DAEMON sends. No ServerMessage reaches a
/// client before its Hello completed (#15).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServerMessage {
    HelloAck {
        protocol_version: u32,
    },
    Snapshot {
        connections: Vec<Connection>,
    },
    // Boxed: Alert dwarfs the other variants; serde serializes it unchanged.
    AlertRequest {
        id: u64,
        alert: Box<Alert>,
    },
    Error {
        message: String,
    },
    /// The answer to `GetRules`: the whole current rule set, session rules
    /// (once / until quit) included.
    Rules {
        rules: Vec<Rule>,
    },
    /// The alert `id` is no longer pending (answered, timed out or gone).
    AlertCleared {
        id: u64,
    },
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

    fn new_rule() -> Rule {
        Rule {
            id: Uuid::new_v4(),
            verdict: Verdict::Deny,
            process_path: Some(r"C:\Program Files\App\app.exe".to_string()),
            signing_id: None,
            team_id: None,
            remote_domain: None,
            remote_host: None,
            remote_address: None,
            ports: None,
            proto: None,
            enabled: true,
            approved: true,
            lifetime: Lifetime::Forever,
            profile_id: None,
            group_id: None,
            created_at: chrono::Utc::now(),
            note: None,
        }
    }

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
            ClientMessage::GetRules,
            ClientMessage::AddRule {
                rule: Box::new(new_rule()),
            },
            ClientMessage::RemoveRule { id: Uuid::new_v4() },
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
            ServerMessage::Rules { rules: vec![] },
            ServerMessage::AlertCleared { id: 3 },
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

    // The new messages are additive: the wire shapes are fixed, and the
    // existing messages keep their exact encoding.
    #[test]
    fn test_get_rules_wire_shapes() {
        assert_eq!(
            ClientMessage::GetRules.to_string().unwrap(),
            r#""GetRules""#
        );
        assert_eq!(
            ServerMessage::Rules { rules: vec![] }.to_string().unwrap(),
            r#"{"Rules":{"rules":[]}}"#
        );
        assert_eq!(
            ServerMessage::AlertCleared { id: 3 }.to_string().unwrap(),
            r#"{"AlertCleared":{"id":3}}"#
        );
        assert_eq!(
            ClientMessage::SetRules { rules: vec![] }
                .to_string()
                .unwrap(),
            r#"{"SetRules":{"rules":[]}}"#
        );
        assert_eq!(
            ClientMessage::Hello {
                protocol_version: 1
            }
            .to_string()
            .unwrap(),
            r#"{"Hello":{"protocol_version":1}}"#
        );
    }

    // A3 wire pins for the incremental rule edits, from an external
    // client's perspective: the exact JSON a non-Rust client (the desktop
    // app) sends decodes, and the encoded shapes stay frozen. The rule body
    // is rat-core's v2 camelCase format; Rule's serde defaults fill the
    // omitted fields (enabled/approved true, lifetime forever, created_at
    // epoch).
    #[test]
    fn test_add_remove_rule_wire_shapes() {
        let id: Uuid = "6ec0bd7f-11d0-4c7d-a9bf-96f16b1c3f2c"
            .parse()
            .expect("valid uuid");
        let add = ClientMessage::from_json_str(
            r#"{"AddRule":{"rule":{"id":"6ec0bd7f-11d0-4c7d-a9bf-96f16b1c3f2c","verdict":"deny","processPath":"/bin/added"}}}"#,
        )
        .expect("AddRule line decodes");
        match &add {
            ClientMessage::AddRule { rule } => {
                assert_eq!(rule.id, id);
                assert_eq!(rule.verdict, Verdict::Deny);
                assert_eq!(rule.process_path.as_deref(), Some("/bin/added"));
                assert!(rule.enabled && rule.approved, "serde defaults");
                assert_eq!(rule.lifetime, Lifetime::Forever);
                assert_eq!(
                    rule.created_at,
                    chrono::DateTime::from_timestamp(0, 0).expect("epoch"),
                    "created_at default"
                );
            }
            other => panic!("expected AddRule, got {other:?}"),
        }
        // The encoded form keeps the additive shape and the camelCase rule
        // body (what a client parsing the reply/echo expects).
        let encoded = add.to_string().expect("serialize AddRule");
        assert!(
            encoded.starts_with(r#"{"AddRule":{"rule":"#),
            "got {encoded}"
        );
        assert!(
            encoded.contains(r#""processPath":"/bin/added""#),
            "camelCase rule body, got {encoded}"
        );
        assert_eq!(
            ClientMessage::from_json_str(&encoded).expect("round trip"),
            add
        );

        let remove = ClientMessage::RemoveRule { id };
        assert_eq!(
            remove.to_string().expect("serialize RemoveRule"),
            r#"{"RemoveRule":{"id":"6ec0bd7f-11d0-4c7d-a9bf-96f16b1c3f2c"}}"#
        );
        assert_eq!(
            ClientMessage::from_json_str(
                r#"{"RemoveRule":{"id":"6ec0bd7f-11d0-4c7d-a9bf-96f16b1c3f2c"}}"#
            )
            .expect("RemoveRule line decodes"),
            remove
        );
    }

    // the split must be real — a client message type must not
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
