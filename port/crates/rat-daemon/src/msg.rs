use rat_types::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Message {
    Hello { version: u32 },
    Snapshot { connections: Vec<Connection> },
    AlertRequest { id: u64, connection: Connection },
    AlertAnswer { id: u64, allow: bool },
    SetRules { rules: Vec<String> },
    Error { message: String },
}

#[derive(Debug, thiserror::Error)]
pub enum MsgError {
    #[error("Failed to serialize message: {0}")]
    SerializeError(#[from] serde_json::Error),
}

impl Message {
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

    #[test]
    fn test_message_roundtrip() {
        let msg = Message::Hello { version: 1 };
        let serialized = msg.to_string().expect("Serialize Hello failed");
        let deserialized = Message::from_json_str(&serialized).expect("Deserialize Hello failed");
        assert_eq!(msg, deserialized);

        let snapshot = Message::Snapshot {
            connections: vec![Connection {
                process: ProcessInfo {
                    pid: 1234,
                    exe: None,
                    name: "test".to_string(),
                    user: None,
                },
                protocol: Protocol::Tcp,
                local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
                remote: None,
                listening: true,
                bytes_in: Some(100),
                bytes_out: Some(200),
            }],
        };
        let serialized = snapshot.to_string().expect("Serialize Snapshot failed");
        let deserialized =
            Message::from_json_str(&serialized).expect("Deserialize Snapshot failed");
        assert_eq!(snapshot, deserialized);
    }

    #[test]
    fn test_bad_input() {
        let err = Message::from_json_str("not json");
        assert!(err.is_err());

        let err2 = Message::from_json_str(r#"{"BadVariant": 123}"#);
        assert!(err2.is_err());
    }
}
