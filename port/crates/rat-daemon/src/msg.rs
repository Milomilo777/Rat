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

#[cfg(test)]
mod tests {
    use super::*;
    use rat_types::{ProcessInfo, Protocol};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_message_roundtrip() {
        let msg = Message::Hello { version: 1 };
        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: Message = serde_json::from_str(&serialized).unwrap();
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
        let serialized = serde_json::to_string(&snapshot).unwrap();
        let deserialized: Message = serde_json::from_str(&serialized).unwrap();
        assert_eq!(snapshot, deserialized);
    }
}
