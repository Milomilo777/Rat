//! Wire-format pins for the IPC/persistence types (the port-ci gate's
//! mutations all SURVIVED because the crate had no tests; these pin the
//! decode/encode contract the daemon and the app both rely on).

use rat_types::{Connection, ProcessInfo, Protocol};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

fn sample_connection() -> Connection {
    Connection {
        process: ProcessInfo {
            pid: 4711,
            exe: Some(PathBuf::from(r"C:\Program Files\app\app.exe")),
            name: "app.exe".to_string(),
            user: Some("OWNER".to_string()),
        },
        protocol: Protocol::Udp,
        local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 51000),
        remote: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443)),
        listening: false,
        bytes_in: Some(123_456),
        bytes_out: Some(654_321),
        via_vpn: true,
    }
}

#[test]
fn test_connection_round_trip_all_fields() {
    let c = sample_connection();
    let json = serde_json::to_string(&c).expect("serialize");
    let back: Connection = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, c);
}

#[test]
fn test_optional_fields_decode_from_null() {
    // Monitors emit null for exe/user/remote/bytes (listening sockets,
    // unconnected UDP, no estats source).
    let json = r#"{"process":{"pid":7,"exe":null,"name":"svchost.exe","user":null},"protocol":"Tcp","local":"0.0.0.0:135","remote":null,"listening":true,"bytes_in":null,"bytes_out":null}"#;
    let c: Connection = serde_json::from_str(json).expect("nulls must decode");
    assert!(c.process.exe.is_none());
    assert!(c.process.user.is_none());
    assert!(c.remote.is_none());
    assert!(c.bytes_in.is_none() && c.bytes_out.is_none());
    assert!(c.listening);
    assert!(!c.via_vpn);
}

#[test]
fn test_via_vpn_is_on_the_wire() {
    // the field is serialized (post-field readers see it), and pre-field
    // JSON still decodes (compat.rs pins that half).
    let json = serde_json::to_string(&sample_connection()).expect("serialize");
    assert!(json.contains(r#""via_vpn":true"#), "got {json}");
}

#[test]
fn test_protocol_wire_spellings() {
    // Canonical Rust spellings decode...
    assert_eq!(
        serde_json::from_str::<Protocol>(r#""Tcp""#).expect("Tcp"),
        Protocol::Tcp
    );
    assert_eq!(
        serde_json::from_str::<Protocol>(r#""Udp""#).expect("Udp"),
        Protocol::Udp
    );
    // ...Swift's lowercase raw values decode (aliases)...
    assert_eq!(
        serde_json::from_str::<Protocol>(r#""tcp""#).expect("tcp alias"),
        Protocol::Tcp
    );
    assert_eq!(
        serde_json::from_str::<Protocol>(r#""udp""#).expect("udp alias"),
        Protocol::Udp
    );
    // ...and the SERIALIZED form stays the canonical spelling (wire-format
    // a Swift-side consumer would need this).
    assert_eq!(
        serde_json::to_string(&Protocol::Tcp).expect("serialize Tcp"),
        r#""Tcp""#
    );
    assert_eq!(
        serde_json::to_string(&Protocol::Udp).expect("serialize Udp"),
        r#""Udp""#
    );
    // Anything else is rejected instead of guessed.
    assert!(serde_json::from_str::<Protocol>(r#""TCP""#).is_err());
    assert!(serde_json::from_str::<Protocol>(r#""icmp""#).is_err());
}
