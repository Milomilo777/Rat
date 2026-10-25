//! M5 (update-09): `Connection` gained a `via_vpn` field; pre-field JSON
//! (daemon snapshots, persisted ledgers) must keep decoding.

use rat_types::Connection;

#[test]
fn test_connection_json_without_via_vpn_still_decodes() {
    let legacy = r#"{"process":{"pid":1,"exe":null,"name":"a","user":null},"protocol":"Tcp","local":"127.0.0.1:1","remote":null,"listening":false,"bytes_in":null,"bytes_out":null}"#;
    let c: Connection = serde_json::from_str(legacy).expect("legacy JSON must decode");
    assert!(!c.via_vpn);

    let round: Connection =
        serde_json::from_str(&serde_json::to_string(&c).expect("serialize")).expect("round-trip");
    assert_eq!(round, c);
}
