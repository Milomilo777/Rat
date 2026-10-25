use rat_daemon::msg::ServerMessage;
use rat_types::{Connection, ProcessInfo, Protocol};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

fn generate_connections(count: usize) -> Vec<Connection> {
    (0..count)
        .map(|i| Connection {
            process: ProcessInfo {
                pid: (i % 10000) as u32,
                exe: None,
                name: format!("process_{}", i),
                user: None,
            },
            protocol: Protocol::Tcp,
            local: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                (1000 + i % 60000) as u16,
            ),
            remote: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                80,
            )),
            listening: false,
            bytes_in: Some(100),
            bytes_out: Some(200),
            via_vpn: false,
        })
        .collect()
}

#[test]
fn test_serialization_budget() {
    let connections = generate_connections(2000);
    let msg = ServerMessage::Snapshot { connections };

    let start = Instant::now();
    let s = msg.to_string().unwrap();
    let elapsed = start.elapsed();

    // Serialize a 2000 element snapshot shouldn't take more than 50ms in debug/test, usually takes 1ms.
    // We allow a large overhead 150ms just to be safe across CI machines, if it goes above that, it fails (3x of 50ms = 150ms).
    assert!(
        elapsed.as_millis() <= 150,
        "Serialization took too long: {} ms (budget 150 ms)",
        elapsed.as_millis()
    );

    // Simple memory size check on the string
    assert!(
        s.len() < 20 * 1024 * 1024,
        "Serialized size exceeded 20MB: {} bytes",
        s.len()
    );
}
