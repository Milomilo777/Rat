use criterion::{criterion_group, criterion_main, Criterion};
use rat_daemon::msg::Message;
use rat_types::{Connection, ProcessInfo, Protocol};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
        })
        .collect()
}

fn bench_serialization(c: &mut Criterion) {
    let connections = generate_connections(2000);
    let msg = Message::Snapshot { connections };

    c.bench_function("serialize_2000_snapshot", |b| {
        b.iter(|| {
            let s = msg.to_string().unwrap();
            black_box(s);
        })
    });
}

criterion_group!(benches, bench_serialization);
criterion_main!(benches);
