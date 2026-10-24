use rat_names::{resolver::LookupBackend, Resolver, ResolverConfig};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

struct DummyBackend;

impl LookupBackend for DummyBackend {
    fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
        Some(format!("host-{}.com", ip))
    }
}

#[test]
fn test_cache_hit_budget() {
    let config = ResolverConfig {
        cache_size: 5000,
        ..Default::default()
    };
    let backend = Arc::new(DummyBackend);
    let resolver = Resolver::with_backend(config, backend).unwrap();
    let mut ips: Vec<IpAddr> = Vec::new();
    for i in 0..2000 {
        let b = (i % 256) as u8;
        let a = (i / 256) as u8;
        let ip: IpAddr = format!("10.0.{}.{}", a, b).parse().unwrap();
        ips.push(ip);
        // warm up cache
        let _ = resolver.resolve(ip);
    }

    // Test performance 2000 lookups
    let start = Instant::now();
    for ip in &ips {
        resolver.resolve(*ip);
    }
    let duration = start.elapsed();

    // Budget is 50ms (50,000 microseconds)
    // Failing > 3x => 150ms
    assert!(
        duration.as_millis() < 150,
        "Budget exceeded! 2000 lookups took {}ms, maximum allowed is 150ms",
        duration.as_millis()
    );
}
