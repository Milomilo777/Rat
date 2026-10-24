use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rat_names::{resolver::LookupBackend, Resolver, ResolverConfig};
use std::net::IpAddr;
use std::sync::Arc;

struct DummyBackend;

impl LookupBackend for DummyBackend {
    fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
        Some(format!("host-{}.com", ip))
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut config = ResolverConfig::default();
    config.cache_size = 5000; // fit 2000 cache entries easily
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

    // Performance budget: 2,000 lookups from cache in < 50ms (average time per lookup < 25 microseconds)
    c.bench_function("resolver_cache_hit_2000", |b| {
        b.iter(|| {
            for ip in &ips {
                resolver.resolve(black_box(*ip));
            }
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
