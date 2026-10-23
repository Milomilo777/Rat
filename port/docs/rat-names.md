# rat-names

## Purpose
The `rat-names` crate is responsible for reverse DNS resolution and port-to-service mapping for the Rat port. It provides an asynchronous-free (thread pool based) resolver with an LRU cache, strict timeouts to avoid blocking on slow DNS servers, and support for Internationalized Domain Names (IDN) through punycode and Unicode representations. It also handles mapping common transport layer ports to well-known service names.

## Public API Example
```rust
use std::net::IpAddr;
use rat_names::{Resolver, ResolverConfig, service_name};
use rat_types::Protocol;

// Initialize the resolver with default configuration
let config = ResolverConfig::default();
// NOTE: returns Err if cache_size is 0
let resolver = Resolver::new(config).unwrap();

// Resolve an IP address
let ip: IpAddr = "8.8.8.8".parse().unwrap();
if let Some(info) = resolver.resolve(ip) {
    println!("Domain: {} (Punycode: {})", info.display_name, info.punycode);
}

// Map a port to a common service name
if let Some(service) = service_name(443, Protocol::Tcp) {
    println!("Service on port 443 TCP is {}", service); // "HTTPS"
}
```

## Platform Notes
- Supported on Linux and Windows.
- No special root or administrator privileges are required to perform DNS lookups.
- Systemd-resolved integration (`org.freedesktop.resolve1`) is not implemented on Linux because the API does not support dumping the cache of recently resolved names.
- Windows `DnsGetCacheDataTable` is undocumented and thus not used to maintain stability.

## Known Limits
- Lookups that time out are strictly cached as "misses" for the duration of `negative_ttl` (default 60s) to prevent thread pool starvation on repeated failed lookups. Retries before TTL expiration will not hit the backend again.
- Lookups are strictly bounded by the `lookup_timeout`.
- Punycode equality is the standard for matching domain names (via `Eq`).
