# rat-core

## Purpose
`rat-core` is the central rule evaluation engine for the Rat firewall port. It provides a pure, platform-independent Rust implementation of Rat's rule evaluation logic, replicating the Swift `RatFilterCore` capabilities. It evaluates network connections against user-defined profiles, handles rule priorities based on specificity, and offers serialization for persistence.

## Public API

The primary interface involves configuring a `RuleEngine` with a `RuleSet` and evaluating connections via `evaluate`.

### Usage Example
```rust
use rat_core::{AppConnection, AppIdentity, PortRange, RuleEngine, Rule, Verdict, Lifetime};
use rat_types::Protocol;
use std::net::SocketAddr;
use uuid::Uuid;

let mut rule = Rule {
    id: Uuid::new_v4(),
    verdict: Verdict::Deny,
    process_path: Some("/usr/bin/curl".to_string()),
    signing_id: None,
    team_id: None,
    remote_domain: Some("example.com".to_string()),
    remote_host: None,
    remote_address: None,
    ports: Some(PortRange { start: 80, end: 443 }),
    proto: Some(Protocol::Tcp),
    enabled: true,
    approved: true,
    lifetime: Lifetime::Forever,
    profile_id: None,
    group_id: None,
    created_at: chrono::Utc::now(),
    note: None,
};

let engine = RuleEngine::with_rules(vec![rule], Verdict::Ask);

let process = AppIdentity::new(None, None, "/usr/bin/curl".to_string());
let connection = AppConnection::new(process, Some("example.com".to_string()), "93.184.216.34".to_string(), 443, Protocol::Tcp);

let verdict = engine.evaluate(&connection);
assert_eq!(verdict, Verdict::Deny);
```

## Platform Notes
- **Platform Agnostic:** The rule evaluation model runs purely in user-space and has no native system calls. It does not require root/admin privileges to parse rule files or execute evaluations.
- **Path Normalization:** On Windows targets, paths instantiated through `AppIdentity::normalized_path()` are lowercased and have backslashes replaced with forward slashes for unified case-insensitive matching logic against rules. On Linux, paths remain case-sensitive as evaluated by the system natively.

## Known Limits
- Domain-based rules perform simple suffix matching internally but do not perform DNS lookups proactively; they rely on connection intercepts passing the resolved or SNI-provided host correctly through the proxy/driver configuration.
- IP matching natively accounts for basic IPv4 and IPv4-mapped IPv6 equality. Advanced CIDR subnets are currently not natively structured in the base Rule configuration per current definitions.
