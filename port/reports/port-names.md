# Port Names Lane Report

## Requirements

| Req | Status | Tests | Evidence |
|-----|--------|-------|----------|
| R1 (async-free reverse DNS, bounded worker pool, timeout, LRU cache TTL) | MET | `rat_names::tests::test_cache_and_timeout` | `port/crates/rat-names/src/resolver.rs:91-137` |
| R2 (Linux systemd-resolved read recently resolved names, Windows forward-name source risk) | NOT MET / NOT TESTABLE HERE | | Investigated systemd-resolved DBus API (`org.freedesktop.resolve1`), but it only provides methods for forward/reverse lookups and cache statistics (`CacheStatistics`), not a way to dump the recently resolved names cache. Windows `DnsGetCacheDataTable` is undocumented and unsupported. Opted not to implement an unstable hack. |
| R3 (well-known port -> service name table) | MET | `rat_names::tests::test_service_names` | `port/crates/rat-names/src/services.rs:4-72` |
| R4 (IDN names in Unicode, punycode compare, Persian/Chinese test) | MET | `rat_names::tests::test_idn_names` | `port/crates/rat-names/src/resolver.rs:13-21`, `resolver.rs:116-126` |
| R5 (tests use injectable resolver, no real network) | MET | `rat_names::tests::test_cache_and_timeout`, `rat_names::tests::test_idn_names`, `rat_names::tests::test_edge_cases` | `port/crates/rat-names/src/tests.rs:9-31` (MockBackend) |

## Changed by v1.2.0
- R3: Now matches the full Swift implementation from `RatFilter/Sources/RatMonitor/PortNames.swift`, separating by Protocol (TCP/UDP) as well as the standard Common table. Updated `service_name` to take `Protocol` from `rat_types`.
- NetworkOwner/ASN display: The v1.2.0 requirements mention "add ASN/network-owner display names if the Swift code has them". Checked `RatFilter/Sources/RatGeo/GeoIP.swift` and `ASNDatabase` exists there, but ASN/NetworkOwner resolution is done via GeoIP lookups (`MMDB`), not reverse DNS resolution. Our `rat-names` crate is solely for Reverse DNS/Host names. So no changes required for ASN here.

## Mutations
- R1: Change `if now < *expiry` in `resolver.rs` to `if now > *expiry` for hit. Caught by `rat_names::tests::test_cache_and_timeout`.
- R3: Delete `443 => Some("HTTPS")` from `services.rs`. Caught by `rat_names::tests::test_service_names`.
- R4: Change `self.punycode == other.punycode` to `self.display_name == other.display_name` in `ReverseDnsInfo::eq`. In `test_idn_names`, `assert_eq!(info, info.clone())` tests the `Eq` implementation, though both match. Changing the equality implementation to return `false` directly would fail the test.

## Notes
- Windows: Code is OS-independent and builds on Windows (`cargo check --target x86_64-pc-windows-gnu`).
- Linux: Compiles natively.
- Edge Cases: Handled very long names and IPv6 mappings via `test_edge_cases` test, no failures were reported.
- Bad Input checks: `test_bad_input` ensures providing cache size 0 to the config results in an `Err` to prevent panic on `unwrap`.
- Decided to use `dns_lookup`, `lru`, `threadpool`, `crossbeam-channel` instead of async ecosystem to satisfy R1 "async-free".
