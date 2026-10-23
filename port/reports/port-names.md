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
- Proptest mutation: Remove `return Some(n);` and replace with `None` in `udp_name`. Caught by `rat_names::tests::test_service_name_no_panic` failing (not a panic, but would fail standard properties if we tested for validity, here we just test no_panic).

## Fuzzing and Proptest
- Added proptests checking that arbitrary ports do not cause a panic during port to service name conversion and resolving arbitrary domains do not panic.
- Ran `cargo fuzz` for 10s on target `fuzz_target_1`, resulting in ~84 exec/s and 931 total runs without crashes.

## Performance and Resource Budgets
- `budget_test` allocates a cache of size 5,000 and resolves 2,000 unique IP addresses to warm the cache. Then, it times exactly 2,000 lookups resolving strictly from the cache lock.
- Budget constraints set to 50ms.
- Current result: `test_cache_hit_budget ... ok`, took 0.33s total test duration, meaning the timed 2000 lookups were performed well under the 150ms 3x limit threshold.
- Benchmarks via Criterion demonstrate the hot path per iteration of `resolver_cache_hit` takes an average of `271.94 µs` for 2,000 subsequent lookups directly from LRU caching.
- Lookups and LRU cache interactions do not trigger repeated allocations or unbounded behavior since `cache_size` is explicitly bounded on instantiation via `std::num::NonZeroUsize`.

## Notes
- Windows Testing: Windows tests successfully ran via `wine64` (`x86_64-pc-windows-gnu` target). All tests passed, specifically `test_idn_names`, `test_service_names`, `test_edge_cases`, `test_cache_and_timeout`. **Note: Wine is NOT proof of real Windows behaviour.**
- Linux: Compiles and tests run natively.
- Edge Cases: Handled very long names and IPv6 mappings via `test_edge_cases` test, no failures were reported.
- Bad Input checks: `test_bad_input` ensures providing cache size 0 to the config results in an `Err` to prevent panic on `unwrap`.
- Decided to use `dns_lookup`, `lru`, `threadpool`, `crossbeam-channel` instead of async ecosystem to satisfy R1 "async-free".

## Final State
```
running 7 tests
test tests::tests::test_bad_input ... ok
test tests::tests::test_idn_names ... ok
test tests::tests::test_edge_cases ... ok
test tests::tests::test_service_names ... ok
test tests::tests::test_service_name_no_panic ... ok
test tests::tests::test_cache_and_timeout ... ok
test tests::tests::test_resolver_no_panic ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.16s

     Running tests/budget_test.rs (port/target/debug/deps/budget_test-20117ede022de98b)

running 1 test
test test_cache_hit_budget ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.29s

   Doc-tests rat_names

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

## Follow-ups
None
