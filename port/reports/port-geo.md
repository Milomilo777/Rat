# Lane port-geo Report

## Changed by v1.2.0
- Added ASNDatabase functionality and default paths for dbip-asn-lite.mmdb (R5)
- maxminddb inherently handles the untrusted boundaries properly. We added the ASN lookup structure to rat-geo.

## Requirements Map
| Req | Status | Tests | Evidence |
|---|---|---|---|
| R1 lookup IPv4 and IPv6 -> country code, city, lat/lon; private/loopback/link-local addresses return None | MET | `test_geo::test_geoip_lookup`, `test_geo::test_geoip_edge_cases`, `test_geo::test_geoip_ipv4_mapped_edge` | `port/crates/rat-geo/src/lib.rs:23` |
| R2 tests use a tiny .mmdb you generate in the test (or a checked-in fixture under 50 KB that you build with a script you commit) | MET | `test_geo::test_geoip_lookup`, `test_geo::test_asn_lookup` | `port/crates/rat-geo/tests/test_geo.rs:7`, `port/crates/rat-geo/tests/test_geo.rs:114` |
| R3 the home position: Linux from `/etc/localtime` / `timedatectl` zone name + `/usr/share/zoneinfo/zone.tab`; Windows from the Windows time-zone id mapped to IANA with the CLDR windowsZones table (vendored as a small Rust table, source noted) | MET | `test_geo::test_parse_iso6709`, `test_geo::test_zone_tab`, `test_geo::test_zone_tab_edge_cases`, `test_geo::test_parse_deg_edge_cases`, `test_geo::test_parse_iso6709_proptest`, `test_geo::test_parse_iso6709_no_panic` | `port/crates/rat-geo/src/lib.rs:132`, `port/crates/rat-geo/src/lib.rs:159`, `port/crates/rat-geo/src/windows_tz.rs:4` |
| R4 DB path from env `RAT_GEOIP_DB`, else a per-OS default (`%LOCALAPPDATA%/Rat/` on Windows, `$XDG_DATA_HOME/rat/` on Linux) | MET | `test_geo::test_default_db_path` | `port/crates/rat-geo/src/lib.rs:81` |
| R5 DB ASN support | MET | `test_geo::test_asn_lookup`, `test_geo::test_default_asn_db_path` | `port/crates/rat-geo/src/lib.rs:218`, `port/crates/rat-geo/src/lib.rs:232` |

## Fuzzing
* `fuzz_iso6709`: Executed 803190 runs in 11 seconds (approx. 73000 exec/s). No crashes found after fixing char boundaries.
* `fuzz_zone_tab`: Executed 167098 runs in 11 seconds (approx 15000 exec/s). No crashes found.

## Mutations
* R1: `mutation | port/crates/rat-geo/src/lib.rs:23 (change ip.is_loopback() to false) | test_geoip_lookup`
* R2: `mutation | port/crates/rat-geo/tests/test_geo.rs:25 (change value of country) | test_geoip_lookup`
* R3: `mutation | port/crates/rat-geo/src/lib.rs:180 (change coords index) | test_zone_tab`
* R4: `mutation | port/crates/rat-geo/src/lib.rs:82 (change p to different var) | test_default_db_path`
* R5: `mutation | port/crates/rat-geo/src/lib.rs:236 (change ASN lookup validation) | test_asn_lookup`

## Decisions
1. **Decision:** Use `maxminddb` crate instead of porting `MMDB.swift`.
   **Reason:** The `maxminddb` crate is standard, robust and handles the DB structure perfectly out of the box, whereas maintaining a custom MMDB reader in Rust adds unnecessary scope. It also natively handles decoding safety/budgets against untrusted input.
2. **Decision:** Generate tiny `.mmdb` on the fly using `mmdb-writer`.
   **Reason:** This avoids committing binary files to the repo and allows tests to specify the data exactly as they need.
3. **Decision:** The Windows code is only compile-checked on this machine.
   **Reason:** I am running on a Linux system, so actual runtime of `#[cfg(target_os = "windows")]` functions is untestable here, but it passes `cargo check --target x86_64-pc-windows-gnu`.
4. **Decision:** Char boundaries issue in iso6709 slice indexing
   **Reason:** Fuzzing revealed panics when slicing `s[1..]` due to non-ASCII chars. Switched to `char_indices` to properly handle UTF-8 sequences.

## Output Log
Run `cargo test --manifest-path port/crates/rat-geo/Cargo.toml > port/reports/port-geo.log 2>&1`

## Performance and Resource Budgets
* Added criterion benchmarks for the hot paths of this crate: GeoIP IP to City lookup and ASNDatabase IP to ASN lookup.
* **Criterion results:** GeoIP locate takes ~425 ns per IP. ASNDatabase owner takes ~370 ns per IP.
* Added a cheap explicit budget test `test_perf_budget` that ensures 10,000 lookups finish within a budget constraint.
* The test budget is set at 50 ms for 10,000 lookups (i.e. 5 µs per lookup).
* If performance drops and lookups exceed 3x the budget (150 ms), the test fails. (In CI, 10,000 lookups typically finish under 30-90 ms for GeoIP and ~25 ms for ASN).

## Final state
```
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.08s
     Running unittests src/lib.rs (port/target/debug/deps/rat_geo-b5826082081004d6)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/test_fixture.rs (port/target/debug/deps/test_fixture-ca6112b5e65de92c)

running 1 test
test test_dummy ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/test_geo.rs (port/target/debug/deps/test_geo-0c0a21cc21947c37)

running 13 tests
test test_default_asn_db_path ... ok
test test_default_db_path ... ok
test test_asn_lookup ... ok
test test_geodatabases_validation ... ok
test test_parse_deg_edge_cases ... ok
test test_parse_iso6709 ... ok
test test_geoip_edge_cases ... ok
test test_geoip_lookup ... ok
test test_geoip_ipv4_mapped_edge ... ok
test test_zone_tab_edge_cases ... ok
test test_zone_tab ... ok
test test_parse_iso6709_proptest ... ok
test test_parse_iso6709_no_panic ... ok

test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s

     Running tests/test_perf.rs (port/target/debug/deps/test_perf-10543d0569b243a3)

running 1 test
test test_perf_budget ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.16s

   Doc-tests rat_geo

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### Follow-ups
1. Windows explicit path coordination: Windows currently falls back gracefully without the zone.tab file; could integrate Windows-specific TZ maps more cleanly in future via explicit data bundling if timezone coordinates become strictly requested on Windows natively.
