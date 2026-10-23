# Lane: port-monitor-linux

## Summary of Completed Work
Implemented the `rat-monitor-linux` crate in the `port/crates` workspace implementing the `ConnectionSource` trait to track and map network connections to process metadata natively on Linux. Met all specified requirements (R1-R5).

### Decisions and Approach

1. **R1: Parse `/proc/net/[tcp|tcp6|udp|udp6]`**
   - Implemented in `proc.rs`. Read lines from standard `/proc/net/` hex dumps.
   - Handled endianness carefully. Using `from_str_radix` natively outputs `u32` matching memory bounds. Converted via `to_ne_bytes` to initialize standard library `Ipv4Addr` as Linux dumps memory bytes per-field.
   - Handled IPv4-mapped IPv6 conversion logic so pure IPv6 connections and mapped IPs resolve properly to native `SocketAddr` equivalents.
   - Added exhaustive static string fixture tests verifying parsing.

2. **R2: Process Info mapping (`inode -> pid`)**
   - Implemented in `pid.rs`.
   - Iterated over `/proc/<pid>/fd/` for symlinks mimicking `socket:[inode]`.
   - Used robust `fs::read_dir` handling omitting vanished PIDs mid-scan (as they throw IO errors), counting them within `LinuxMonitor::vanished_count`.
   - Resolved process info elements from `exe`, `comm`, and `status`. Used `libc::getpwuid_r` to resolve username safely within Linux context, falling back gracefully.

3. **R3: Netlink byte counters**
   - Implemented in `diag.rs` using `netlink-sys` and `netlink-packet-core`.
   - Sent `INET_DIAG_INFO` requests directly into `NETLINK_SOCK_DIAG` domain natively asking for `AF_INET` and `AF_INET6` TCP connections.
   - Leveraged raw serialization for NLA fetching over fragile enums (worked around missing variants in older/newer `netlink-packet-sock-diag` by accessing payloads at known raw byte offsets: 120 and 128 for TCP stats based on `tcp_info`).

4. **R4: Injectable `/proc` root path**
   - Exposed `LinuxMonitor::new(PathBuf)` and leveraged `.join()` within all process polling and `proc/net` dumps, allowing future mocking without elevated capabilities. Default defaults to `/proc`.

5. **R5: Integration tests**
   - Implemented inside `tests/integration.rs`. Setup a background threaded `TcpListener` that receives an ongoing `TcpStream`.
   - Invoked `LinuxMonitor::sample()`, verified the returned TCP local bound endpoints match and have the correct matching PIDs associated to current application (`std::process::id()`).

6. **VPN Route Detection**
   - Implemented `is_vpn_address` using simple heuristics to query `/proc/net/route` and `/proc/net/ipv6_route` looking for interfaces corresponding to known tun/tap/wg/ppp VPN interfaces.

7. **Proptests & Fuzzing**
   - Added robust proptest and `cargo-fuzz` targets to ensure string parsing never panics unexpectedly on `/proc/net/*` arbitrary or malformed data. Fuzzer ran against native string slices safely.

8. **Cross Platform and Tooling constraints**
   - Used `cfg(target_os = "linux")` aggressively avoiding compiler checks failing on `x86_64-pc-windows-gnu` target testing.
   - Resolved all clippy lints successfully enforcing clean builds.

### Execution Output & Verification

Running `cargo test` yields clean passes across all test modules (Edge, Integration, Unit, and Proptest cases).
Checking windows cross-compilation `cargo check --target x86_64-pc-windows-gnu` completes successfully with no regressions.

Everything behaves correctly and no unsupported assumptions were made regarding `Configuration` bounds outside of provided scopes.
