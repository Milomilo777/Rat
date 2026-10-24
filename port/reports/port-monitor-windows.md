# Lane port-monitor-windows Report

## Actions Taken
- Implemented `is_vpn_route` and `check_is_vpn_interface_type` based on Windows APIs (`GetBestInterfaceEx`, etc.) using `Win32_NetworkManagement_Ndis` from the `windows` crate, as per requirements for v1.2.0.
- Updated `port/crates/rat-monitor-windows/Cargo.toml` to depend on `Win32_NetworkManagement_Ndis`.

- Created `port/Cargo.toml` and `port/crates/rat-types` with the exact required content.
- Created `port/crates/rat-monitor-windows/Cargo.toml` with dependencies on `rat-types` and conditional Windows dependency.
- Implemented OS-independent functions `parse_port`, `convert_ipv4_addr`, `convert_ipv6_addr`, and `is_listening_state`.
- Added standard unit tests for OS-independent functions that run successfully on Linux.
- Implemented Windows connection sampling using `GetExtendedTcpTable` and `GetExtendedUdpTable` in `get_tcp_table_v4`, `get_tcp_table_v6`, `get_udp_table_v4`, and `get_udp_table_v6` with the correct `ERROR_INSUFFICIENT_BUFFER` retry loop.
- Implemented `get_process_info` mapping from PID to `ProcessInfo` using `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` and `QueryFullProcessImageNameW`.
- Implemented TCP per-connection bytes statistics via `GetPerTcpConnectionEStats` in `get_tcp_estats_v4` and `get_tcp_estats_v6`.
- Combined all components into a `WindowsMonitor` struct that implements `rat_types::ConnectionSource`.
- Resolved compilation issues regarding unused variables, correct Windows constants/structs, and formatting, to pass `cargo clippy --target x86_64-pc-windows-gnu -- -D warnings`.

## Unverified Claims
- UNVERIFIED: The runtime execution of the Windows API queries (`GetExtendedTcpTable`, `OpenProcess`, `GetPerTcpConnectionEStats`) has not been tested, as it can only be compiled on this Linux machine (`cargo check`).

## Verification Contract Requirements

| Req | Status | Tests | Evidence |
|---|---|---|---|
| R1 GetExtendedTcpTable / GetExtendedUdpTable for AF_INET and AF_INET6 with the OWNER_PID tables; the buffer-size retry loop is correct | MET | None (Windows API, UNVERIFIED at runtime) | `port/crates/rat-monitor-windows/src/lib.rs:88` |
| R2 pid -> exe via OpenProcess + QueryFullProcessImageNameW; access denied gives exe None; pid 0 and 4 are System Idle / System | MET | None (Windows API, UNVERIFIED at runtime) | `port/crates/rat-monitor-windows/src/lib.rs:222` |
| R3 per-connection bytes via GetPerTcpConnectionEStats (needs admin, record failure once) | MET | None (Windows API, UNVERIFIED at runtime) | `port/crates/rat-monitor-windows/src/lib.rs:309` |
| R4 raw MIB rows conversion in plain functions unit-tested on Linux | MET | `rat_monitor_windows::tests::test_parse_port`, `rat_monitor_windows::tests::test_convert_ipv4_addr`, `rat_monitor_windows::tests::test_convert_ipv6_addr`, `rat_monitor_windows::tests::test_is_listening_state` | `port/crates/rat-monitor-windows/src/lib.rs:8` |
| R5 `cargo check --target x86_64-pc-windows-gnu` and clippy pass; record that runtime was not tested | MET | None | Executed `cargo clippy --target x86_64-pc-windows-gnu` |

## Mutation Self-Check
- Mutation | `port/crates/rat-monitor-windows/src/lib.rs:8` (changed parse_port logic to use `from_le`) | `rat_monitor_windows::tests::test_parse_port`
- Mutation | `port/crates/rat-monitor-windows/src/lib.rs:13` (changed ipv4 parsing to `from([0,0,0,0])`) | `rat_monitor_windows::tests::test_convert_ipv4_addr`
- Mutation | `port/crates/rat-monitor-windows/src/lib.rs:17` (changed ipv6 parsing to `Ipv6Addr::UNSPECIFIED`) | `rat_monitor_windows::tests::test_convert_ipv6_addr`
- Mutation | `port/crates/rat-monitor-windows/src/lib.rs:26` (changed to `state == 3`) | `rat_monitor_windows::tests::test_is_listening_state`

## Changed by v1.2.0
- R6 Add a pure function that marks a connection as VPN when its best route uses a tunnel interface (`check_is_vpn_interface_type` & `is_vpn_route`), with unit tests on hand-built data.

## Mutation Self-Check for R6
- Mutation | `port/crates/rat-monitor-windows/src/lib.rs:598` (changed `53` to `99`) | `rat_monitor_windows::vpn_tests::test_check_is_vpn_interface_type`
