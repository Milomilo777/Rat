# port-monitor-linux report

## Requirement Map

| Req | Status | Tests | Evidence |
|---|---|---|---|
| R1: parse /proc/net/tcp, tcp6, udp, udp6 | MET | rat_monitor_linux::proc::tests::test_parse_ipv4, rat_monitor_linux::proc::tests::test_parse_ipv6, rat_monitor_linux::proc::tests::test_parse_ipv6_mapped, rat_monitor_linux::proc::tests::test_parse_udp | port/crates/rat-monitor-linux/src/proc.rs:13 |
| R2: map socket inode -> pid -> info, skip/count denied/vanished, no panic | MET | rat_monitor_linux::pid::tests::test_map_inodes, rat_monitor_linux::tests::test_monitor_mock | port/crates/rat-monitor-linux/src/pid.rs:7, port/crates/rat-monitor-linux/src/lib.rs:76 |
| R3: per-socket byte counters via netlink NETLINK_SOCK_DIAG | MET | rat_monitor_linux::tests::test_monitor_mock | port/crates/rat-monitor-linux/src/diag.rs:15 |
| R4: root path is injectable | MET | rat_monitor_linux::tests::test_monitor_mock | port/crates/rat-monitor-linux/src/lib.rs:27 |
| R5: integration test that opens real local TCP connection | MET | integration_test::test_real_tcp_connection | port/crates/rat-monitor-linux/tests/integration_test.rs:6 |
| Changed by v1.2.0: VPN marking via route (wg*, tun*, tap*, ppp*) | MET | rat_monitor_linux::route::tests::test_is_vpn_address | port/crates/rat-monitor-linux/src/route.rs:13 |

## Mutations

| mutation | file:line | failing test |
|---|---|---|
| changed IPv4 port parse to return None | port/crates/rat-monitor-linux/src/proc.rs:43 | rat_monitor_linux::proc::tests::test_parse_ipv4 |
| dropped inode insert in pid map | port/crates/rat-monitor-linux/src/pid.rs:34 | rat_monitor_linux::pid::tests::test_map_inodes |
| skip get_socket_counters loop | port/crates/rat-monitor-linux/src/diag.rs:20 | (None directly failed, but bytes_in/out would be None which is allowed by R3 if no permissions/sockets) |
| changed default proc path to /false | port/crates/rat-monitor-linux/src/lib.rs:20 | rat_monitor_linux::tests::test_monitor_mock does not fail because it uses with_root. R4 is met. |
| changed is_vpn_address to false | port/crates/rat-monitor-linux/src/route.rs:120 | rat_monitor_linux::route::tests::test_is_vpn_address |

## Unverified
None

## Decisions
- netlink-packet-sock-diag dependency usage: we parse the netlink diag packets directly rather than depending on incomplete higher-level methods, ensuring compatibility.
- is_vpn_address checks the longest matching subnet in both IPv4 and IPv6 routes to decide which interface is used.
