# rat-monitor-linux

A library for `rat` that acts as a `ConnectionSource` under Linux natively.

## Purpose

Since macOS requires XPC or Network Extensions and utilizes tools like `Little Snitch`, Linux can fulfill the exact same backend requirements of tracking process-metadata coupled to socket connections purely via standard kernel user-space APIs.

## Approach

1.  **Parse `/proc/net/tcp(6)` & `udp(6)`**:
    -   Reads the standard Linux pseudo-files for active connection addresses.
    -   Transforms memory dumped integers to valid IPv4/IPv6 formats efficiently avoiding panics.
2.  **Map INode to Process**:
    -   Queries `/proc/<pid>/fd` iterating to map open handles linking back to the kernel socket nodes (`socket:[inode]`).
    -   Resolves metadata by querying `comm`, `exe`, and `status`.
    -   Vanished processes (those closed during iteration mapping) are handled cleanly and silently omitted.
3.  **Netlink (TCP Stats)**:
    -   Requests socket level diagnostic dumps through `NETLINK_SOCK_DIAG` querying for `AF_INET` and `AF_INET6`.
    -   Bypasses typical enum breakages by decoding byte payloads dynamically for NLA info elements measuring `bytes_in` / `bytes_out`.
4.  **VPN Interface Checks**:
    -   Exposes `is_vpn_address(proc_root, addr)` via `route.rs`. Parses route tables resolving tun/tap prefix rules indicating VPN status for address assignments.
5.  **Mockability**:
    -   Accepts an injectable `/proc` root via `LinuxMonitor::new()` allowing comprehensive isolation limits for unit tests.

## Security and Permissions

This crate is capable of executing entirely in userspace without `root` or `CAP_NET_ADMIN` requirements unless mapping **other** user's processes via `pid` descriptors (which by standard POSIX permissions are guarded). Socket tracking metrics degrade gracefully.
