use std::fs;
use std::net::IpAddr;
use std::path::Path;

/// Very basic heuristic to check if the route is a tunnel/VPN.
/// Scans /proc/net/route and /proc/net/ipv6_route looking for interfaces
/// that commonly represent VPNs (tun, tap, wg, ppp).
pub fn is_vpn_address(proc_root: &Path, _addr: IpAddr) -> bool {
    let route_paths = [
        proc_root.join("net/route"),
        proc_root.join("net/ipv6_route"),
    ];

    for path in &route_paths {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(iface) = parts.first() {
                    // Typical VPN interface prefixes
                    if iface.starts_with("tun")
                        || iface.starts_with("tap")
                        || iface.starts_with("wg")
                        || iface.starts_with("ppp")
                    {
                        return true;
                    }
                }
            }
        }
    }

    false
}
