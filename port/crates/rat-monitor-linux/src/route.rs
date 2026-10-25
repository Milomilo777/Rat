use std::fs;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;

pub fn is_vpn_address(proc_root: &Path, addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            // M6 (update-09): pick the LONGEST matching prefix over all
            // routes, then answer by that route's interface - a tun0 default
            // route must not mark LAN traffic as VPN when a more specific
            // non-VPN route exists.
            let target_v4 = u32::from_ne_bytes(v4.octets());
            let path = proc_root.join("net/route");
            let mut best_bits: i32 = -1;
            let mut best_is_vpn = false;
            if let Ok(content) = fs::read_to_string(path) {
                for line in content.lines().skip(1) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() < 8 {
                        continue;
                    }

                    let iface = parts[0];
                    if let (Ok(dest), Ok(mask)) = (
                        u32::from_str_radix(parts[1], 16),
                        u32::from_str_radix(parts[7], 16),
                    ) {
                        if (target_v4 & mask) == (dest & mask) {
                            let bits = mask.count_ones() as i32;
                            if bits > best_bits {
                                best_bits = bits;
                                best_is_vpn = is_vpn_iface(iface);
                            }
                        }
                    }
                }
            }
            best_is_vpn
        }
        IpAddr::V6(v6) => {
            let path = proc_root.join("net/ipv6_route");
            let mut best_bits: i32 = -1;
            let mut best_is_vpn = false;
            if let Ok(content) = fs::read_to_string(path) {
                for line in content.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() < 10 {
                        continue;
                    }

                    let dest_hex = parts[0];
                    let prefix_len_hex = parts[1];
                    let iface = parts[9];

                    if dest_hex.len() == 32 {
                        let mut dest_bytes = [0u8; 16];
                        let mut valid = true;
                        for i in 0..4 {
                            let chunk = &dest_hex[i * 8..(i + 1) * 8];
                            if let Ok(val) = u32::from_str_radix(chunk, 16) {
                                dest_bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
                            } else {
                                valid = false;
                            }
                        }

                        if valid {
                            if let Ok(prefix_len) = u32::from_str_radix(prefix_len_hex, 16) {
                                let dest_ip = Ipv6Addr::from(dest_bytes);
                                // M6 (update-09): longest prefix wins; a
                                // malformed prefix above 128 never matches
                                // (instead of indexing out of bounds).
                                if prefix_len <= 128
                                    && match_ipv6(v6, dest_ip, prefix_len)
                                    && prefix_len as i32 > best_bits
                                {
                                    best_bits = prefix_len as i32;
                                    best_is_vpn = is_vpn_iface(iface);
                                }
                            }
                        }
                    }
                }
            }
            best_is_vpn
        }
    }
}

fn is_vpn_iface(iface: &str) -> bool {
    iface.starts_with("tun")
        || iface.starts_with("tap")
        || iface.starts_with("wg")
        || iface.starts_with("ppp")
}

fn match_ipv6(target: Ipv6Addr, network: Ipv6Addr, prefix_len: u32) -> bool {
    let t_octets = target.octets();
    let n_octets = network.octets();

    let full_bytes = (prefix_len / 8) as usize;
    for i in 0..full_bytes {
        if t_octets[i] != n_octets[i] {
            return false;
        }
    }

    let remainder = prefix_len % 8;
    if remainder > 0 {
        let mask = 0xFF_u8 << (8 - remainder);
        if (t_octets[full_bytes] & mask) != (n_octets[full_bytes] & mask) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_vpn_route_matching_v4() {
        let temp_dir = tempfile::tempdir().unwrap();
        let net_dir = temp_dir.path().join("net");
        fs::create_dir_all(&net_dir).unwrap();

        let mut route_file = fs::File::create(net_dir.join("route")).unwrap();
        let content = "Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0100A8C0	0003	0	0	100	00000000	0	0	0
tun0	00000A0A	00000000	0001	0	0	0	00FFFFFF	0	0	0
";
        route_file.write_all(content.as_bytes()).unwrap();

        let addr1: IpAddr = "10.10.0.1".parse().unwrap();
        assert!(is_vpn_address(temp_dir.path(), addr1));

        let addr2: IpAddr = "192.168.0.1".parse().unwrap();
        assert!(!is_vpn_address(temp_dir.path(), addr2));
    }

    #[test]
    fn test_vpn_default_route_does_not_shadow_specific_route() {
        // M6 (update-09): tun0 owns the default route, eth0 the specific
        // 10.0.0.0/8 route - the specific route must win.
        let temp_dir = tempfile::tempdir().unwrap();
        let net_dir = temp_dir.path().join("net");
        fs::create_dir_all(&net_dir).unwrap();

        let mut route_file = fs::File::create(net_dir.join("route")).unwrap();
        let content = "Iface	Destination	Gateway	Flags	RefCnt	Use	Metric	Mask	MTU	Window	IRTT
tun0	00000000	00000000	0003	0	0	0	00000000	0	0	0
eth0	0000000A	00000000	0001	0	0	100	000000FF	0	0	0
";
        route_file.write_all(content.as_bytes()).unwrap();

        let lan: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(
            !is_vpn_address(temp_dir.path(), lan),
            "specific eth0 /8 route must beat the tun0 default route"
        );

        let wan: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(is_vpn_address(temp_dir.path(), wan));
    }

    #[test]
    fn test_v6_prefix_over_128_does_not_panic() {
        // M6 (update-09): a malformed prefix length above 128 must be
        // ignored, not index out of bounds.
        let temp_dir = tempfile::tempdir().unwrap();
        let net_dir = temp_dir.path().join("net");
        fs::create_dir_all(&net_dir).unwrap();

        let mut route_file = fs::File::create(net_dir.join("ipv6_route")).unwrap();
        let content = "00000000000000000000000000000000 81 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 00000001 tun0
";
        route_file.write_all(content.as_bytes()).unwrap();

        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(!is_vpn_address(temp_dir.path(), addr));
    }

    #[test]
    fn test_vpn_route_matching_v6() {
        let temp_dir = tempfile::tempdir().unwrap();
        let net_dir = temp_dir.path().join("net");
        fs::create_dir_all(&net_dir).unwrap();

        let mut route_file = fs::File::create(net_dir.join("ipv6_route")).unwrap();
        let content = "20010db8000000000000000000000000 20 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 00000001 wg0\n";
        route_file.write_all(content.as_bytes()).unwrap();

        let addr1: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(is_vpn_address(temp_dir.path(), addr1));

        let addr2: IpAddr = "fe80::1".parse().unwrap();
        assert!(!is_vpn_address(temp_dir.path(), addr2));
    }
}
