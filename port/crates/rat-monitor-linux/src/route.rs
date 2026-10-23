use std::fs;
use std::net::IpAddr;
use std::path::Path;

pub fn is_vpn_address(proc_root: &Path, addr: IpAddr) -> bool {
    let target_v4 = match addr {
        IpAddr::V4(v4) => u32::from_ne_bytes(v4.octets()),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                u32::from_ne_bytes(v4.octets())
            } else {
                return false; // IPv6 routing complex mapping skipped for brevity
            }
        }
    };

    let path = proc_root.join("net/route");
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 8 {
                continue;
            }

            let iface = parts[0];
            if iface.starts_with("tun")
                || iface.starts_with("tap")
                || iface.starts_with("wg")
                || iface.starts_with("ppp")
            {
                if let (Ok(dest), Ok(mask)) = (u32::from_str_radix(parts[1], 16), u32::from_str_radix(parts[7], 16)) {
                    // Check if addr matches network destination
                    if (target_v4 & mask) == (dest & mask) {
                        return true;
                    }
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_vpn_route_matching() {
        let temp_dir = tempfile::tempdir().unwrap();
        let net_dir = temp_dir.path().join("net");
        fs::create_dir_all(&net_dir).unwrap();

        let mut route_file = fs::File::create(net_dir.join("route")).unwrap();
        let content = "Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0100A8C0	0003	0	0	100	00000000	0	0	0
tun0	00000A0A	00000000	0001	0	0	0	00FFFFFF	0	0	0
";
        route_file.write_all(content.as_bytes()).unwrap();

        // 10.10.0.1 is 0x01000A0A
        let addr1: IpAddr = "10.10.0.1".parse().unwrap();
        assert!(is_vpn_address(temp_dir.path(), addr1));

        let addr2: IpAddr = "192.168.0.1".parse().unwrap();
        assert!(!is_vpn_address(temp_dir.path(), addr2));
    }
}
