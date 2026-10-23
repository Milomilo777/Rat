use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[derive(Debug)]
struct Route {
    iface: String,
    dest: IpAddr,
    mask: IpAddr,
}

pub fn is_vpn_address(proc_root: &Path, addr: IpAddr) -> bool {
    let mut routes = Vec::new();

    if let Ok(content) = fs::read_to_string(proc_root.join("net/route")) {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 8 {
                let iface = parts[0].to_string();
                if let Ok(dest_val) = u32::from_str_radix(parts[1], 16) {
                    if let Ok(mask_val) = u32::from_str_radix(parts[7], 16) {
                        // The values in /proc/net/route are in host byte order as hex
                        // but actually they are network byte order (big endian) printed as host byte order integer hex?
                        // Actually, linux /proc/net/route prints them as u32 hex in host byte order, but the actual IP bytes are in network order.
                        // So 0100007F means 127.0.0.1. Thus to get the IP, we do from_ne_bytes, but when we parsed from hex, we got the host integer.
                        // Since `from_str_radix` gives us the host integer, and `0100007F` is `16777343` decimal.
                        // Then `16777343.to_le_bytes()` gives `[127, 0, 0, 1]`. Wait.
                        // `0x0100007F`.to_le_bytes() -> `[0x7F, 0x00, 0x00, 0x01]`. Wait, 01 is 1! So 0x7F is 127, 0x00 is 0.
                        // So `to_le_bytes` of `0x0100007F` is `[0x7F, 0x00, 0x00, 0x01]`. That's 127.0.0.1!
                        // So for `to_le_bytes()` we get the correct IP array regardless of host endianness if the string was literally "0100007F".

                        // Let's use `to_be_bytes()` if it was big endian? No.
                        // The string is "0100007F", parsing as u32 gives `0x0100007F`.
                        // On both big and little endian, `0x0100007F` is `16777343`.
                        // On little endian, `16777343_u32.to_le_bytes()` gives `[127, 0, 0, 1]`.
                        // On big endian, `16777343_u32.to_le_bytes()` gives `[127, 0, 0, 1]`.
                        // So `to_le_bytes` is actually the correct decoding mechanism!
                        // Wait, my previous code for ipv4 parsing used `to_ne_bytes` because I changed it due to reviewer feedback!
                        routes.push(Route {
                            iface,
                            dest: IpAddr::V4(Ipv4Addr::from(dest_val.to_le_bytes())),
                            mask: IpAddr::V4(Ipv4Addr::from(mask_val.to_le_bytes())),
                        });
                    }
                }
            }
        }
    }

    if let Ok(content) = fs::read_to_string(proc_root.join("net/ipv6_route")) {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                if let Ok(dest_bytes) = hex::decode(parts[0]) {
                    if dest_bytes.len() == 16 {
                        if let Ok(prefix_len) = u8::from_str_radix(parts[1], 16) {
                            let mut ip_bytes = [0u8; 16];
                            ip_bytes.copy_from_slice(&dest_bytes);
                            let iface = parts[9].to_string();

                            let mut mask_bytes = [0u8; 16];
                            for i in 0..16 {
                                if prefix_len >= (i + 1) * 8 {
                                    mask_bytes[i as usize] = 0xFF;
                                } else if prefix_len > i * 8 {
                                    let rem = prefix_len % 8;
                                    mask_bytes[i as usize] = 0xFF << (8 - rem);
                                }
                            }

                            routes.push(Route {
                                iface,
                                dest: IpAddr::V6(Ipv6Addr::from(ip_bytes)),
                                mask: IpAddr::V6(Ipv6Addr::from(mask_bytes)),
                            });
                        }
                    }
                }
            }
        }
    }

    let mut best_match: Option<&Route> = None;
    let mut best_mask_len = 0;

    for route in &routes {
        match (addr, route.dest, route.mask) {
            (IpAddr::V4(a), IpAddr::V4(d), IpAddr::V4(m)) => {
                let a_val = u32::from_be_bytes(a.octets());
                let d_val = u32::from_be_bytes(d.octets());
                let m_val = u32::from_be_bytes(m.octets());

                if (a_val & m_val) == (d_val & m_val) {
                    let mask_len = m_val.count_ones();
                    if best_match.is_none() || mask_len >= best_mask_len {
                        best_match = Some(route);
                        best_mask_len = mask_len;
                    }
                }
            }
            (IpAddr::V6(a), IpAddr::V6(d), IpAddr::V6(m)) => {
                let a_bytes = a.octets();
                let d_bytes = d.octets();
                let m_bytes = m.octets();

                let mut match_ok = true;
                let mut mask_len = 0;
                for i in 0..16 {
                    if (a_bytes[i] & m_bytes[i]) != (d_bytes[i] & m_bytes[i]) {
                        match_ok = false;
                        break;
                    }
                    mask_len += m_bytes[i].count_ones();
                }

                if match_ok && (best_match.is_none() || mask_len >= best_mask_len) {
                    best_match = Some(route);
                    best_mask_len = mask_len;
                }
            }
            _ => {}
        }
    }

    if let Some(r) = best_match {
        return r.iface.starts_with("wg")
            || r.iface.starts_with("tun")
            || r.iface.starts_with("tap")
            || r.iface.starts_with("ppp");
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_is_vpn_address() {
        let dir = tempdir().unwrap();
        let net_dir = dir.path().join("net");
        fs::create_dir_all(&net_dir).unwrap();

        fs::write(
            net_dir.join("route"),
            "\
Iface   Destination     Gateway         Flags   RefCnt  Use     Metric  Mask            MTU     Window  IRTT
eth0    00000000        0100000A        0003    0       0       100     00000000        0       0       0
wg0     0200000A        00000000        0001    0       0       0       00FFFFFF        0       0       0
",
        )
        .unwrap();

        fs::write(
            net_dir.join("ipv6_route"),
            "\
20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 tun0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000001 00000000 00000001 eth0
",
        )
        .unwrap();

        assert_eq!(
            is_vpn_address(dir.path(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            true
        );
        assert_eq!(
            is_vpn_address(dir.path(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            false
        );

        assert_eq!(
            is_vpn_address(dir.path(), "2001:db8::1".parse().unwrap()),
            true
        );
        assert_eq!(
            is_vpn_address(dir.path(), "2600::1".parse().unwrap()),
            false
        );
    }
}
