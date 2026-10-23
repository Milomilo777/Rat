use rat_types::Protocol;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug, PartialEq, Eq)]
pub struct SocketInfo {
    pub inode: u64,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub listening: bool,
    pub protocol: Protocol,
}

pub fn parse_proc_net(content: &str, is_tcp: bool) -> Vec<SocketInfo> {
    let mut sockets = Vec::new();
    for line in content.lines().skip(1) {
        if let Some(sock) = parse_line(line, is_tcp) {
            sockets.push(sock);
        }
    }
    sockets
}

fn parse_line(line: &str, is_tcp: bool) -> Option<SocketInfo> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    let local = parse_address(parts[1])?;
    let remote = parse_address(parts[2])?;
    let state = u8::from_str_radix(parts[3], 16).ok()?;
    let inode = parts[9].parse::<u64>().ok()?;

    // For UDP, listening means "unconnected" (i.e. listening on all).
    // Usually if remote port is 0, we can say it's unconnected.
    let is_remote_unspecified = remote.ip().is_unspecified() && remote.port() == 0;

    let actual_remote = if is_remote_unspecified {
        None
    } else {
        Some(remote)
    };

    Some(SocketInfo {
        inode,
        local,
        remote: actual_remote,
        listening: if is_tcp {
            state == 0x0A
        } else {
            is_remote_unspecified
        },
        protocol: if is_tcp { Protocol::Tcp } else { Protocol::Udp },
    })
}

fn parse_address(s: &str) -> Option<SocketAddr> {
    let mut parts = s.split(':');
    let ip_hex = parts.next()?;
    let port_hex = parts.next()?;

    let port = u16::from_str_radix(port_hex, 16).ok()?;

    if ip_hex.len() == 8 {
        // IPv4
        let val = u32::from_str_radix(ip_hex, 16).ok()?;
        let ip = Ipv4Addr::from(val.to_le_bytes()); // Wait, to_le_bytes is correct because hex string is little endian byte sequence if viewed as u32.
        Some(SocketAddr::new(IpAddr::V4(ip), port))
    } else if ip_hex.len() == 32 {
        // IPv6 is 4 u32s.
        let bytes = hex::decode(ip_hex).ok()?;
        let mut ip_bytes = [0u8; 16];
        for i in 0..4 {
            let chunk = &bytes[i * 4..(i + 1) * 4];
            let val = u32::from_be_bytes(chunk.try_into().unwrap());
            ip_bytes[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
        }
        let ip = Ipv6Addr::from(ip_bytes);
        Some(SocketAddr::new(IpAddr::V6(ip), port))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1267 1 0000000000000000 100 0 0 10 0";
        let sockets = parse_proc_net(content, true);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].inode, 1267);
        assert_eq!(
            sockets[0].local.ip(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
        );
        assert_eq!(sockets[0].local.port(), 22);
    }

    #[test]
    fn test_parse_ipv6() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1268 1 0000000000000000 100 0 0 10 0";
        let sockets = parse_proc_net(content, true);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].inode, 1268);
        assert_eq!(sockets[0].local.ip(), IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert_eq!(sockets[0].local.port(), 22);
        assert_eq!(sockets[0].remote, None);
        assert_eq!(sockets[0].listening, true);
    }

    #[test]
    fn test_parse_ipv6_mapped() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0000000000000000FFFF00000100007F:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1269 1 0000000000000000 100 0 0 10 0";
        let sockets = parse_proc_net(content, true);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].inode, 1269);
    }

    #[test]
    fn test_parse_udp() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n  345: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4220 2 0000000000000000 0";
        let sockets = parse_proc_net(content, false);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].inode, 4220);
        assert_eq!(sockets[0].local.ip(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(sockets[0].local.port(), 68);
        assert_eq!(sockets[0].remote, None);
        assert_eq!(sockets[0].listening, true);
        assert_eq!(sockets[0].protocol, Protocol::Udp);
    }
}
