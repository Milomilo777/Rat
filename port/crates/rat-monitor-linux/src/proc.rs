use rat_types::Protocol;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

#[derive(Debug, PartialEq, Eq)]
pub struct ProcNetEntry {
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub state: u8,
    pub inode: u64,
}

pub fn parse_proc_net(content: &str, protocol: Protocol) -> Vec<ProcNetEntry> {
    let mut entries = Vec::new();
    for line in content.lines().skip(1) {
        // Optimized split to avoid allocating Vec<&str> repeatedly
        let mut parts = line.split_whitespace();
        // parts layout: sl(0), local(1), remote(2), state(3), tx/rx(4), tr(5), tm->when(6), retrnsmt(7), uid(8), timeout(9), inode(10)
        let _sl = parts.next();
        let local_str = parts.next();
        let remote_str = parts.next();
        let state_str = parts.next();
        let _tx_rx = parts.next();
        let _tr = parts.next();
        let _tm = parts.next();
        let _retr = parts.next();
        let _uid = parts.next();
        let inode_str = parts.next();

        if let (Some(local_str), Some(remote_str), Some(state_str), Some(inode_str)) =
            (local_str, remote_str, state_str, inode_str)
        {
            let state = u8::from_str_radix(state_str, 16).unwrap_or(0);
            let inode = inode_str.parse::<u64>().unwrap_or(0);

            if let (Some(local), Some(remote)) =
                (parse_address(local_str), parse_address(remote_str))
            {
                // TCP_LISTEN is 0x0A (10), UDP unconnected uses 0.1 for state or remote 0.0.0.0
                let remote_addr = if (protocol == Protocol::Tcp && state == 10)
                    || (remote.ip().is_unspecified() && remote.port() == 0)
                {
                    None
                } else {
                    Some(remote)
                };
                entries.push(ProcNetEntry {
                    local,
                    remote: remote_addr,
                    state,
                    inode,
                });
            }
        }
    }
    entries
}

fn parse_address(addr: &str) -> Option<SocketAddr> {
    let mut parts = addr.split(':');
    let ip_hex = parts.next()?;
    let port_hex = parts.next()?;

    let port = u16::from_str_radix(port_hex, 16).ok()?;

    if ip_hex.len() == 8 {
        let ip_bytes = u32::from_str_radix(ip_hex, 16).ok()?;
        let ip = Ipv4Addr::from(ip_bytes.to_ne_bytes());
        Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
    } else if ip_hex.len() == 32 {
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let chunk = &ip_hex[i * 8..(i + 1) * 8];
            let chunk_val = u32::from_str_radix(chunk, 16).ok()?;
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&chunk_val.to_ne_bytes());
        }
        let ip = Ipv6Addr::from(bytes);

        if let Some(v4) = ip.to_ipv4_mapped() {
            Some(SocketAddr::V4(SocketAddrV4::new(v4, port)))
        } else {
            Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
    } else {
        None
    }
}
#[cfg(test)]
mod edge_tests {
    use super::*;

    #[test]
    fn test_parse_proc_net_empty() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
        let entries = parse_proc_net(content, Protocol::Tcp);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_proc_net_malformed() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: INVALID 00000000:0000 0A";
        let entries = parse_proc_net(content, Protocol::Tcp);
        assert!(entries.is_empty());
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn test_parse_proc_net_tcp4() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     \n   0: 0100007F:13AD 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 357890 1 0000000000000000 100 0 0 10 0\n   1: 0100007F:E646 0100007F:13AD 01 00000000:00000000 00:00000000 00000000  1000        0 358900 1 0000000000000000 20 4 30 10 -1";

        let entries = parse_proc_net(content, Protocol::Tcp);
        assert_eq!(entries.len(), 2);

        assert_eq!(
            entries[0].local,
            "127.0.0.1:5037".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(entries[0].remote, None);
        assert_eq!(entries[0].state, 10);
        assert_eq!(entries[0].inode, 357890);

        assert_eq!(
            entries[1].local,
            "127.0.0.1:58950".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            entries[1].remote,
            Some("127.0.0.1:5037".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(entries[1].state, 1);
        assert_eq!(entries[1].inode, 358900);
    }

    #[test]
    fn test_parse_proc_net_tcp6() {
        let content = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0000000000000000FFFF00000100007F:13AD 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 400000 1 0000000000000000 100 0 0 10 0\n   1: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 400001 1 0000000000000000 100 0 0 10 0";

        let entries = parse_proc_net(content, Protocol::Tcp);
        assert_eq!(entries.len(), 2);

        assert_eq!(
            entries[0].local,
            "127.0.0.1:5037".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(entries[0].remote, None);
        assert_eq!(entries[0].inode, 400000);

        assert_eq!(entries[1].local, "[::1]:22".parse::<SocketAddr>().unwrap());
        assert_eq!(entries[1].remote, None);
        assert_eq!(entries[1].inode, 400001);
    }

    #[test]
    fn test_parse_proc_net_udp() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     \n  13: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000    89        0 400002 2 0000000000000000 0";
        let entries = parse_proc_net(content, Protocol::Udp);
        assert_eq!(entries.len(), 1);

        assert_eq!(
            entries[0].local,
            "127.0.0.1:53".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(entries[0].remote, None);
        assert_eq!(entries[0].state, 7);
        assert_eq!(entries[0].inode, 400002);
    }
}
