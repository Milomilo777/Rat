use std::collections::HashMap;

#[derive(Debug, Default, Clone, Copy)]
pub struct SocketCounters {
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
}

// Netlink alignment macro
#[cfg(target_os = "linux")]
macro_rules! nlmsg_align {
    ($len:expr) => {
        (($len) + 3) & !3
    };
}

#[cfg(target_os = "linux")]
pub fn get_socket_counters() -> HashMap<u64, SocketCounters> {
    use netlink_packet_core::{
        Emitable, NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST,
    };
    use netlink_packet_sock_diag::{
        inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
        SockDiagMessage, AF_INET, AF_INET6, IPPROTO_TCP,
    };
    use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

    let mut map = HashMap::new();

    let mut socket = match Socket::new(NETLINK_SOCK_DIAG) {
        Ok(s) => s,
        Err(_) => return map,
    };

    if socket.bind_auto().is_err() {
        return map;
    }

    for &family in &[AF_INET, AF_INET6] {
        let req = InetRequest {
            family,
            protocol: IPPROTO_TCP,
            extensions: ExtensionFlags::INFO,
            states: StateFlags::all(),
            socket_id: SocketId::new_v4(),
        };

        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | NLM_F_DUMP;

        let mut msg: NetlinkMessage<SockDiagMessage> =
            NetlinkMessage::new(header, NetlinkPayload::from(SockDiagMessage::InetRequest(req)));
        msg.finalize();

        let mut buf = vec![0; msg.header.length as usize];
        msg.serialize(&mut buf);

        let kernel_addr = SocketAddr::new(0, 0);
        if socket.send_to(&buf, &kernel_addr, 0).is_err() {
            continue;
        }

        let mut receive_buffer = vec![0; 8192];
        'outer: while let Ok((size, _)) = socket.recv_from(&mut receive_buffer, 0) {
            let mut offset = 0;
            while offset < size {
                let bytes = &receive_buffer[offset..];
                if let Ok(rx_msg) = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes) {
                    offset += nlmsg_align!(rx_msg.header.length as usize);

                    match rx_msg.payload {
                        NetlinkPayload::Done(_) | NetlinkPayload::Error(_) => {
                            break 'outer;
                        }
                        NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(res)) => {
                            let inode = res.header.inode;
                            let mut counters = SocketCounters::default();

                            for nla in res.nlas {
                                let mut nla_buf = vec![0; nla.buffer_len()];
                                nla.emit(&mut nla_buf);

                                if nla_buf.len() >= 4 {
                                    let nla_type =
                                        u16::from_ne_bytes(nla_buf[2..4].try_into().unwrap());
                                    // INET_DIAG_INFO = 2
                                    if nla_type == 2 && nla_buf.len() >= 4 + 136 {
                                        let payload = &nla_buf[4..];
                                        // 120 is bytes_acked (outbound)
                                        counters.bytes_out = Some(u64::from_ne_bytes(
                                            payload[120..128].try_into().unwrap(),
                                        ));
                                        // 128 is bytes_received (inbound)
                                        counters.bytes_in = Some(u64::from_ne_bytes(
                                            payload[128..136].try_into().unwrap(),
                                        ));
                                    }
                                }
                            }
                            map.insert(inode as u64, counters);
                        }
                        _ => {}
                    }
                } else {
                    break 'outer; // Unparseable
                }
            }
        }
    }

    map
}

#[cfg(not(target_os = "linux"))]
pub fn get_socket_counters() -> HashMap<u64, SocketCounters> {
    HashMap::new()
}
