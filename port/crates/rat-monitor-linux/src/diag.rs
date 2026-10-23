#[cfg(target_os = "linux")]
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, Nla as CoreNla, NLM_F_DUMP, NLM_F_REQUEST,
};
#[cfg(target_os = "linux")]
use netlink_packet_sock_diag::{
    inet::{nlas::Nla, ExtensionFlags, InetRequest, SocketId, StateFlags},
    SockDiagMessage, AF_INET, AF_INET6, IPPROTO_TCP,
};
#[cfg(target_os = "linux")]
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketCounters {
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
}

#[cfg(not(target_os = "linux"))]
pub fn get_socket_counters() -> HashMap<u64, SocketCounters> {
    HashMap::new()
}

#[cfg(target_os = "linux")]
pub fn get_socket_counters() -> HashMap<u64, SocketCounters> {
    let mut counters = HashMap::new();

    for family in [AF_INET, AF_INET6] {
        if let Ok(mut socket) = Socket::new(NETLINK_SOCK_DIAG) {
            let _ = socket.bind_auto();

            let request = InetRequest {
                family,
                protocol: IPPROTO_TCP,
                extensions: ExtensionFlags::INFO,
                states: StateFlags::all(),
                socket_id: SocketId::new_v4(),
            };

            let mut msg = NetlinkMessage::from(SockDiagMessage::InetRequest(request));
            msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
            msg.header.sequence_number = 1;

            msg.finalize();

            let mut buf = vec![0; msg.buffer_len()];
            msg.serialize(&mut buf);

            if socket.send(&buf, 0).is_ok() {
                let mut recv_buf = vec![0; 8192];
                // Use a loop counter to avoid infinite loops in mock tests
                let mut max_iters = 10000;
                'outer: loop {
                    max_iters -= 1;
                    if max_iters == 0 {
                        break;
                    }
                    let size = match socket.recv(&mut recv_buf, 0) {
                        Ok(size) => size,
                        Err(_) => break,
                    };
                    if size == 0 {
                        break;
                    }

                    let mut offset = 0;
                    while offset < size {
                        let rx_packet =
                            <NetlinkMessage<SockDiagMessage>>::deserialize(&recv_buf[offset..]);
                        let rx_msg = match rx_packet {
                            Ok(msg) => msg,
                            Err(_) => break 'outer,
                        };

                        match rx_msg.payload {
                            NetlinkPayload::Done(_) | NetlinkPayload::Error(_) => break 'outer,
                            NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(res)) => {
                                let inode = res.header.inode;

                                let mut bytes_in: Option<u64> = None;
                                let mut bytes_out: Option<u64> = None;

                                for nla in res.nlas {
                                    if let Nla::Other(default_nla) = nla {
                                        let kind = default_nla.kind();
                                        let mut info = vec![0; default_nla.value_len()];
                                        default_nla.emit_value(&mut info);

                                        if kind == 2 && info.len() >= 152 {
                                            // INET_DIAG_INFO
                                            let acked = u64::from_ne_bytes(
                                                info[136..144].try_into().unwrap(),
                                            );
                                            let received = u64::from_ne_bytes(
                                                info[144..152].try_into().unwrap(),
                                            );
                                            bytes_out = Some(acked);
                                            bytes_in = Some(received);
                                        }
                                    }
                                }

                                counters.insert(
                                    inode as u64,
                                    SocketCounters {
                                        bytes_in,
                                        bytes_out,
                                    },
                                );
                            }
                            _ => {}
                        }

                        let header_len = rx_msg.header.length as usize;
                        if header_len == 0 {
                            break 'outer;
                        }
                        offset += header_len;
                    }
                }
            }
        }
    }

    counters
}
