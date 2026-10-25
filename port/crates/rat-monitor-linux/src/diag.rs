//! Per-socket TCP byte counters from the kernel's `sock_diag` netlink interface.
//!
//! The wire format is built and parsed by pure functions (no syscalls, any
//! platform) so it can be unit tested on captured byte sequences; only
//! `get_socket_counters` talks to the kernel.
//!
//! ABI facts used (linux/netlink.h, linux/sock_diag.h, linux/inet_diag.h,
//! linux/tcp.h), all native-endian except ports/addresses inside `sockid`:
//! * `nlmsghdr` = 16 bytes: len u32, type u16, flags u16, seq u32, pid u32.
//! * `inet_diag_req_v2` = 56 bytes: family u8, protocol u8, ext u8, pad u8,
//!   states u32, `inet_diag_sockid` (48 bytes).
//! * `inet_diag_msg` = 72 bytes: family, state, timer, retrans (4 x u8),
//!   `inet_diag_sockid` (48), expires, rqueue, wqueue, uid, inode (5 x u32).
//!   Attributes (`nlattr`: len u16, type u16, 4-byte aligned) follow it.
//! * `idiag_ext` bit for `INET_DIAG_INFO` (2) is `1 << (2 - 1)`.
//! * `tcp_info.tcpi_bytes_acked` is at offset 120 and `tcpi_bytes_received`
//!   at offset 128 (both u64).

use std::collections::HashMap;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SocketCounters {
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
}

const NLMSG_HDR_LEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300;
const INET_DIAG_REQ_LEN: usize = 56;
const INET_DIAG_MSG_LEN: usize = 72;
const INET_DIAG_MSG_INODE_OFFSET: usize = 68;
const INET_DIAG_INFO: u16 = 2;
const NLA_TYPE_MASK: u16 = 0x3fff;
const TCPI_BYTES_ACKED: usize = 120;
const TCPI_BYTES_RECEIVED: usize = 128;
const TCPI_MIN_LEN: usize = 136;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(off..off + 2)?.try_into().ok()?))
}

fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(off..off + 4)?.try_into().ok()?))
}

fn rd_u64(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// Build a `SOCK_DIAG_BY_FAMILY` dump request for all TCP sockets of `family`
/// (`AF_INET` = 2 or `AF_INET6` = 10) asking for `INET_DIAG_INFO`.
pub fn build_request(family: u8, seq: u32) -> Vec<u8> {
    let total = NLMSG_HDR_LEN + INET_DIAG_REQ_LEN;
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&(total as u32).to_ne_bytes());
    buf.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    // inet_diag_req_v2
    buf.push(family);
    buf.push(6); // IPPROTO_TCP
    buf.push(1 << (INET_DIAG_INFO - 1)); // idiag_ext
    buf.push(0); // pad
    buf.extend_from_slice(&0xffff_ffffu32.to_ne_bytes()); // every TCP state
    buf.extend_from_slice(&[0u8; 40]); // sockid: ports, addrs, if (wildcards)
    buf.extend_from_slice(&0xffff_ffffu32.to_ne_bytes()); // cookie (NOCOOKIE)
    buf.extend_from_slice(&0xffff_ffffu32.to_ne_bytes());
    debug_assert_eq!(buf.len(), total);
    buf
}

/// Counters out of a `tcp_info` blob; `None` when the blob is too short to
/// contain `tcpi_bytes_received` (kernel older than 4.1).
pub fn parse_tcp_info(info: &[u8]) -> Option<SocketCounters> {
    if info.len() < TCPI_MIN_LEN {
        return None;
    }
    Some(SocketCounters {
        bytes_out: Some(rd_u64(info, TCPI_BYTES_ACKED)?),
        bytes_in: Some(rd_u64(info, TCPI_BYTES_RECEIVED)?),
    })
}

/// Result of feeding one `recv` buffer to [`parse_messages`].
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// More datagrams follow.
    More,
    /// `NLMSG_DONE` or `NLMSG_ERROR` seen: the dump is over.
    Done,
}

/// Walk every netlink message in `buf`, adding `inode -> counters` entries.
pub fn parse_messages(buf: &[u8], out: &mut HashMap<u64, SocketCounters>) -> Parsed {
    let mut off = 0usize;
    while off + NLMSG_HDR_LEN <= buf.len() {
        let len = match rd_u32(buf, off) {
            Some(l) => l as usize,
            None => break,
        };
        let ty = rd_u16(buf, off + 4).unwrap_or(0);
        if len < NLMSG_HDR_LEN || off + len > buf.len() {
            break;
        }
        let payload = &buf[off + NLMSG_HDR_LEN..off + len];
        match ty {
            NLMSG_DONE | NLMSG_ERROR => return Parsed::Done,
            SOCK_DIAG_BY_FAMILY => {
                if let Some((inode, c)) = parse_inet_diag_msg(payload) {
                    out.insert(inode, c);
                }
            }
            _ => {}
        }
        off += align4(len);
    }
    Parsed::More
}

fn parse_inet_diag_msg(payload: &[u8]) -> Option<(u64, SocketCounters)> {
    if payload.len() < INET_DIAG_MSG_LEN {
        return None;
    }
    let inode = rd_u32(payload, INET_DIAG_MSG_INODE_OFFSET)? as u64;
    let mut counters = SocketCounters::default();
    let mut off = INET_DIAG_MSG_LEN;
    while off + 4 <= payload.len() {
        let alen = rd_u16(payload, off)? as usize;
        let aty = rd_u16(payload, off + 2)? & NLA_TYPE_MASK;
        if alen < 4 || off + alen > payload.len() {
            break;
        }
        if aty == INET_DIAG_INFO {
            if let Some(c) = parse_tcp_info(&payload[off + 4..off + alen]) {
                counters = c;
            }
        }
        off += align4(alen);
    }
    Some((inode, counters))
}

#[cfg(target_os = "linux")]
pub fn get_socket_counters() -> HashMap<u64, SocketCounters> {
    let mut map = HashMap::new();
    // SAFETY: plain syscalls on a descriptor owned here and closed below;
    // every pointer passed refers to a live local buffer of the stated length.
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            4, /* NETLINK_SOCK_DIAG */
        );
        if fd < 0 {
            return map;
        }
        let tv = libc::timeval {
            tv_sec: 2,
            tv_usec: 0,
        };
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        let mut kernel: libc::sockaddr_nl = std::mem::zeroed();
        kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;

        let mut rx = vec![0u8; 65536];
        for (seq, family) in [libc::AF_INET, libc::AF_INET6].iter().enumerate() {
            let req = build_request(*family as u8, seq as u32 + 1);
            let sent = libc::sendto(
                fd,
                req.as_ptr() as *const libc::c_void,
                req.len(),
                0,
                &kernel as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            );
            if sent < 0 {
                continue;
            }
            loop {
                let n = libc::recv(fd, rx.as_mut_ptr() as *mut libc::c_void, rx.len(), 0);
                if n <= 0 {
                    break;
                }
                if parse_messages(&rx[..n as usize], &mut map) == Parsed::Done {
                    break;
                }
            }
        }
        libc::close(fd);
    }
    map
}

#[cfg(not(target_os = "linux"))]
pub fn get_socket_counters() -> HashMap<u64, SocketCounters> {
    HashMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_info(acked: u64, received: u64, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        v[TCPI_BYTES_ACKED..TCPI_BYTES_ACKED + 8].copy_from_slice(&acked.to_ne_bytes());
        v[TCPI_BYTES_RECEIVED..TCPI_BYTES_RECEIVED + 8].copy_from_slice(&received.to_ne_bytes());
        v
    }

    fn nla(ty: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
        v.extend_from_slice(&ty.to_ne_bytes());
        v.extend_from_slice(payload);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    fn diag_msg(inode: u32, attrs: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; INET_DIAG_MSG_LEN];
        body[0] = 2; // AF_INET
        body[INET_DIAG_MSG_INODE_OFFSET..INET_DIAG_MSG_INODE_OFFSET + 4]
            .copy_from_slice(&inode.to_ne_bytes());
        body.extend_from_slice(attrs);
        nlmsg(SOCK_DIAG_BY_FAMILY, &body)
    }

    fn nlmsg(ty: u16, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&((NLMSG_HDR_LEN + body.len()) as u32).to_ne_bytes());
        v.extend_from_slice(&ty.to_ne_bytes());
        v.extend_from_slice(&2u16.to_ne_bytes()); // NLM_F_MULTI
        v.extend_from_slice(&[0u8; 8]);
        v.extend_from_slice(body);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn request_layout_matches_abi() {
        let r = build_request(2, 7);
        assert_eq!(r.len(), 72);
        assert_eq!(rd_u32(&r, 0), Some(72));
        assert_eq!(rd_u16(&r, 4), Some(20));
        assert_eq!(rd_u16(&r, 6), Some(0x301));
        assert_eq!(rd_u32(&r, 8), Some(7));
        assert_eq!(&r[16..20], &[2, 6, 2, 0]);
        assert_eq!(rd_u32(&r, 20), Some(0xffff_ffff));
        let v6 = build_request(10, 1);
        assert_eq!(v6[16], 10);
    }

    #[test]
    fn tcp_info_offsets() {
        let c = parse_tcp_info(&tcp_info(1_048_577, 42, 232)).unwrap();
        assert_eq!(c.bytes_out, Some(1_048_577));
        assert_eq!(c.bytes_in, Some(42));
        assert!(parse_tcp_info(&tcp_info(1, 2, 135 + 1)).is_some());
        assert!(parse_tcp_info(&[0u8; 135]).is_none());
    }

    #[test]
    fn parses_multipart_dump_with_other_attributes() {
        let attrs_a = [
            nla(1, &[0u8; 8]), // INET_DIAG_MEMINFO-like filler
            nla(INET_DIAG_INFO, &tcp_info(1_048_577, 9, 232)),
            nla(3, &[1, 2, 3]), // unaligned length, padded
        ]
        .concat();
        let attrs_b = nla(INET_DIAG_INFO, &tcp_info(5, 6, 136));
        let mut first = diag_msg(13161, &attrs_a);
        first.extend(diag_msg(777, &attrs_b));
        let mut map = HashMap::new();
        assert_eq!(parse_messages(&first, &mut map), Parsed::More);
        assert_eq!(map[&13161].bytes_out, Some(1_048_577));
        assert_eq!(map[&13161].bytes_in, Some(9));
        assert_eq!(map[&777].bytes_out, Some(5));

        let mut second = diag_msg(1, &[]);
        second.extend(nlmsg(NLMSG_DONE, &0i32.to_ne_bytes()));
        second.extend(diag_msg(2, &[])); // after DONE: ignored
        assert_eq!(parse_messages(&second, &mut map), Parsed::Done);
        assert_eq!(map[&1], SocketCounters::default());
        assert!(!map.contains_key(&2));
    }

    #[test]
    fn truncated_and_garbage_input_is_safe() {
        let msg = diag_msg(5, &nla(INET_DIAG_INFO, &tcp_info(1, 2, 232)));
        for cut in 0..msg.len() {
            let mut map = HashMap::new();
            let _ = parse_messages(&msg[..cut], &mut map);
        }
        let mut map = HashMap::new();
        assert_eq!(parse_messages(&[0xff; 64], &mut map), Parsed::More);
        assert!(map.is_empty());
    }

    #[test]
    fn error_message_ends_dump() {
        let mut map = HashMap::new();
        let m = nlmsg(NLMSG_ERROR, &(-1i32).to_ne_bytes());
        assert_eq!(parse_messages(&m, &mut map), Parsed::Done);
    }
}
