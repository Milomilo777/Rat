//! Windows implementation for rat-types connection source

#[cfg(windows)]
use rat_types::{Connection, ConnectionSource, Protocol};
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(windows)]
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

pub fn parse_port(port: u32) -> u16 {
    let port = port as u16;
    u16::from_be(port)
}

pub fn convert_ipv4_addr(addr: u32) -> Ipv4Addr {
    Ipv4Addr::from(addr.to_ne_bytes())
}

pub fn convert_ipv6_addr(addr: &[u8; 16]) -> Ipv6Addr {
    Ipv6Addr::from(*addr)
}

pub fn extract_process_name_from_path(path: Option<&std::path::Path>) -> String {
    if let Some(p) = path {
        let path_str = p.to_string_lossy();
        let name = path_str.split('\\').next_back().unwrap_or(&path_str);
        let name = name.split('/').next_back().unwrap_or(name);

        if name.is_empty() {
            "<unknown>".to_string()
        } else {
            name.to_string()
        }
    } else {
        "<unknown>".to_string()
    }
}

pub fn get_ipv6_scope_id(scope_id: u32) -> u32 {
    scope_id
}

pub fn is_listening_state(state: u32) -> bool {
    // MIB_TCP_STATE_LISTEN = 2
    state == 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_parse_port() {
        assert_eq!(parse_port(0xbb01), 443);
        assert_eq!(parse_port(0x5000), 80);
    }

    #[test]
    fn test_convert_ipv4_addr() {
        assert_eq!(convert_ipv4_addr(0x0100007f), Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn test_convert_ipv6_addr() {
        let addr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            convert_ipv6_addr(&addr),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)
        );
    }

    #[test]
    fn test_is_listening_state() {
        assert!(is_listening_state(2));
        assert!(!is_listening_state(1));
        assert!(!is_listening_state(5));
    }
}

#[cfg(windows)]
pub mod windows_sys {
    use std::ffi::c_void;
    use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, WIN32_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
        TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    pub fn get_tcp_table_v4() -> std::io::Result<Vec<MIB_TCPROW_OWNER_PID>> {
        let mut size = 0;
        let mut buffer = Vec::new();

        loop {
            let res = unsafe {
                GetExtendedTcpTable(
                    Some(buffer.as_mut_ptr() as *mut c_void),
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };

            if res == WIN32_ERROR(0).0 {
                break;
            } else if res == ERROR_INSUFFICIENT_BUFFER.0 {
                buffer.resize(size as usize, 0);
            } else {
                return Err(std::io::Error::from_raw_os_error(res as i32));
            }
        }

        if buffer.is_empty() {
            return Ok(Vec::new());
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID) };
        let count = table.dwNumEntries as usize;
        let slice = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), count) };

        Ok(slice.to_vec())
    }

    pub fn get_tcp_table_v6() -> std::io::Result<Vec<MIB_TCP6ROW_OWNER_PID>> {
        let mut size = 0;
        let mut buffer = Vec::new();

        loop {
            let res = unsafe {
                GetExtendedTcpTable(
                    Some(buffer.as_mut_ptr() as *mut c_void),
                    &mut size,
                    false,
                    AF_INET6.0 as u32,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };

            if res == WIN32_ERROR(0).0 {
                break;
            } else if res == ERROR_INSUFFICIENT_BUFFER.0 {
                buffer.resize(size as usize, 0);
            } else {
                return Err(std::io::Error::from_raw_os_error(res as i32));
            }
        }

        if buffer.is_empty() {
            return Ok(Vec::new());
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID) };
        let count = table.dwNumEntries as usize;
        let slice = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), count) };

        Ok(slice.to_vec())
    }

    pub fn get_udp_table_v4() -> std::io::Result<Vec<MIB_UDPROW_OWNER_PID>> {
        let mut size = 0;
        let mut buffer = Vec::new();

        loop {
            let res = unsafe {
                GetExtendedUdpTable(
                    Some(buffer.as_mut_ptr() as *mut c_void),
                    &mut size,
                    false,
                    AF_INET.0 as u32,
                    UDP_TABLE_OWNER_PID,
                    0,
                )
            };

            if res == WIN32_ERROR(0).0 {
                break;
            } else if res == ERROR_INSUFFICIENT_BUFFER.0 {
                buffer.resize(size as usize, 0);
            } else {
                return Err(std::io::Error::from_raw_os_error(res as i32));
            }
        }

        if buffer.is_empty() {
            return Ok(Vec::new());
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDPTABLE_OWNER_PID) };
        let count = table.dwNumEntries as usize;
        let slice = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), count) };

        Ok(slice.to_vec())
    }

    pub fn get_udp_table_v6() -> std::io::Result<Vec<MIB_UDP6ROW_OWNER_PID>> {
        let mut size = 0;
        let mut buffer = Vec::new();

        loop {
            let res = unsafe {
                GetExtendedUdpTable(
                    Some(buffer.as_mut_ptr() as *mut c_void),
                    &mut size,
                    false,
                    AF_INET6.0 as u32,
                    UDP_TABLE_OWNER_PID,
                    0,
                )
            };

            if res == WIN32_ERROR(0).0 {
                break;
            } else if res == ERROR_INSUFFICIENT_BUFFER.0 {
                buffer.resize(size as usize, 0);
            } else {
                return Err(std::io::Error::from_raw_os_error(res as i32));
            }
        }

        if buffer.is_empty() {
            return Ok(Vec::new());
        }

        let table = unsafe { &*(buffer.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID) };
        let count = table.dwNumEntries as usize;
        let slice = unsafe { std::slice::from_raw_parts(table.table.as_ptr(), count) };

        Ok(slice.to_vec())
    }
}

#[cfg(windows)]
pub mod process_info {
    use rat_types::ProcessInfo;
    use std::path::PathBuf;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED};
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    pub fn get_process_info(pid: u32) -> ProcessInfo {
        if pid == 0 {
            return ProcessInfo {
                pid,
                exe: None,
                name: "System Idle".to_string(),
                user: None,
            };
        } else if pid == 4 {
            return ProcessInfo {
                pid,
                exe: None,
                name: "System".to_string(),
                user: None,
            };
        }

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };

        match handle {
            Ok(h) => {
                let mut path_buf = [0u16; 1024];
                let mut size = path_buf.len() as u32;

                let exe = unsafe {
                    if QueryFullProcessImageNameW(
                        h,
                        windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0),
                        PWSTR(path_buf.as_mut_ptr()),
                        &mut size,
                    )
                    .is_ok()
                    {
                        let path_str = String::from_utf16_lossy(&path_buf[..size as usize]);
                        Some(PathBuf::from(&path_str))
                    } else {
                        None
                    }
                };

                let name = crate::extract_process_name_from_path(exe.as_deref());

                let _ = unsafe { CloseHandle(h) };

                ProcessInfo {
                    pid,
                    exe,
                    name,
                    user: None,
                }
            }
            Err(e) if e.code() == ERROR_ACCESS_DENIED.into() => {
                // Access denied usually happens for system processes, don't fail, just return what we know
                ProcessInfo {
                    pid,
                    exe: None,
                    name: "<unknown>".to_string(),
                    user: None,
                }
            }
            Err(_) => ProcessInfo {
                pid,
                exe: None,
                name: "<unknown>".to_string(),
                user: None,
            },
        }
    }
}

#[cfg(windows)]
pub mod stats {
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetPerTcp6ConnectionEStats, GetPerTcpConnectionEStats, TCP_ESTATS_DATA_ROD_v0,
        TcpConnectionEstatsData, MIB_TCP6ROW, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_LH,
        MIB_TCPROW_OWNER_PID,
    };

    pub fn get_tcp_estats_v4(row: &MIB_TCPROW_OWNER_PID) -> Result<(u64, u64), WIN32_ERROR> {
        let mut data = vec![0u8; std::mem::size_of::<TCP_ESTATS_DATA_ROD_v0>()];
        let res = unsafe {
            GetPerTcpConnectionEStats(
                row as *const _ as *const MIB_TCPROW_LH,
                TcpConnectionEstatsData,
                None,
                0,
                None,
                0,
                Some(&mut data),
                0,
            )
        };

        if res == WIN32_ERROR(0).0 {
            let data_struct = unsafe { &*(data.as_ptr() as *const TCP_ESTATS_DATA_ROD_v0) };
            Ok((data_struct.DataBytesIn, data_struct.DataBytesOut))
        } else {
            Err(WIN32_ERROR(res))
        }
    }

    pub fn get_tcp_estats_v6(row: &MIB_TCP6ROW_OWNER_PID) -> Result<(u64, u64), WIN32_ERROR> {
        let mut data = vec![0u8; std::mem::size_of::<TCP_ESTATS_DATA_ROD_v0>()];
        let res = unsafe {
            GetPerTcp6ConnectionEStats(
                row as *const _ as *const MIB_TCP6ROW,
                TcpConnectionEstatsData,
                None,
                0,
                None,
                0,
                Some(&mut data),
                0,
            )
        };

        if res == WIN32_ERROR(0).0 {
            let data_struct = unsafe { &*(data.as_ptr() as *const TCP_ESTATS_DATA_ROD_v0) };
            Ok((data_struct.DataBytesIn, data_struct.DataBytesOut))
        } else {
            Err(WIN32_ERROR(res))
        }
    }
}

#[cfg(windows)]
pub struct WindowsMonitor {
    estats_supported: bool,
    estats_checked: bool,
}

#[cfg(windows)]
impl Default for WindowsMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
impl WindowsMonitor {
    pub fn new() -> Self {
        Self {
            estats_supported: true,
            estats_checked: false,
        }
    }
}

#[cfg(windows)]
impl ConnectionSource for WindowsMonitor {
    fn sample(&mut self) -> std::io::Result<Vec<Connection>> {
        let mut connections = Vec::new();

        // TCP IPv4
        if let Ok(table) = windows_sys::get_tcp_table_v4() {
            for row in table {
                let local_ip = convert_ipv4_addr(row.dwLocalAddr);
                let local_port = parse_port(row.dwLocalPort);
                let local = SocketAddr::V4(SocketAddrV4::new(local_ip, local_port));

                let remote = if is_listening_state(row.dwState) {
                    None
                } else {
                    let remote_ip = convert_ipv4_addr(row.dwRemoteAddr);
                    let remote_port = parse_port(row.dwRemotePort);
                    Some(SocketAddr::V4(SocketAddrV4::new(remote_ip, remote_port)))
                };

                let mut bytes_in = None;
                let mut bytes_out = None;

                if self.estats_supported {
                    match stats::get_tcp_estats_v4(&row) {
                        Ok((bin, bout)) => {
                            self.estats_checked = true;
                            bytes_in = Some(bin);
                            bytes_out = Some(bout);
                        }
                        Err(e) => {
                            if !self.estats_checked {
                                if e == windows::Win32::Foundation::ERROR_ACCESS_DENIED
                                    || e == windows::Win32::Foundation::ERROR_NOT_SUPPORTED
                                {
                                    self.estats_supported = false;
                                }
                                self.estats_checked = true;
                            }
                        }
                    }
                }

                connections.push(Connection {
                    process: process_info::get_process_info(row.dwOwningPid),
                    protocol: Protocol::Tcp,
                    local,
                    remote,
                    listening: is_listening_state(row.dwState),
                    bytes_in,
                    bytes_out,
                });
            }
        }

        // TCP IPv6
        if let Ok(table) = windows_sys::get_tcp_table_v6() {
            for row in table {
                let local_ip = convert_ipv6_addr(&row.ucLocalAddr);
                let local_port = parse_port(row.dwLocalPort);
                let local = SocketAddr::V6(SocketAddrV6::new(
                    local_ip,
                    local_port,
                    0,
                    get_ipv6_scope_id(row.dwLocalScopeId),
                ));

                let remote = if is_listening_state(row.dwState) {
                    None
                } else {
                    let remote_ip = convert_ipv6_addr(&row.ucRemoteAddr);
                    let remote_port = parse_port(row.dwRemotePort);
                    Some(SocketAddr::V6(SocketAddrV6::new(
                        remote_ip,
                        remote_port,
                        0,
                        get_ipv6_scope_id(row.dwRemoteScopeId),
                    )))
                };

                let mut bytes_in = None;
                let mut bytes_out = None;

                if self.estats_supported {
                    match stats::get_tcp_estats_v6(&row) {
                        Ok((bin, bout)) => {
                            self.estats_checked = true;
                            bytes_in = Some(bin);
                            bytes_out = Some(bout);
                        }
                        Err(e) => {
                            if !self.estats_checked {
                                if e == windows::Win32::Foundation::ERROR_ACCESS_DENIED
                                    || e == windows::Win32::Foundation::ERROR_NOT_SUPPORTED
                                {
                                    self.estats_supported = false;
                                }
                                self.estats_checked = true;
                            }
                        }
                    }
                }

                connections.push(Connection {
                    process: process_info::get_process_info(row.dwOwningPid),
                    protocol: Protocol::Tcp,
                    local,
                    remote,
                    listening: is_listening_state(row.dwState),
                    bytes_in,
                    bytes_out,
                });
            }
        }

        // UDP IPv4
        if let Ok(table) = windows_sys::get_udp_table_v4() {
            for row in table {
                let local_ip = convert_ipv4_addr(row.dwLocalAddr);
                let local_port = parse_port(row.dwLocalPort);
                let local = SocketAddr::V4(SocketAddrV4::new(local_ip, local_port));

                connections.push(Connection {
                    process: process_info::get_process_info(row.dwOwningPid),
                    protocol: Protocol::Udp,
                    local,
                    remote: None,    // Unconnected UDP
                    listening: true, // Listening
                    bytes_in: None,
                    bytes_out: None,
                });
            }
        }

        // UDP IPv6
        if let Ok(table) = windows_sys::get_udp_table_v6() {
            for row in table {
                let local_ip = convert_ipv6_addr(&row.ucLocalAddr);
                let local_port = parse_port(row.dwLocalPort);
                let local = SocketAddr::V6(SocketAddrV6::new(local_ip, local_port, 0, 0));

                connections.push(Connection {
                    process: process_info::get_process_info(row.dwOwningPid),
                    protocol: Protocol::Udp,
                    local,
                    remote: None,
                    listening: true,
                    bytes_in: None,
                    bytes_out: None,
                });
            }
        }

        Ok(connections)
    }
}

#[cfg(windows)]
pub mod routes {
    use std::net::IpAddr;
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias,
    };
    use windows::Win32::NetworkManagement::IpHelper::{
        GetBestInterfaceEx, IF_TYPE_PROP_VIRTUAL, IF_TYPE_TUNNEL,
    };
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    pub fn is_vpn_route(remote: IpAddr) -> bool {
        let mut index = 0;
        let mut sockaddr_storage: [u8; 128] = [0; 128]; // Minimal representation of SOCKADDR_INET

        let _family = match remote {
            IpAddr::V4(v4) => {
                let addr = windows::Win32::Networking::WinSock::SOCKADDR_IN {
                    sin_family: windows::Win32::Networking::WinSock::AF_INET,
                    sin_port: 0,
                    sin_addr: windows::Win32::Networking::WinSock::IN_ADDR {
                        S_un: windows::Win32::Networking::WinSock::IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(v4.octets()),
                        },
                    },
                    sin_zero: [0; 8],
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &addr as *const _ as *const u8,
                        sockaddr_storage.as_mut_ptr(),
                        std::mem::size_of_val(&addr),
                    );
                }
                windows::Win32::Networking::WinSock::AF_INET
            }
            IpAddr::V6(v6) => {
                let addr = windows::Win32::Networking::WinSock::SOCKADDR_IN6 {
                    sin6_family: windows::Win32::Networking::WinSock::AF_INET6,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: windows::Win32::Networking::WinSock::IN6_ADDR {
                        u: windows::Win32::Networking::WinSock::IN6_ADDR_0 { Byte: v6.octets() },
                    },
                    Anonymous: windows::Win32::Networking::WinSock::SOCKADDR_IN6_0 {
                        sin6_scope_id: 0,
                    },
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        &addr as *const _ as *const u8,
                        sockaddr_storage.as_mut_ptr(),
                        std::mem::size_of_val(&addr),
                    );
                }
                windows::Win32::Networking::WinSock::AF_INET6
            }
        };

        let res = unsafe { GetBestInterfaceEx(sockaddr_storage.as_ptr() as *const _, &mut index) };

        if res != WIN32_ERROR(0).0 {
            return false;
        }

        let mut luid = NET_LUID_LH::default();
        if unsafe { ConvertInterfaceIndexToLuid(index, &mut luid).is_err() } {
            return false;
        }

        let mut alias = [0u16; 257]; // NDIS_IF_MAX_STRING_SIZE + 1
        if unsafe { ConvertInterfaceLuidToAlias(&luid, &mut alias).is_err() } {
            return false;
        }

        let alias_str = String::from_utf16_lossy(&alias).to_lowercase();

        // Check if interface type is virtual or tunnel by checking the high bits of luid Info
        let if_type = unsafe { luid.Info._bitfield >> 48 } as u32;
        if if_type == IF_TYPE_PROP_VIRTUAL || if_type == IF_TYPE_TUNNEL {
            return true;
        }

        if alias_str.contains("wintun") || alias_str.contains("wireguard") {
            return true;
        }

        false
    }
}

pub fn check_is_vpn_interface_type(if_type: u32, alias: &str) -> bool {
    // 53 is IF_TYPE_PROP_VIRTUAL, 131 is IF_TYPE_TUNNEL
    if if_type == 53 || if_type == 131 {
        return true;
    }

    let lower_alias = alias.to_lowercase();
    if lower_alias.contains("wintun") || lower_alias.contains("wireguard") {
        return true;
    }

    false
}

#[cfg(test)]
mod vpn_tests {
    use super::*;

    #[test]
    fn test_check_is_vpn_interface_type() {
        assert!(check_is_vpn_interface_type(53, "eth0"));
        assert!(check_is_vpn_interface_type(131, "tun0"));
        assert!(check_is_vpn_interface_type(6, "Wintun Userspace Tunnel"));
        assert!(check_is_vpn_interface_type(6, "wireguard1"));
        assert!(!check_is_vpn_interface_type(6, "Ethernet"));
    }
}

#[cfg(test)]
mod edge_case_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_extract_process_name_from_path() {
        assert_eq!(extract_process_name_from_path(None), "<unknown>");
        assert_eq!(
            extract_process_name_from_path(Some(Path::new(""))),
            "<unknown>"
        );

        // Windows paths with spaces
        assert_eq!(
            extract_process_name_from_path(Some(Path::new("C:\\Program Files\\My App\\app.exe"))),
            "app.exe"
        );

        // Very long names
        let long_name = "a".repeat(300) + ".exe";
        assert_eq!(
            extract_process_name_from_path(Some(Path::new(&long_name))),
            long_name
        );

        // Non-ASCII (Persian, Chinese)
        assert_eq!(
            extract_process_name_from_path(Some(Path::new("C:\\برنامه\\تست.exe"))),
            "تست.exe"
        );
        assert_eq!(
            extract_process_name_from_path(Some(Path::new("C:\\测试\\应用.exe"))),
            "应用.exe"
        );
    }

    #[test]
    fn test_ipv6_variations() {
        // Unspecified
        assert_eq!(convert_ipv6_addr(&[0; 16]), std::net::Ipv6Addr::UNSPECIFIED);

        // Scoped/link-local
        let link_local = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(convert_ipv6_addr(&link_local).is_unicast_link_local());

        // IPv4-mapped
        let ipv4_mapped = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1];
        assert!(convert_ipv6_addr(&ipv4_mapped).to_ipv4_mapped().is_some());
    }
}
