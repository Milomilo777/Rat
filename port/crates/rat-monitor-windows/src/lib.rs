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
        // u32-aligned storage for the table cast (a Vec<u8>
        // is only 1-aligned), and the size query passes NULL, not a dangling
        // non-null pointer.
        let mut buffer: Vec<u32> = Vec::new();

        loop {
            let res = unsafe {
                GetExtendedTcpTable(
                    if buffer.is_empty() {
                        None
                    } else {
                        Some(buffer.as_mut_ptr() as *mut c_void)
                    },
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
                buffer.resize((size as usize).div_ceil(4), 0);
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
        // u32-aligned storage for the table cast (a Vec<u8>
        // is only 1-aligned), and the size query passes NULL, not a dangling
        // non-null pointer.
        let mut buffer: Vec<u32> = Vec::new();

        loop {
            let res = unsafe {
                GetExtendedTcpTable(
                    if buffer.is_empty() {
                        None
                    } else {
                        Some(buffer.as_mut_ptr() as *mut c_void)
                    },
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
                buffer.resize((size as usize).div_ceil(4), 0);
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
        // u32-aligned storage for the table cast (a Vec<u8>
        // is only 1-aligned), and the size query passes NULL, not a dangling
        // non-null pointer.
        let mut buffer: Vec<u32> = Vec::new();

        loop {
            let res = unsafe {
                GetExtendedUdpTable(
                    if buffer.is_empty() {
                        None
                    } else {
                        Some(buffer.as_mut_ptr() as *mut c_void)
                    },
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
                buffer.resize((size as usize).div_ceil(4), 0);
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
        // u32-aligned storage for the table cast (a Vec<u8>
        // is only 1-aligned), and the size query passes NULL, not a dangling
        // non-null pointer.
        let mut buffer: Vec<u32> = Vec::new();

        loop {
            let res = unsafe {
                GetExtendedUdpTable(
                    if buffer.is_empty() {
                        None
                    } else {
                        Some(buffer.as_mut_ptr() as *mut c_void)
                    },
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
                buffer.resize((size as usize).div_ceil(4), 0);
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
    use windows::core::PCWSTR;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, HANDLE, PSID};
    use windows::Win32::Security::{
        GetTokenInformation, LookupAccountSidW, TokenUser, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// `DOMAIN\user` (or `user` when the domain is empty) of the process
    /// token. `None` on access denied or any failed call: never a panic.
    /// The token handle is always closed; `process` stays owned by the caller.
    fn process_user(process: HANDLE) -> Option<String> {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) }.ok()?;
        let user = token_user(token);
        let _ = unsafe { CloseHandle(token) };
        user
    }

    fn token_user(token: HANDLE) -> Option<String> {
        let mut needed = 0u32;
        // First call only sizes the buffer (fails with INSUFFICIENT_BUFFER).
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
        if needed == 0 || needed > 1 << 16 {
            return None;
        }
        // u64 elements keep the TOKEN_USER header aligned.
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                (buf.len() * 8) as u32,
                &mut needed,
            )
        }
        .ok()?;
        let sid: PSID = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };

        let mut name = [0u16; 256];
        let mut domain = [0u16; 256];
        let mut name_len = name.len() as u32;
        let mut domain_len = domain.len() as u32;
        let mut kind = SID_NAME_USE(0);
        unsafe {
            LookupAccountSidW(
                PCWSTR::null(),
                sid,
                PWSTR(name.as_mut_ptr()),
                &mut name_len,
                PWSTR(domain.as_mut_ptr()),
                &mut domain_len,
                &mut kind,
            )
        }
        .ok()?;
        let name = String::from_utf16_lossy(&name[..name_len as usize]);
        let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
        if name.is_empty() {
            None
        } else if domain.is_empty() {
            Some(name)
        } else {
            Some(format!("{domain}\\{name}"))
        }
    }

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

                let user = process_user(h);

                let _ = unsafe { CloseHandle(h) };

                ProcessInfo {
                    pid,
                    exe,
                    name,
                    user,
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

/// API-level conditions that disable estats for the whole
/// process (no admin rights / OS support) - but only for rows a real
/// process owns: kernel rows (pid 0, e.g. TIME_WAIT) answer NOT_SUPPORTED
/// for row-class reasons, which is per-row, not global. Takes the raw
/// Win32 error code so the rule is testable on every platform (ci-04).
pub fn estats_error_is_global(win32_error: u32, owning_pid: u32) -> bool {
    const ERROR_ACCESS_DENIED: u32 = 5;
    const ERROR_NOT_SUPPORTED: u32 = 50;
    owning_pid != 0 && (win32_error == ERROR_ACCESS_DENIED || win32_error == ERROR_NOT_SUPPORTED)
}

#[cfg(windows)]
pub mod stats {
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetPerTcp6ConnectionEStats, GetPerTcpConnectionEStats, SetPerTcp6ConnectionEStats,
        SetPerTcpConnectionEStats, TCP_ESTATS_DATA_ROD_v0, TCP_ESTATS_DATA_RW_v0,
        TcpConnectionEstatsData, MIB_TCP6ROW, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_LH,
        MIB_TCPROW_OWNER_PID,
    };

    pub fn get_tcp_estats_v4(row: &MIB_TCPROW_OWNER_PID) -> Result<(u64, u64), WIN32_ERROR> {
        // the ROD carries u64 counters; read it through
        // 8-aligned storage instead of an align-1 Vec<u8>.
        let mut data_storage =
            vec![0u64; std::mem::size_of::<TCP_ESTATS_DATA_ROD_v0>().div_ceil(8)];
        let mut data = unsafe {
            std::slice::from_raw_parts_mut(
                data_storage.as_mut_ptr() as *mut u8,
                data_storage.len() * 8,
            )
        };
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
        // the ROD carries u64 counters; read it through
        // 8-aligned storage instead of an align-1 Vec<u8>.
        let mut data_storage =
            vec![0u64; std::mem::size_of::<TCP_ESTATS_DATA_ROD_v0>().div_ceil(8)];
        let mut data = unsafe {
            std::slice::from_raw_parts_mut(
                data_storage.as_mut_ptr() as *mut u8,
                data_storage.len() * 8,
            )
        };
        let res = unsafe {
            GetPerTcp6ConnectionEStats(
                &to_mib_tcp6_row(row),
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

    /// `MIB_TCP6ROW_OWNER_PID` and `MIB_TCP6ROW` have
    /// different layouts (State first vs. last, no PID field); casting one
    /// to the other made the estats call read garbage fields. Build the
    /// real row from the owner-pid row's fields.
    pub fn to_mib_tcp6_row(row: &MIB_TCP6ROW_OWNER_PID) -> MIB_TCP6ROW {
        use windows::Win32::NetworkManagement::IpHelper::MIB_TCP_STATE;
        use windows::Win32::Networking::WinSock::{IN6_ADDR, IN6_ADDR_0};
        MIB_TCP6ROW {
            State: MIB_TCP_STATE(row.dwState as i32),
            LocalAddr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: row.ucLocalAddr,
                },
            },
            dwLocalScopeId: row.dwLocalScopeId,
            dwLocalPort: row.dwLocalPort,
            RemoteAddr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: row.ucRemoteAddr,
                },
            },
            dwRemoteScopeId: row.dwRemoteScopeId,
            dwRemotePort: row.dwRemotePort,
        }
    }

    /// API-level conditions that disable estats for the
    /// whole process (no admin rights / OS support); anything else is a
    /// per-row error.
    fn estats_rw_bytes(rw: &TCP_ESTATS_DATA_RW_v0) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                rw as *const _ as *const u8,
                std::mem::size_of::<TCP_ESTATS_DATA_RW_v0>(),
            )
        }
    }

    /// byte counters stay zero until data collection is
    /// enabled for the individual connection; call once per established row.
    pub fn enable_tcp_estats_v4(row: &MIB_TCPROW_OWNER_PID) -> WIN32_ERROR {
        let rw = TCP_ESTATS_DATA_RW_v0 {
            EnableCollection: windows::Win32::Foundation::BOOLEAN(1),
        };
        WIN32_ERROR(unsafe {
            SetPerTcpConnectionEStats(
                row as *const _ as *const MIB_TCPROW_LH,
                TcpConnectionEstatsData,
                estats_rw_bytes(&rw),
                0,
                0,
            )
        })
    }

    pub fn enable_tcp_estats_v6(row: &MIB_TCP6ROW_OWNER_PID) -> WIN32_ERROR {
        let rw = TCP_ESTATS_DATA_RW_v0 {
            EnableCollection: windows::Win32::Foundation::BOOLEAN(1),
        };
        WIN32_ERROR(unsafe {
            SetPerTcp6ConnectionEStats(
                &to_mib_tcp6_row(row),
                TcpConnectionEstatsData,
                estats_rw_bytes(&rw),
                0,
                0,
            )
        })
    }
}

#[cfg(windows)]
#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct EstatsRowKey {
    local: u128,
    local_port: u32,
    remote: u128,
    remote_port: u32,
    pid: u32,
}

#[cfg(windows)]
fn estats_row_key_v4(
    row: &windows::Win32::NetworkManagement::IpHelper::MIB_TCPROW_OWNER_PID,
) -> EstatsRowKey {
    EstatsRowKey {
        local: row.dwLocalAddr as u128,
        local_port: row.dwLocalPort,
        remote: row.dwRemoteAddr as u128,
        remote_port: row.dwRemotePort,
        pid: row.dwOwningPid,
    }
}

#[cfg(windows)]
fn estats_row_key_v6(
    row: &windows::Win32::NetworkManagement::IpHelper::MIB_TCP6ROW_OWNER_PID,
) -> EstatsRowKey {
    let mut local = [0u8; 16];
    local.copy_from_slice(&row.ucLocalAddr);
    let mut remote = [0u8; 16];
    remote.copy_from_slice(&row.ucRemoteAddr);
    EstatsRowKey {
        local: u128::from_be_bytes(local),
        local_port: row.dwLocalPort,
        remote: u128::from_be_bytes(remote),
        remote_port: row.dwRemotePort,
        pid: row.dwOwningPid,
    }
}

#[cfg(windows)]
pub struct WindowsMonitor {
    estats_supported: bool,
    /// connections whose estats collection was already
    /// enabled (never on LISTEN rows).
    enabled_rows: std::collections::HashSet<EstatsRowKey>,
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
            enabled_rows: std::collections::HashSet::new(),
        }
    }
}

#[cfg(windows)]
impl ConnectionSource for WindowsMonitor {
    fn sample(&mut self) -> std::io::Result<Vec<Connection>> {
        let mut connections = Vec::new();

        // bound the enabled-connection set; re-enabling a
        // still-live connection is harmless, so a plain clear suffices.
        if self.enabled_rows.len() > 8192 {
            self.enabled_rows.clear();
        }

        // one adapter scan per sample feeds the per-row VPN
        // classification.
        let vpn_adapters = crate::list_adapter_descriptions();

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

                // LISTEN rows are never queried (estats is
                // for live connections), and only API-level failures switch
                // byte counting off globally - a row-level error (the row
                // vanished between the table snapshot and the stats call)
                // leaves that row at None without affecting the others.
                if self.estats_supported && !is_listening_state(row.dwState) {
                    // enable collection once per connection.
                    let key = estats_row_key_v4(&row);
                    if !self.enabled_rows.contains(&key) {
                        let rc = stats::enable_tcp_estats_v4(&row);
                        if rc == windows::Win32::Foundation::WIN32_ERROR(0) {
                            self.enabled_rows.insert(key);
                        } else if crate::estats_error_is_global(rc.0, row.dwOwningPid) {
                            self.estats_supported = false;
                        }
                    }
                }
                if self.estats_supported && !is_listening_state(row.dwState) {
                    match stats::get_tcp_estats_v4(&row) {
                        Ok((bin, bout)) => {
                            bytes_in = Some(bin);
                            bytes_out = Some(bout);
                        }
                        Err(e) => {
                            if crate::estats_error_is_global(e.0, row.dwOwningPid) {
                                self.estats_supported = false;
                            }
                        }
                    }
                }

                let via_vpn =
                    remote.is_some_and(|r| routes::is_vpn_route_with(&vpn_adapters, r.ip()));

                connections.push(Connection {
                    process: process_info::get_process_info(row.dwOwningPid),
                    protocol: Protocol::Tcp,
                    local,
                    remote,
                    listening: is_listening_state(row.dwState),
                    bytes_in,
                    bytes_out,
                    via_vpn,
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

                // LISTEN rows are never queried (estats is
                // for live connections), and only API-level failures switch
                // byte counting off globally - a row-level error (the row
                // vanished between the table snapshot and the stats call)
                // leaves that row at None without affecting the others.
                if self.estats_supported && !is_listening_state(row.dwState) {
                    // enable collection once per connection.
                    let key = estats_row_key_v6(&row);
                    if !self.enabled_rows.contains(&key) {
                        let rc = stats::enable_tcp_estats_v6(&row);
                        if rc == windows::Win32::Foundation::WIN32_ERROR(0) {
                            self.enabled_rows.insert(key);
                        } else if crate::estats_error_is_global(rc.0, row.dwOwningPid) {
                            self.estats_supported = false;
                        }
                    }
                }
                if self.estats_supported && !is_listening_state(row.dwState) {
                    match stats::get_tcp_estats_v6(&row) {
                        Ok((bin, bout)) => {
                            bytes_in = Some(bin);
                            bytes_out = Some(bout);
                        }
                        Err(e) => {
                            if crate::estats_error_is_global(e.0, row.dwOwningPid) {
                                self.estats_supported = false;
                            }
                        }
                    }
                }

                let via_vpn =
                    remote.is_some_and(|r| routes::is_vpn_route_with(&vpn_adapters, r.ip()));

                connections.push(Connection {
                    process: process_info::get_process_info(row.dwOwningPid),
                    protocol: Protocol::Tcp,
                    local,
                    remote,
                    listening: is_listening_state(row.dwState),
                    bytes_in,
                    bytes_out,
                    via_vpn,
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
                    via_vpn: false,
                });
            }
        }

        // UDP IPv6
        if let Ok(table) = windows_sys::get_udp_table_v6() {
            for row in table {
                let local_ip = convert_ipv6_addr(&row.ucLocalAddr);
                let local_port = parse_port(row.dwLocalPort);
                // scope id from the row, not hard-coded 0.
                let local = SocketAddr::V6(SocketAddrV6::new(
                    local_ip,
                    local_port,
                    0,
                    get_ipv6_scope_id(row.dwLocalScopeId),
                ));

                connections.push(Connection {
                    process: process_info::get_process_info(row.dwOwningPid),
                    protocol: Protocol::Udp,
                    local,
                    remote: None,
                    listening: true,
                    bytes_in: None,
                    bytes_out: None,
                    via_vpn: false,
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
    use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid;
    use windows::Win32::NetworkManagement::IpHelper::GetBestInterfaceEx;
    use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    /// variant for hot loops - the adapter list is scanned
    /// once per sample and reused per connection.
    pub fn is_vpn_route_with(adapters: &[(u64, String, u32)], remote: IpAddr) -> bool {
        is_vpn_route_inner(adapters, remote)
    }

    pub fn is_vpn_route(remote: IpAddr) -> bool {
        is_vpn_route_inner(&crate::list_adapter_descriptions(), remote)
    }

    fn is_vpn_route_inner(adapters: &[(u64, String, u32)], remote: IpAddr) -> bool {
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

        // decide from the adapter's tunnel type + DESCRIPTION;
        // the user-editable alias and IF_TYPE_PROP_VIRTUAL alone produce
        // false positives (Hyper-V vSwitch, WSL vEthernet are type 53 too).
        for (adapter_luid, description, if_type) in adapters {
            if *adapter_luid == unsafe { luid.Value } {
                return crate::check_is_vpn_interface(*if_type, description);
            }
        }
        false
    }
}

/// (luid, description, if_type) for every adapter. The
/// DESCRIPTION is the driver-provided string, unlike the editable alias.
#[cfg(windows)]
pub fn list_adapter_descriptions() -> Vec<(u64, String, u32)> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_ALL_INTERFACES, GAA_FLAG_SKIP_ANYCAST,
        GAA_FLAG_SKIP_MULTICAST, GAA_FLAG_SKIP_UNICAST, IP_ADAPTER_ADDRESSES_LH,
    };

    const AF_UNSPEC: u32 = 0;
    let flags = GAA_FLAG_INCLUDE_ALL_INTERFACES
        | GAA_FLAG_SKIP_UNICAST
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST;

    let mut size: u32 = 16 * 1024;
    for _ in 0..4 {
        let mut buffer = vec![0u8; size as usize];
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                flags,
                None,
                Some(buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            )
        };
        if rc != 0 {
            if rc == 111
            /* ERROR_MORE_DATA */
            {
                continue;
            }
            return Vec::new();
        }

        let mut out = Vec::new();
        let mut current = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !current.is_null() {
            let adapter = unsafe { &*current };
            let description = unsafe {
                let mut len = 0usize;
                while *adapter.Description.as_ptr().add(len) != 0 {
                    len += 1;
                }
                String::from_utf16_lossy(std::slice::from_raw_parts(
                    adapter.Description.as_ptr(),
                    len,
                ))
            };
            out.push((unsafe { adapter.Luid.Value }, description, adapter.IfType));
            current = adapter.Next;
        }
        return out;
    }
    Vec::new()
}

pub fn check_is_vpn_interface(if_type: u32, description: &str) -> bool {
    // 131 (IF_TYPE_TUNNEL) is authoritative. 53
    // (IF_TYPE_PROP_VIRTUAL) is NOT - Hyper-V vSwitch and WSL vEthernet
    // adapters report it too - so it needs a matching driver DESCRIPTION.
    if if_type == 131 {
        return true;
    }

    let lower = description.to_lowercase();
    lower.contains("wintun") || lower.contains("wireguard") || lower.contains("tap-")
}

#[cfg(test)]
mod vpn_tests {
    use super::*;

    #[test]
    fn test_check_is_vpn_interface_description_semantics() {
        // tunnel type is authoritative...
        assert!(check_is_vpn_interface(131, "anything"));
        // ...but PROP_VIRTUAL alone is not (Hyper-V vSwitch / WSL vEthernet)
        assert!(!check_is_vpn_interface(
            53,
            "Hyper-V Virtual Ethernet Adapter"
        ));
        assert!(!check_is_vpn_interface(53, "vEthernet (WSL)"));
        // ...wintun/wireguard/tap drivers are VPNs regardless of type
        assert!(check_is_vpn_interface(6, "Wintun Userspace Tunnel"));
        assert!(check_is_vpn_interface(53, "Wintun Userspace Tunnel"));
        assert!(check_is_vpn_interface(6, "WireGuard Tunnel"));
        assert!(check_is_vpn_interface(6, "TAP-Windows Adapter V9"));
        assert!(!check_is_vpn_interface(
            6,
            "Intel(R) Ethernet Connection I219-V"
        ));
        assert!(!check_is_vpn_interface(
            53,
            "Microsoft Wi-Fi Direct Virtual Adapter"
        ));
    }

    #[cfg(windows)]
    #[test]
    fn test_list_adapter_descriptions_smoke() {
        let adapters = list_adapter_descriptions();
        assert!(!adapters.is_empty(), "host has at least one adapter");
        for (_, description, if_type) in &adapters {
            assert!(!description.is_empty(), "descriptions are populated");
            assert!(*if_type > 0);
        }
    }
}

#[cfg(test)]
mod edge_case_tests {
    use super::*;
    use std::path::Path;

    #[cfg(windows)]
    #[test]
    fn test_estats_enablement_live_loopback_counts_bytes() {
        // without SetPerTcpConnectionEStats the Get side
        // reports zeros; enablement must happen once per connection. Two
        // samples: the first enables, traffic flows, the second reads.
        use rat_types::Protocol;
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut server = listener.accept().unwrap().0;
        client.write_all(&vec![b'x'; 1024]).unwrap();
        let mut drain = [0u8; 16];
        let _ = server.read(&mut drain);

        let mut monitor = WindowsMonitor::new();
        let _ = monitor.sample().expect("first sample (enables estats)");

        client.write_all(&vec![b'y'; 64 * 1024]).unwrap();
        client.flush().unwrap();
        let mut probe = [0u8; 1];
        let _ = server.read(&mut probe);

        let conns = monitor.sample().expect("second sample");
        let row = conns
            .iter()
            .find(|c| c.protocol == Protocol::Tcp && c.local.port() == port && !c.listening)
            .expect("accepted loopback connection not found");
        let bytes_in = row
            .bytes_in
            .expect("estats must yield counters for the live connection (None = disabled)");
        assert!(
            bytes_in > 0,
            "byte counters must be nonzero after enablement, got {bytes_in}"
        );
    }

    #[test]
    fn test_estats_global_vs_row_errors() {
        // only API-level conditions on owned rows are global.
        assert!(estats_error_is_global(5, 42)); // ACCESS_DENIED, owned row
        assert!(estats_error_is_global(50, 42)); // NOT_SUPPORTED, owned row
        assert!(!estats_error_is_global(50, 0)); // kernel TIME_WAIT row: per-row
        assert!(!estats_error_is_global(1168, 42)); // NOT_FOUND (row vanished)
        assert!(!estats_error_is_global(87, 42)); // INVALID_PARAMETER
    }

    #[cfg(windows)]
    #[test]
    fn test_mib_tcp6_row_layouts_differ_and_copy_is_faithful() {
        // the owner-pid row and the plain row have
        // different layouts; the faithful copy must carry every field.
        assert_ne!(
            std::mem::size_of::<windows::Win32::NetworkManagement::IpHelper::MIB_TCP6ROW>(),
            std::mem::size_of::<windows::Win32::NetworkManagement::IpHelper::MIB_TCP6ROW_OWNER_PID>(
            ),
            "layouts must not be conflated"
        );
        let owner = windows::Win32::NetworkManagement::IpHelper::MIB_TCP6ROW_OWNER_PID {
            ucLocalAddr: [1; 16],
            dwLocalScopeId: 7,
            dwLocalPort: 0x1234,
            ucRemoteAddr: [2; 16],
            dwRemoteScopeId: 9,
            dwRemotePort: 0x5678,
            dwState: 5,
            dwOwningPid: 42,
        };
        let plain = stats::to_mib_tcp6_row(&owner);
        assert_eq!(plain.State.0, 5);
        assert_eq!(unsafe { plain.LocalAddr.u.Byte }, [1; 16]);
        assert_eq!(plain.dwLocalScopeId, 7);
        assert_eq!(plain.dwLocalPort, 0x1234);
        assert_eq!(unsafe { plain.RemoteAddr.u.Byte }, [2; 16]);
        assert_eq!(plain.dwRemoteScopeId, 9);
        assert_eq!(plain.dwRemotePort, 0x5678);
    }

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

#[cfg(all(test, windows))]
mod process_user_tests {
    use super::process_info::get_process_info;

    #[test]
    fn test_process_user_current_process() {
        let info = get_process_info(std::process::id());
        let user = info.user.expect("own process user must be known");
        assert!(!user.is_empty());
        let env = std::env::var("USERNAME").expect("USERNAME set");
        let user_part = user.rsplit('\\').next().unwrap();
        assert!(user_part.eq_ignore_ascii_case(&env), "{user} vs {env}");
    }

    #[test]
    fn test_process_user_denied_or_system_never_panics() {
        for pid in [0u32, 4, 1, 0xFFFF_FFF0] {
            let info = get_process_info(pid);
            if let Some(u) = info.user {
                assert!(!u.is_empty());
            }
        }
    }
}
