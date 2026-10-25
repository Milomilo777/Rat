use crate::core::Command;
use crate::msg::{ClientMessage, ServerMessage, PROTOCOL_VERSION};
use futures::{SinkExt, StreamExt};

pub const SOCKET_PATH: &str = "/run/rat/rat.sock";
pub const PIPE_NAME: &str = r"\\.\pipe\rat";

#[cfg(unix)]
fn effective_uid() -> u32 {
    // std has no geteuid(); /proc/self/status exposes it without a libc dep.
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:\t") {
                if let Some(uid) = rest.split_whitespace().nth(1).and_then(|e| e.parse().ok()) {
                    return uid;
                }
            }
        }
    }
    u32::MAX
}

#[cfg(unix)]
fn rat_group_gid() -> Option<u32> {
    let group = std::env::var("RAT_IPC_GROUP").unwrap_or_else(|_| "rat".to_string());
    let content = std::fs::read_to_string("/etc/group").ok()?;
    for line in content.lines() {
        let mut fields = line.split(':');
        if fields.next() == Some(group.as_str()) {
            // group:password:gid:... — the third field is the GID
            if let Some(gid) = fields.nth(1).and_then(|g| g.parse().ok()) {
                return Some(gid);
            }
        }
    }
    None
}

/// S2 (update-08): who may talk to the privileged daemon over the unix
/// socket — root, the daemon's own user, or a member of the `rat` group
/// (primary gid; override the group name with RAT_IPC_GROUP).
#[cfg(unix)]
fn peer_allowed(uid: u32, gid: u32) -> bool {
    uid == 0 || uid == effective_uid() || rat_group_gid().is_some_and(|g| g == gid)
}

#[cfg(unix)]
pub async fn start_ipc_server(
    socket_path: &str,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    snapshot_rx: tokio::sync::broadcast::Receiver<ServerMessage>,
    commands: tokio::sync::mpsc::UnboundedSender<Command>,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    // PROPOSALS #9: if a live listener answers on this path, another daemon
    // owns the socket — refuse to start instead of silently stealing it.
    // Only a stale socket left by a crashed daemon gets removed below.
    if tokio::net::UnixStream::connect(socket_path).await.is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            format!("another daemon is already listening on {socket_path}"),
        ));
    }

    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        // S4 (update-08): a directory we create is 0o750 so the socket it
        // holds stays unreachable for others even during the bind->chmod
        // window (systemd's RuntimeDirectory=rat covers /run/rat the same
        // way in production).
        let existed = parent.exists();
        std::fs::create_dir_all(parent)?;
        if !existed {
            let mut perms = std::fs::metadata(parent)?.permissions();
            perms.set_mode(0o750);
            std::fs::set_permissions(parent, perms)?;
        }
    }

    let listener = UnixListener::bind(socket_path)?;

    // S3 (update-08): bounded concurrent clients.
    let client_slots = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CLIENTS));

    // S4 (update-08): always tighten the socket to owner+group read/write.
    let mut perms = std::fs::metadata(socket_path)?.permissions();
    perms.set_mode(0o660);
    std::fs::set_permissions(socket_path, perms)?;

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, _)) => {
                        // S2 (update-08): drop connections from peers that are
                        // neither root, us, nor in the rat group.
                        let allowed = stream
                            .peer_cred()
                            .ok()
                            .is_some_and(|c| peer_allowed(c.uid(), c.gid()));
                        if !allowed {
                            continue;
                        }
                        // S3 (update-08): at capacity the extra client is
                        // dropped instead of spawning another handler.
                        let permit = match client_slots.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => continue,
                        };
                        let snap_rx = snapshot_rx.resubscribe();
                        let cmd_tx = commands.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            handle_connection(stream, snap_rx, cmd_tx).await;
                        });
                    }
                    Err(_) => {
                        // S9 (update-08): back off so a persistent accept
                        // error (e.g. EMFILE) cannot spin the CPU.
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }

    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

#[cfg(windows)]
struct SdGuard(isize);
#[cfg(windows)]
impl Drop for SdGuard {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                windows_sys::Win32::Foundation::LocalFree(
                    self.0 as windows_sys::Win32::Foundation::HLOCAL,
                );
            }
        }
    }
}

#[cfg(windows)]
// S1 (update-08): SYSTEM and Administrators get GENERIC_ALL; Interactive
// Users only read/write (0x12019b = FILE_GENERIC_READ | FILE_GENERIC_WRITE)
// so a local app cannot create rogue pipe instances or rewrite the DACL
// (GA for IU would include FILE_CREATE_PIPE_INSTANCE and WRITE_DAC).
// D:P makes the DACL protected against inherited ACE reordering.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)\0";

/// S1 call-site split (gate-fix-S1 caveat): the ONLY place PIPE_SDDL becomes
/// a security descriptor, so the const cannot drift away from what the pipe
/// is actually created with.
#[cfg(windows)]
fn security_descriptor() -> std::io::Result<SdGuard> {
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorA;

    const SDDL_REVISION_1: u32 = 1;

    let sddl = PIPE_SDDL.as_bytes();
    let mut sd_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut sd_size = 0;

    let success = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd_ptr,
            &mut sd_size,
        )
    };

    if success == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(SdGuard(sd_ptr as isize))
}

#[cfg(windows)]
mod client_auth {
    //! C2 (PROPOSALS #5/#10, gate-fix-S2): per-client identity on the named
    //! pipe. The S1 DACL admits every Interactive User, so before a
    //! connection reaches the handler the daemon checks the CLIENT process's
    //! primary token: the same user as the daemon, or a member of the Builtin
    //! Administrators group. Every error fails CLOSED (connection dropped) —
    //! this is the token check gate-fix-S2 deferred to "when the handshake
    //! lands".

    use std::sync::OnceLock;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        CopySid, GetTokenInformation, TokenGroups, TokenUser, PSID, SID_AND_ATTRIBUTES,
        TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// SECURITY_MAX_SID_SIZE from the Windows SDK.
    const MAX_SID_SIZE: u32 = 68;

    /// Owns one open kernel handle.
    struct HandleGuard(HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the guard owns exactly one handle from Open*.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    /// Copy `sid` into an owned fixed-size buffer (EqualSid compares via the
    /// SID's internal length, so a MAX_SID_SIZE buffer is fine).
    ///
    /// SAFETY: `sid` must point at a valid SID for the lifetime of the call.
    unsafe fn copy_sid(sid: PSID) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; MAX_SID_SIZE as usize];
        let ok = unsafe { CopySid(MAX_SID_SIZE, buf.as_mut_ptr() as PSID, sid) };
        (ok != 0).then_some(buf)
    }

    /// (user SID, group SIDs) of the process's primary token.
    pub fn process_token_sids(pid: u32) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
        // SAFETY: all FFI below uses out-pointers into owned buffers and
        // handles guarded by HandleGuard; token buffers are only read back
        // as TOKEN_USER/TOKEN_GROUPS as produced by GetTokenInformation.
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return None;
            }
            let _process_guard = HandleGuard(process);

            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
                return None;
            }
            let _token_guard = HandleGuard(token);

            // Size probe: a null buffer fails with ERROR_INSUFFICIENT_BUFFER
            // and writes the required size.
            let mut needed = 0u32;
            let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
            if needed == 0 {
                return None;
            }
            let mut user_buf = vec![0u8; needed as usize];
            if GetTokenInformation(
                token,
                TokenUser,
                user_buf.as_mut_ptr() as *mut std::ffi::c_void,
                needed,
                &mut needed,
            ) == 0
            {
                return None;
            }
            let token_user = &*(user_buf.as_ptr() as *const TOKEN_USER);
            if token_user.User.Sid.is_null() {
                return None;
            }
            let user_sid = copy_sid(token_user.User.Sid)?;

            let mut needed = 0u32;
            let _ = GetTokenInformation(token, TokenGroups, std::ptr::null_mut(), 0, &mut needed);
            if needed == 0 {
                return None;
            }
            let mut groups_buf = vec![0u8; needed as usize];
            if GetTokenInformation(
                token,
                TokenGroups,
                groups_buf.as_mut_ptr() as *mut std::ffi::c_void,
                needed,
                &mut needed,
            ) == 0
            {
                return None;
            }
            let groups = &*(groups_buf.as_ptr() as *const TOKEN_GROUPS);
            let count = groups.GroupCount as usize;
            let attrs = std::slice::from_raw_parts(groups.Groups.as_ptr(), count);
            let group_sids = attrs
                .iter()
                .filter_map(
                    |SID_AND_ATTRIBUTES { Sid, .. }| {
                        if Sid.is_null() {
                            None
                        } else {
                            copy_sid(*Sid)
                        }
                    },
                )
                .collect();

            Some((user_sid, group_sids))
        }
    }

    /// The daemon's own user SID, fetched once.
    pub fn daemon_user_sid() -> std::io::Result<Vec<u8>> {
        static CACHE: OnceLock<Vec<u8>> = OnceLock::new();
        if let Some(sid) = CACHE.get() {
            return Ok(sid.clone());
        }
        // SAFETY: GetCurrentProcess returns a valid pseudo-handle that needs
        // no close; copy_sid only reads what the token reports.
        let sid = unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let _guard = HandleGuard(token);
            let mut needed = 0u32;
            let _ = GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
            if needed == 0 {
                return Err(std::io::Error::other("cannot size the daemon's TokenUser"));
            }
            let mut buf = vec![0u8; needed as usize];
            if GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                needed,
                &mut needed,
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
            if token_user.User.Sid.is_null() {
                return Err(std::io::Error::other("daemon token has no user SID"));
            }
            copy_sid(token_user.User.Sid)
                .ok_or_else(|| std::io::Error::other("cannot copy the daemon's user SID"))?
        };
        let _ = CACHE.set(sid.clone());
        Ok(sid)
    }
}

#[cfg(windows)]
/// C2: may the client process behind this pipe connection set rules? Same
/// user as the daemon, or a Builtin Administrator; anything else — and every
/// error — is refused.
fn client_pid_allowed(pid: u32) -> bool {
    use windows_sys::Win32::Security::{
        EqualSid, IsWellKnownSid, WinBuiltinAdministratorsSid, PSID,
    };

    let Some((user, groups)) = client_auth::process_token_sids(pid) else {
        return false;
    };
    let Ok(daemon_sid) = client_auth::daemon_user_sid() else {
        return false;
    };
    // SAFETY: all three buffers were produced by CopySid and are valid SIDs.
    unsafe {
        if EqualSid(user.as_ptr() as PSID, daemon_sid.as_ptr() as PSID) != 0 {
            return true;
        }
        groups
            .iter()
            .any(|g| IsWellKnownSid(g.as_ptr() as PSID, WinBuiltinAdministratorsSid) != 0)
    }
}

#[cfg(windows)]
/// The client process behind a connected pipe instance, when Windows tells us.
fn pipe_client_pid(server: &tokio::net::windows::named_pipe::NamedPipeServer) -> Option<u32> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

    let mut pid = 0u32;
    // SAFETY: the server owns its handle; pid is a valid out-pointer.
    let ok = unsafe { GetNamedPipeClientProcessId(server.as_raw_handle(), &mut pid) };
    (ok != 0).then_some(pid)
}

#[cfg(windows)]
pub async fn start_ipc_server(
    pipe_name: &str,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    snapshot_rx: tokio::sync::broadcast::Receiver<ServerMessage>,
    commands: tokio::sync::mpsc::UnboundedSender<Command>,
) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    let sd_guard = std::sync::Arc::new(security_descriptor()?);
    let sd_val = sd_guard.0;

    // S3 (update-08): bounded concurrent clients.
    let client_slots = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CLIENTS));

    let mut server_options = ServerOptions::new();
    let mut first = true;

    loop {
        if first {
            server_options.first_pipe_instance(true);
            first = false;
        } else {
            server_options.first_pipe_instance(false);
        }

        let server: std::io::Result<NamedPipeServer> = {
            let mut security_attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                    as u32,
                lpSecurityDescriptor: sd_val as *mut _,
                bInheritHandle: 0,
            };
            unsafe {
                server_options.create_with_security_attributes_raw(
                    pipe_name,
                    &mut security_attributes as *mut _ as *mut _,
                )
            }
        };

        let server = match server {
            Ok(server) => server,
            Err(e) => {
                return Err(e);
            }
        };

        tokio::select! {
            _ = shutdown.recv() => {
                break;
            }
            res = server.connect() => {
                match res {
                    Ok(()) => {
                        // C2 (gate-fix-S2): identify the client before it can
                        // send anything; errors above already failed closed.
                        let allowed = match pipe_client_pid(&server) {
                            Some(pid) => client_pid_allowed(pid),
                            None => false,
                        };
                        if !allowed {
                            continue;
                        }
                        // S3 (update-08): at capacity the extra client's pipe
                        // end is dropped instead of spawning another handler.
                        let permit = match client_slots.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => continue,
                        };
                        let snap_rx = snapshot_rx.resubscribe();
                        let cmd_tx = commands.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            handle_connection(server, snap_rx, cmd_tx).await;
                        });
                    }
                    Err(_) => {
                        // S9 (update-08): back off so a persistent connect
                        // error cannot spin the CPU.
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        }
    }
    // ensure sd_guard drops here
    let _ = sd_guard;
    Ok(())
}

// S3 (update-08): inbound client lines are capped at 64 KiB (a request is a
// small JSON message; anything bigger is abuse) while outbound snapshots keep
// the 10 MiB ceiling (hundreds of connections serialize large). Concurrent
// clients are capped so a local user cannot exhaust daemon memory.
const MAX_CLIENT_LINE: usize = 64 * 1024;
const MAX_SERVER_LINE: usize = 10 * 1024 * 1024;
const MAX_CONCURRENT_CLIENTS: usize = 4;

/// PROPOSALS #15: a client has this long to complete the Hello handshake
/// before the slot is given up (4 bounded slots: unauthenticated clients
/// cannot pin the daemon forever).
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

async fn send_server<W>(
    writer: &mut tokio_util::codec::FramedWrite<W, tokio_util::codec::LinesCodec>,
    msg: ServerMessage,
) -> Result<(), tokio_util::codec::LinesCodecError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    // Our own message types always serialize; a failure is skipped rather
    // than killing the connection.
    let Ok(line) = msg.to_string() else {
        return Ok(());
    };
    writer.send(line).await
}

async fn handle_connection<S>(
    stream: S,
    mut snapshot_rx: tokio::sync::broadcast::Receiver<ServerMessage>,
    commands: tokio::sync::mpsc::UnboundedSender<Command>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = tokio_util::codec::FramedRead::new(
        read_half,
        tokio_util::codec::LinesCodec::new_with_max_length(MAX_CLIENT_LINE),
    );
    let mut writer = tokio_util::codec::FramedWrite::new(
        write_half,
        tokio_util::codec::LinesCodec::new_with_max_length(MAX_SERVER_LINE),
    );

    // PROPOSALS #15: the FIRST client message must be Hello; nothing is sent
    // to the client before the handshake completes, and a version mismatch
    // or any other opener is answered with Error and the connection closed.
    let first = tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.next()).await;
    match first {
        Ok(Some(Ok(line))) => match ClientMessage::from_json_str(&line) {
            Ok(ClientMessage::Hello { protocol_version })
                if protocol_version == PROTOCOL_VERSION =>
            {
                if send_server(
                    &mut writer,
                    ServerMessage::HelloAck {
                        protocol_version: PROTOCOL_VERSION,
                    },
                )
                .await
                .is_err()
                {
                    return;
                }
            }
            Ok(ClientMessage::Hello { protocol_version }) => {
                let _ = send_server(
                    &mut writer,
                    ServerMessage::Error {
                        message: format!(
                            "unsupported protocol version {protocol_version}; this server speaks {PROTOCOL_VERSION}"
                        ),
                    },
                )
                .await;
                return;
            }
            Ok(_) => {
                let _ = send_server(
                    &mut writer,
                    ServerMessage::Error {
                        message: format!("the first message must be Hello {{ protocol_version: {PROTOCOL_VERSION} }}"),
                    },
                )
                .await;
                return;
            }
            Err(_) => {
                let _ = send_server(
                    &mut writer,
                    ServerMessage::Error {
                        message: "Invalid JSON".to_string(),
                    },
                )
                .await;
                return;
            }
        },
        Ok(Some(Err(e))) => {
            let _ = send_server(
                &mut writer,
                ServerMessage::Error {
                    message: format!("LinesCodec error: {e}"),
                },
            )
            .await;
            return;
        }
        // Handshake timeout or the client hung up.
        _ => return,
    }

    loop {
        tokio::select! {
            msg = snapshot_rx.recv() => {
                match msg {
                    Ok(msg) => {
                        if send_server(&mut writer, msg).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Just continue if lagged, next msg will be a fresh snapshot anyway
                    }
                    Err(_) => break,
                }
            }
            result = reader.next() => {
                match result {
                    Some(Ok(line)) => {
                        match ClientMessage::from_json_str(&line) {
                            Ok(ClientMessage::SetRules { rules }) => {
                                // PROPOSALS #10: forwarded to the pipeline,
                                // which owns the rule engine and enforcer.
                                let _ = commands.send(Command::SetRules { rules });
                            }
                            Ok(ClientMessage::AlertAnswer { id, verdict, scope, lifetime }) => {
                                let _ = commands.send(Command::AlertAnswer {
                                    id,
                                    verdict,
                                    scope,
                                    lifetime,
                                });
                            }
                            Ok(ClientMessage::Hello { .. }) => {
                                // The handshake already succeeded once; a
                                // repeat Hello gets an error but the
                                // connection stays.
                                let _ = send_server(
                                    &mut writer,
                                    ServerMessage::Error {
                                        message: "already handshaked".to_string(),
                                    },
                                )
                                .await;
                            }
                            Err(_) => {
                                // S10 (update-08): reply once, then close —
                                // a client that cannot produce a valid
                                // message gets no second attempt.
                                let _ = send_server(
                                    &mut writer,
                                    ServerMessage::Error {
                                        message: "Invalid JSON".to_string(),
                                    },
                                )
                                .await;
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        let _ = send_server(
                            &mut writer,
                            ServerMessage::Error {
                                message: format!("LinesCodec error: {e}"),
                            },
                        )
                        .await;
                        break;
                    }
                    None => break,
                }
            }
        }
    }
}

#[cfg(all(test, windows))]
mod sddl_tests {
    use super::{security_descriptor, PIPE_SDDL};

    // S1 (update-08): the pipe DACL must never hand GENERIC_ALL to
    // Interactive Users (that includes FILE_CREATE_PIPE_INSTANCE and
    // WRITE_DAC), while SYSTEM/Administrators stay full-control and the
    // DACL itself is protected.
    #[test]
    fn test_pipe_sddl_restricts_interactive_users() {
        assert!(PIPE_SDDL.starts_with("D:P("), "DACL must be protected");
        assert!(PIPE_SDDL.contains("(A;;GA;;;SY)"), "SYSTEM full control");
        assert!(
            PIPE_SDDL.contains("(A;;GA;;;BA)"),
            "Administrators full control"
        );
        let iu = PIPE_SDDL
            .split('(')
            .find(|ace| ace.starts_with("A;;") && ace.contains(";;;IU)"))
            .expect("an Interactive Users ACE");
        assert!(
            !iu.contains("GA"),
            "Interactive Users must not get GENERIC_ALL: {iu}"
        );
    }

    // S1 call-site split (gate-fix-S1 caveat): the real conversion path used
    // by start_ipc_server must accept exactly this const.
    #[test]
    fn test_pipe_sddl_converts_through_the_real_path() {
        security_descriptor().expect("PIPE_SDDL must convert to a security descriptor");
    }
}

#[cfg(all(test, windows))]
mod client_auth_tests {
    use super::client_pid_allowed;

    #[test]
    fn test_client_pid_allowed_own_process() {
        // The daemon's own process trivially shares its user SID.
        assert!(
            client_pid_allowed(std::process::id()),
            "the daemon's own pid must pass the client token check"
        );
    }

    #[test]
    fn test_client_pid_fail_closed_on_unknown_pid() {
        // A pid that cannot be opened (no such process) must be REFUSED —
        // any FFI error fails closed.
        let ghost = u32::MAX - 100;
        assert!(
            !client_pid_allowed(ghost),
            "an unopenable pid must fail closed"
        );
    }
}

#[cfg(all(test, unix))]
mod peer_tests {
    use super::{effective_uid, peer_allowed};

    // S2 (update-08): root and the daemon's own user are always allowed;
    // anyone else only via the rat group's gid.
    #[test]
    fn test_peer_allowed_root_and_self() {
        assert!(peer_allowed(0, 9999), "root must always be allowed");
        let self_uid = effective_uid();
        assert_ne!(self_uid, u32::MAX, "could not read /proc/self/status");
        assert!(
            peer_allowed(self_uid, 9999),
            "the daemon's own uid must be allowed"
        );
    }

    #[test]
    fn test_peer_allowed_rejects_strangers() {
        let stranger = effective_uid().wrapping_add(1);
        // gid 9999 is not a group we recognize as ours in the test environment;
        // if it somehow is, pick another.
        let gid = if super::rat_group_gid() == Some(9999) {
            9998
        } else {
            9999
        };
        assert!(
            !peer_allowed(stranger, gid),
            "uid {stranger} with unrelated gid {gid} must be refused"
        );
    }
}
