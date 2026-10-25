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

/// Parse the `Groups:` line of `/proc/<pid>/status` (supplementary gids,
/// whitespace separated). No such line -> empty; unparsable tokens are
/// skipped (they can never grant access).
#[cfg_attr(not(unix), allow(dead_code))]
fn groups_from_proc_status(text: &str) -> Vec<u32> {
    text.lines()
        .find_map(|l| l.strip_prefix("Groups:"))
        .map(|rest| {
            rest.split_whitespace()
                .filter_map(|t| t.parse::<u32>().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Pure admission decision: root, the daemon's own user, the `rat` group as
/// primary gid, or the `rat` gid among the peer's supplementary groups.
/// `supplementary` is `None` when it could not be read (fail closed).
#[cfg_attr(not(unix), allow(dead_code))]
fn peer_decision(
    uid: u32,
    gid: u32,
    supplementary: Option<&[u32]>,
    rat_gid: Option<u32>,
    daemon_uid: u32,
) -> bool {
    if uid == 0 || uid == daemon_uid {
        return true;
    }
    let Some(rat) = rat_gid else {
        return false;
    };
    gid == rat || supplementary.is_some_and(|groups| groups.contains(&rat))
}

/// who may talk to the privileged daemon over the unix
/// socket — root, the daemon's own user, or a member of the `rat` group
/// (primary or supplementary gid, e.g. `usermod -aG rat`; override the group
/// name with RAT_IPC_GROUP). `pid` comes from SO_PEERCRED; a missing pid or an
/// unreadable `/proc/<pid>/status` only removes the supplementary check.
#[cfg(unix)]
fn peer_allowed(uid: u32, gid: u32, pid: Option<i32>) -> bool {
    let daemon_uid = effective_uid();
    if uid == 0 || uid == daemon_uid {
        return true;
    }
    let supplementary = pid
        .filter(|p| *p > 0)
        .and_then(|p| std::fs::read_to_string(format!("/proc/{p}/status")).ok())
        .map(|text| groups_from_proc_status(&text));
    peer_decision(
        uid,
        gid,
        supplementary.as_deref(),
        rat_group_gid(),
        daemon_uid,
    )
}

#[cfg(unix)]
pub async fn start_ipc_server_with_options(
    socket_path: &str,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    snapshot_rx: tokio::sync::broadcast::Receiver<ServerMessage>,
    commands: tokio::sync::mpsc::Sender<Command>,
    options: IpcOptions,
) -> std::io::Result<()> {
    let write_timeout = options.write_timeout;
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    // if a live listener answers on this path, another daemon
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
        // a directory we create is 0o750 so the socket it
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

    // bounded concurrent clients.
    let client_slots = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CLIENTS));
    let active_alert = track_active_alert(&snapshot_rx, &shutdown);

    // always tighten the socket to owner+group read/write.
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
                        // drop connections from peers that are
                        // neither root, us, nor in the rat group.
                        let allowed = stream
                            .peer_cred()
                            .ok()
                            .is_some_and(|c| peer_allowed(c.uid(), c.gid(), c.pid()));
                        if !allowed {
                            continue;
                        }
                        // at capacity the extra client is
                        // dropped instead of spawning another handler.
                        let permit = match client_slots.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => continue,
                        };
                        let snap_rx = snapshot_rx.resubscribe();
                        let cmd_tx = commands.clone();
                        let alert = active_alert.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            handle_connection(stream, snap_rx, cmd_tx, alert, write_timeout).await;
                        });
                    }
                    Err(_) => {
                        // back off so a persistent accept
                        // error (e.g. EMFILE) cannot spin the CPU.
                        back_off_after_accept_error().await;
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
// SYSTEM and Administrators get GENERIC_ALL; Interactive
// Users only read/write (0x12019b = FILE_GENERIC_READ | FILE_GENERIC_WRITE)
// so a local app cannot create rogue pipe instances or rewrite the DACL
// (GA for IU would include FILE_CREATE_PIPE_INSTANCE and WRITE_DAC).
// D:P makes the DACL protected against inherited ACE reordering.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)\0";

/// Call-site split: the ONLY place PIPE_SDDL becomes
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
    //! per-client identity on the named
    //! pipe. The pipe DACL admits every Interactive User, so before a
    //! connection reaches the handler the daemon checks the CLIENT process's
    //! primary token: the same user as the daemon, or a Builtin Administrator
    //! whose admin group is ENABLED / whose token is elevated (a token
    //! that merely LISTS the group, as an unelevated admin's filtered token
    //! does, is refused). Every error fails CLOSED (connection dropped) —
    //! this is the token check deferred to "when the handshake
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

    /// One token group: (SID bytes, SE_GROUP_* attributes). The admin check needs the
    /// attributes to tell an ENABLED Administrators membership from a
    /// deny-only one.
    pub type TokenGroup = (Vec<u8>, u32);

    /// (user SID, groups) of the process's primary token.
    pub fn process_token_sids(pid: u32) -> Option<(Vec<u8>, Vec<TokenGroup>)> {
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
                    |SID_AND_ATTRIBUTES {
                         Sid,
                         Attributes: attrs,
                     }| {
                        if Sid.is_null() {
                            None
                        } else {
                            copy_sid(*Sid).map(|sid| (sid, *attrs))
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

    #[cfg(windows)]
    /// belt-and-braces: an elevated token admits even when the group walk
    /// above came up empty. Any error fails closed.
    pub(super) fn token_elevated(pid: u32) -> bool {
        use windows_sys::Win32::Security::{TokenElevation, TOKEN_ELEVATION};

        // SAFETY: out-pointers into owned buffers; handles guarded by HandleGuard.
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return false;
            }
            let _process_guard = HandleGuard(process);
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let _token_guard = HandleGuard(token);
            let mut needed = 0u32;
            let _ =
                GetTokenInformation(token, TokenElevation, std::ptr::null_mut(), 0, &mut needed);
            if needed < std::mem::size_of::<TOKEN_ELEVATION>() as u32 {
                return false;
            }
            let mut buf = vec![0u8; needed as usize];
            if GetTokenInformation(
                token,
                TokenElevation,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                needed,
                &mut needed,
            ) == 0
            {
                return false;
            }
            let elevation = &*(buf.as_ptr() as *const TOKEN_ELEVATION);
            elevation.TokenIsElevated != 0
        }
    }
}

#[cfg(windows)]
/// may the client process behind this pipe connection set rules? Same
/// user as the daemon, or a Builtin Administrator whose admin group is
/// ENABLED (not deny-only) / whose token is elevated; anything else — and
/// every error — is refused.
fn client_pid_allowed(pid: u32) -> bool {
    use windows_sys::Win32::Security::{EqualSid, PSID};

    let Some((user, groups)) = client_auth::process_token_sids(pid) else {
        return false;
    };
    let Ok(daemon_sid) = client_auth::daemon_user_sid() else {
        return false;
    };
    // SAFETY: both buffers were produced by CopySid and are valid SIDs.
    unsafe {
        if EqualSid(user.as_ptr() as PSID, daemon_sid.as_ptr() as PSID) != 0 {
            return true;
        }
    }
    // listing Builtin Administrators is not enough — the group must be
    // enabled (an unelevated admin's filtered token carries it deny-only), or
    // the token must be elevated outright.
    admin_group_enabled(&groups) || client_auth::token_elevated(pid)
}

#[cfg(windows)]
/// does any group in this token ADMIT via Builtin Administrators? The old
/// check accepted a token that merely LISTS the group — an unelevated admin
/// process runs on a filtered token where the group is deny-only. Only an
/// ENABLED membership (deny-only clear) counts here.
fn admin_group_enabled(groups: &[(Vec<u8>, u32)]) -> bool {
    use windows_sys::Win32::Security::{IsWellKnownSid, WinBuiltinAdministratorsSid, PSID};
    use windows_sys::Win32::System::SystemServices::{
        SE_GROUP_ENABLED, SE_GROUP_USE_FOR_DENY_ONLY,
    };

    groups.iter().any(|(sid, attrs)| {
        // SAFETY: sid is a CopySid-produced buffer.
        let is_admins =
            unsafe { IsWellKnownSid(sid.as_ptr() as PSID, WinBuiltinAdministratorsSid) != 0 };
        is_admins
            && attrs & SE_GROUP_ENABLED as u32 != 0
            && attrs & SE_GROUP_USE_FOR_DENY_ONLY as u32 == 0
    })
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
pub async fn start_ipc_server_with_options(
    pipe_name: &str,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    snapshot_rx: tokio::sync::broadcast::Receiver<ServerMessage>,
    commands: tokio::sync::mpsc::Sender<Command>,
    options: IpcOptions,
) -> std::io::Result<()> {
    let write_timeout = options.write_timeout;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    let sd_guard = std::sync::Arc::new(security_descriptor()?);
    let sd_val = sd_guard.0;

    // bounded concurrent clients.
    let client_slots = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CLIENTS));
    let active_alert = track_active_alert(&snapshot_rx, &shutdown);

    let mut server_options = ServerOptions::new();
    let mut first = true;

    loop {
        let creating_first = first;
        if first {
            server_options.first_pipe_instance(true);
            first = false;
        } else {
            server_options.first_pipe_instance(false);
        }

        let create = || -> std::io::Result<NamedPipeServer> {
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
        // The FIRST instance fails while another process owns the pipe name
        // (often the previous service instance, still shutting down): retry
        // with backoff for a bounded time, then report it. Later instances
        // are ours by then, so a failure there is final at once.
        let server = if creating_first {
            tokio::select! {
                _ = shutdown.recv() => break,
                created = create_with_retry(create, options.pipe_retry_window, pipe_name) => created,
            }
        } else {
            create()
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
                        // identify the client before it can
                        // send anything; errors above already failed closed.
                        let allowed = match pipe_client_pid(&server) {
                            Some(pid) => client_pid_allowed(pid),
                            None => false,
                        };
                        if !allowed {
                            continue;
                        }
                        // at capacity the extra client's pipe
                        // end is dropped instead of spawning another handler.
                        let permit = match client_slots.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => continue,
                        };
                        let snap_rx = snapshot_rx.resubscribe();
                        let cmd_tx = commands.clone();
                        let alert = active_alert.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            handle_connection(server, snap_rx, cmd_tx, alert, write_timeout).await;
                        });
                    }
                    Err(_) => {
                        // back off so a persistent connect
                        // error cannot spin the CPU.
                        back_off_after_accept_error().await;
                    }
                }
            }
        }
    }
    // ensure sd_guard drops here
    let _ = sd_guard;
    Ok(())
}

// inbound client lines are capped at 64 KiB (a request is a
// small JSON message; anything bigger is abuse) while outbound snapshots keep
// the 10 MiB ceiling (hundreds of connections serialize large). Concurrent
// clients are capped so a local user cannot exhaust daemon memory.
const MAX_CLIENT_LINE: usize = 64 * 1024;
const MAX_SERVER_LINE: usize = 10 * 1024 * 1024;
const MAX_CONCURRENT_CLIENTS: usize = 4;

/// The bound of the pipeline's command queue (back pressure): a client
/// that floods faster than the daemon enforces gets an explicit Error
/// reply once this many commands are pending, instead of piling every
/// message — each `SetRules` a full enforce — onto an unbounded backlog.
pub const COMMAND_QUEUE_CAPACITY: usize = 16;

/// A client that does not accept a reply within this long is dropped, so a
/// GUI that stopped reading cannot hold one of the four client slots for ever.
pub const CLIENT_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long start-up keeps retrying when the daemon's pipe is still owned by
/// another process (typically the previous service instance that is shutting
/// down) before giving up with an error.
pub const PIPE_RETRY_WINDOW: std::time::Duration = std::time::Duration::from_secs(3);

/// Tunables of [`start_ipc_server_with_options`]; the defaults are what the
/// daemon runs with, tests shorten them.
#[derive(Debug, Clone, Copy)]
pub struct IpcOptions {
    /// See [`CLIENT_WRITE_TIMEOUT`].
    pub write_timeout: std::time::Duration,
    /// See [`PIPE_RETRY_WINDOW`] (Windows only).
    pub pipe_retry_window: std::time::Duration,
}

impl Default for IpcOptions {
    fn default() -> Self {
        Self {
            write_timeout: CLIENT_WRITE_TIMEOUT,
            pipe_retry_window: PIPE_RETRY_WINDOW,
        }
    }
}

/// Serve clients on `endpoint` (unix socket path / Windows pipe name) with the
/// default options.
pub async fn start_ipc_server(
    endpoint: &str,
    shutdown: tokio::sync::broadcast::Receiver<()>,
    snapshot_rx: tokio::sync::broadcast::Receiver<ServerMessage>,
    commands: tokio::sync::mpsc::Sender<Command>,
) -> std::io::Result<()> {
    start_ipc_server_with_options(
        endpoint,
        shutdown,
        snapshot_rx,
        commands,
        IpcOptions::default(),
    )
    .await
}

/// Pause after a failed accept/connect so a persistent error (e.g. EMFILE)
/// cannot spin the CPU.
const ACCEPT_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);

async fn back_off_after_accept_error() {
    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
}

/// Run `create` until it succeeds, backing off 50 ms doubling to 1 s, for at
/// most `window`; then fail with the last error's kind and a message that says
/// the name is owned by another process.
#[cfg_attr(not(windows), allow(dead_code))]
async fn create_with_retry<T>(
    mut create: impl FnMut() -> std::io::Result<T>,
    window: std::time::Duration,
    what: &str,
) -> std::io::Result<T> {
    let deadline = tokio::time::Instant::now() + window;
    let mut delay = std::time::Duration::from_millis(50);
    loop {
        let err = match create() {
            Ok(created) => return Ok(created),
            Err(err) => err,
        };
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(std::io::Error::new(
                err.kind(),
                format!(
                    "{what} is still owned by another process after {window:?} ({err}); is another rat-daemon running?"
                ),
            ));
        }
        eprintln!("rat-daemon: cannot create {what} ({err}); retrying");
        tokio::time::sleep(delay.min(deadline - now)).await;
        delay = (delay * 2).min(std::time::Duration::from_secs(1));
    }
}

/// The alert clients are currently asked about (the last `AlertRequest` not
/// yet followed by its `AlertCleared`), kept so a GUI that connects later can
/// be shown it: the broadcast only reaches clients that were already there.
type ActiveAlert = std::sync::Arc<std::sync::Mutex<Option<ServerMessage>>>;

fn track_active_alert(
    snapshot_rx: &tokio::sync::broadcast::Receiver<ServerMessage>,
    shutdown: &tokio::sync::broadcast::Receiver<()>,
) -> ActiveAlert {
    let state: ActiveAlert = std::sync::Arc::new(std::sync::Mutex::new(None));
    let mut rx = snapshot_rx.resubscribe();
    let mut stop = shutdown.resubscribe();
    let tracked = state.clone();
    tokio::spawn(async move {
        loop {
            let msg = tokio::select! {
                _ = stop.recv() => break,
                msg = rx.recv() => msg,
            };
            let mut slot = tracked.lock().unwrap_or_else(|e| e.into_inner());
            match msg {
                Ok(alert @ ServerMessage::AlertRequest { .. }) => *slot = Some(alert),
                Ok(ServerMessage::AlertCleared { id }) => {
                    if matches!(&*slot, Some(ServerMessage::AlertRequest { id: held, .. }) if *held == id)
                    {
                        *slot = None;
                    }
                }
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    state
}

/// a client has this long to complete the Hello handshake
/// before the slot is given up (4 bounded slots: unauthenticated clients
/// cannot pin the daemon forever).
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The server's write half of one client: framed lines plus the write
/// timeout. A send that times out leaves a half-written line on the wire, so
/// the writer is dead from then on and the connection must be closed.
struct ClientWriter<W> {
    inner: tokio_util::codec::FramedWrite<W, tokio_util::codec::LinesCodec>,
    timeout: std::time::Duration,
    dead: bool,
}

async fn send_server<W>(
    writer: &mut ClientWriter<W>,
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
    if writer.dead {
        return Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into());
    }
    match tokio::time::timeout(writer.timeout, writer.inner.send(line)).await {
        Ok(result) => result,
        Err(_) => {
            writer.dead = true;
            eprintln!(
                "rat-daemon: dropping an IPC client that did not read its replies for {:?}",
                writer.timeout
            );
            Err(std::io::Error::from(std::io::ErrorKind::TimedOut).into())
        }
    }
}

/// Forward one client command onto the pipeline's BOUNDED queue. A full
/// queue answers the client with an explicit Error — it may slow down and
/// retry — instead of the silent unbounded backlog a fire-and-forget send
/// would build; a closed queue means the pipeline is already gone
/// (shutdown), and the command dies with the connection.
async fn forward_command<W>(
    commands: &tokio::sync::mpsc::Sender<Command>,
    writer: &mut ClientWriter<W>,
    cmd: Command,
) where
    W: tokio::io::AsyncWrite + Unpin,
{
    if let Err(tokio::sync::mpsc::error::TrySendError::Full(_)) = commands.try_send(cmd) {
        let _ = send_server(
            writer,
            ServerMessage::Error {
                message: format!(
                    "daemon busy: command queue full ({COMMAND_QUEUE_CAPACITY} commands pending); slow down and retry"
                ),
            },
        )
        .await;
    }
}

async fn handle_connection<S>(
    stream: S,
    mut snapshot_rx: tokio::sync::broadcast::Receiver<ServerMessage>,
    commands: tokio::sync::mpsc::Sender<Command>,
    active_alert: ActiveAlert,
    write_timeout: std::time::Duration,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (read_half, write_half) = tokio::io::split(stream);
    let mut reader = tokio_util::codec::FramedRead::new(
        read_half,
        tokio_util::codec::LinesCodec::new_with_max_length(MAX_CLIENT_LINE),
    );
    let mut writer = ClientWriter {
        inner: tokio_util::codec::FramedWrite::new(
            write_half,
            tokio_util::codec::LinesCodec::new_with_max_length(MAX_SERVER_LINE),
        ),
        timeout: write_timeout,
        dead: false,
    };

    // the FIRST client message must be Hello; nothing is sent
    // to the client before the handshake completes, and a version mismatch
    // or any other opener is answered with Error and the connection closed.
    // Id of the active alert replayed after the handshake: the same request may
    // also sit in this client's own broadcast queue and must not be sent twice.
    let mut replayed_alert_id: Option<u64> = None;
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
                // An alert that is already active was broadcast before this
                // client existed: hand it over right after the handshake.
                let held = active_alert
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                if let Some(alert) = held {
                    if let ServerMessage::AlertRequest { id, .. } = &alert {
                        replayed_alert_id = Some(*id);
                    }
                    if send_server(&mut writer, alert).await.is_err() {
                        return;
                    }
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
                        if let (ServerMessage::AlertRequest { id, .. }, Some(replayed)) =
                            (&msg, replayed_alert_id)
                        {
                            if *id == replayed {
                                replayed_alert_id = None;
                                continue;
                            }
                        }
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
                                // forwarded to the pipeline,
                                // which owns the rule engine and enforcer.
                                forward_command(&commands, &mut writer, Command::SetRules { rules })
                                    .await;
                            }
                            Ok(ClientMessage::GetRules) => {
                                forward_command(&commands, &mut writer, Command::GetRules).await;
                            }
                            Ok(ClientMessage::AlertAnswer { id, verdict, scope, lifetime }) => {
                                forward_command(
                                    &commands,
                                    &mut writer,
                                    Command::AlertAnswer {
                                        id,
                                        verdict,
                                        scope,
                                        lifetime,
                                    },
                                )
                                .await;
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
                                // reply once, then close —
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
        // A reply that timed out (arms above ignore send errors) ends the
        // connection: the line on the wire is incomplete.
        if writer.dead {
            break;
        }
    }
}

#[cfg(all(test, windows))]
mod sddl_tests {
    use super::{security_descriptor, PIPE_SDDL};

    // the pipe DACL must never hand GENERIC_ALL to
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

    // Call-site split: the real conversion path used
    // by start_ipc_server must accept exactly this const.
    #[test]
    fn test_pipe_sddl_converts_through_the_real_path() {
        security_descriptor().expect("PIPE_SDDL must convert to a security descriptor");
    }
}

#[cfg(all(test, windows))]
mod client_auth_tests {
    use super::{admin_group_enabled, client_pid_allowed};

    /// S-1-5-32-544 (Builtin\Administrators) / S-1-5-32-545 (Builtin\Users),
    /// hand-encoded; the tests below re-check each encoding with
    /// IsWellKnownSid so a typo in the helper fails the test, not the check.
    fn builtin_sid(last_rid: u32) -> Vec<u8> {
        vec![
            1, // revision
            2, // sub-authority count
            0,
            0,
            0,
            0,
            0,
            5, // NT authority
            32,
            0,
            0,
            0, // SECURITY_BUILTIN_DOMAIN_RID
            last_rid.to_le_bytes()[0],
            last_rid.to_le_bytes()[1],
            last_rid.to_le_bytes()[2],
            last_rid.to_le_bytes()[3],
        ]
    }

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

    // an unelevated admin's filtered token still LISTS Builtin
    // Administrators, but the group is deny-only there. Only an ENABLED
    // membership (deny-only clear) may admit.
    #[test]
    fn test_admin_group_attribute_check() {
        use windows_sys::Win32::Security::{IsWellKnownSid, WinBuiltinAdministratorsSid, PSID};
        use windows_sys::Win32::System::SystemServices::{
            SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_USE_FOR_DENY_ONLY,
        };

        let admins = builtin_sid(544);
        let users = builtin_sid(545);
        // SAFETY: both vectors are hand-built SIDs of valid layout.
        unsafe {
            assert!(
                IsWellKnownSid(admins.as_ptr() as PSID, WinBuiltinAdministratorsSid) != 0,
                "helper must build the real Builtin Administrators SID"
            );
            assert!(
                IsWellKnownSid(users.as_ptr() as PSID, WinBuiltinAdministratorsSid) == 0,
                "helper must NOT encode Users as Administrators"
            );
        }

        // An enabled admin group admits.
        assert!(
            admin_group_enabled(&[(admins.clone(), SE_GROUP_ENABLED as u32)]),
            "an enabled Administrators group must be accepted"
        );
        // THE defect case: deny-only (filtered token of an unelevated admin)
        // must be refused.
        assert!(
            !admin_group_enabled(&[(admins.clone(), SE_GROUP_USE_FOR_DENY_ONLY as u32)]),
            "a deny-only Administrators group must be refused"
        );
        // Deny wins even when ENABLED is also present.
        assert!(
            !admin_group_enabled(&[(
                admins.clone(),
                (SE_GROUP_ENABLED | SE_GROUP_USE_FOR_DENY_ONLY) as u32
            )]),
            "deny-only must win over ENABLED when both are set"
        );
        // Listed by default but not currently enabled: refused.
        assert!(
            !admin_group_enabled(&[(admins.clone(), SE_GROUP_ENABLED_BY_DEFAULT as u32)]),
            "a listed-but-disabled Administrators group must be refused"
        );
        assert!(
            !admin_group_enabled(&[(admins.clone(), 0)]),
            "attribute-less Administrators membership must be refused"
        );
        // An enabled NON-admin group never admits.
        assert!(
            !admin_group_enabled(&[(users, SE_GROUP_ENABLED as u32)]),
            "an enabled non-admin group must be refused"
        );
        // No groups: no admission.
        assert!(!admin_group_enabled(&[]), "no groups must be refused");
    }
}

#[cfg(test)]
mod decision_tests {
    use super::{groups_from_proc_status, peer_decision};

    const DAEMON: u32 = 995;
    const RAT: u32 = 990;

    #[test]
    fn parses_groups_line() {
        let status =
            "Name:\tx\nUid:\t1000\t1000\t1000\t1000\nGroups:\t4 24 990 1000 \nVmPeak:\t1 kB\n";
        assert_eq!(groups_from_proc_status(status), vec![4, 24, 990, 1000]);
    }

    #[test]
    fn groups_line_missing_empty_or_garbage() {
        assert!(groups_from_proc_status("Name:\tx\n").is_empty());
        assert!(groups_from_proc_status("Groups:\t\n").is_empty());
        assert!(groups_from_proc_status("").is_empty());
        assert_eq!(groups_from_proc_status("Groups:\t5 abc -1 7\n"), vec![5, 7]);
    }

    #[test]
    fn root_and_daemon_user_always_allowed() {
        assert!(peer_decision(0, 1, None, None, DAEMON));
        assert!(peer_decision(DAEMON, 1, None, Some(RAT), DAEMON));
    }

    #[test]
    fn primary_gid_match_allowed() {
        assert!(peer_decision(1000, RAT, None, Some(RAT), DAEMON));
    }

    #[test]
    fn supplementary_gid_match_allowed() {
        assert!(peer_decision(
            1000,
            1000,
            Some(&[4, RAT]),
            Some(RAT),
            DAEMON
        ));
    }

    #[test]
    fn no_match_refused() {
        assert!(!peer_decision(
            1000,
            1000,
            Some(&[4, 24]),
            Some(RAT),
            DAEMON
        ));
        assert!(!peer_decision(1000, 1000, Some(&[]), Some(RAT), DAEMON));
    }

    #[test]
    fn unreadable_proc_refused() {
        assert!(!peer_decision(1000, 1000, None, Some(RAT), DAEMON));
    }

    #[test]
    fn missing_rat_group_refuses_non_privileged() {
        assert!(!peer_decision(1000, 0, Some(&[0]), None, DAEMON));
    }
}

#[cfg(all(test, unix))]
mod peer_tests {
    use super::{effective_uid, peer_allowed};

    // root and the daemon's own user are always allowed;
    // anyone else only via the rat group's gid.
    #[test]
    fn test_peer_allowed_root_and_self() {
        assert!(peer_allowed(0, 9999, None), "root must always be allowed");
        let self_uid = effective_uid();
        assert_ne!(self_uid, u32::MAX, "could not read /proc/self/status");
        assert!(
            peer_allowed(self_uid, 9999, None),
            "the daemon's own uid must be allowed"
        );
    }

    #[test]
    fn test_peer_allowed_missing_pid_fails_closed() {
        let stranger = effective_uid().wrapping_add(1);
        assert!(!peer_allowed(stranger, 9999, None));
        assert!(!peer_allowed(stranger, 9999, Some(i32::MAX)));
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
            !peer_allowed(stranger, gid, None),
            "uid {stranger} with unrelated gid {gid} must be refused"
        );
    }
}

#[cfg(test)]
mod backoff_tests {
    use super::{back_off_after_accept_error, ACCEPT_ERROR_BACKOFF};

    // The accept loops call this after every failed accept; without the pause
    // a persistent error would busy-loop a core.
    #[tokio::test]
    async fn accept_error_backoff_really_waits() {
        let start = std::time::Instant::now();
        back_off_after_accept_error().await;
        let waited = start.elapsed();
        assert!(
            waited >= ACCEPT_ERROR_BACKOFF - std::time::Duration::from_millis(5),
            "returned after only {waited:?}"
        );
    }
}

#[cfg(test)]
mod retry_tests {
    use super::create_with_retry;
    use std::time::{Duration, Instant};

    // A name that frees up within the window is taken over.
    #[tokio::test]
    async fn retries_until_the_creation_succeeds() {
        let mut calls = 0;
        let got = create_with_retry(
            || {
                calls += 1;
                if calls < 4 {
                    Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                } else {
                    Ok(calls)
                }
            },
            Duration::from_secs(5),
            "test pipe",
        )
        .await
        .expect("must succeed once the owner is gone");
        assert_eq!(got, 4);
    }

    // A name that stays owned ends in a clear error after the bounded window,
    // keeping the error kind.
    #[tokio::test]
    async fn gives_up_after_the_window_with_a_clear_error() {
        let window = Duration::from_millis(400);
        let start = Instant::now();
        let mut calls = 0;
        let err = create_with_retry(
            || -> std::io::Result<()> {
                calls += 1;
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            },
            window,
            "test pipe",
        )
        .await
        .expect_err("a pipe that stays owned must fail");
        let waited = start.elapsed();
        assert!(waited >= window, "gave up early after {waited:?}");
        assert!(waited < window + Duration::from_secs(2), "took {waited:?}");
        assert!(calls >= 3, "only {calls} attempts");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        let text = err.to_string();
        assert!(text.contains("test pipe") && text.contains("owned by another process"));
    }
}
