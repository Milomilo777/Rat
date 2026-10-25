use crate::msg::Message;
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
    snapshot_rx: tokio::sync::broadcast::Receiver<Message>,
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
                        tokio::spawn(async move {
                            let _permit = permit;
                            handle_connection(stream, snap_rx).await;
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

#[cfg(windows)]
pub async fn start_ipc_server(
    pipe_name: &str,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    snapshot_rx: tokio::sync::broadcast::Receiver<Message>,
) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorA;

    // S2 (update-08): no per-client identity check on Windows. The pipe is
    // deliberately open to Interactive Users for the GUI; they hold only
    // read/write (PIPE_SDDL, S1) and cannot create instances or change the
    // DACL. A token check can be added with GetNamedPipeClientProcessId when
    // the GUI/daemon handshake (PROPOSALS) lands.
    const SDDL_REVISION_1: u32 = 1;

    let sd_val = {
        let sddl = PIPE_SDDL.as_bytes();
        let mut sd_ptr_inner: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut sd_size = 0;

        let success = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorA(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd_ptr_inner,
                &mut sd_size,
            )
        };

        if success == 0 {
            return Err(std::io::Error::last_os_error());
        }
        sd_ptr_inner as isize
    };

    let sd_guard = std::sync::Arc::new(SdGuard(sd_val));

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
                        // S3 (update-08): at capacity the extra client's pipe
                        // end is dropped instead of spawning another handler.
                        let permit = match client_slots.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => continue,
                        };
                        let snap_rx = snapshot_rx.resubscribe();
                        tokio::spawn(async move {
                            let _permit = permit;
                            handle_connection(server, snap_rx).await;
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

async fn handle_connection<S>(stream: S, mut snapshot_rx: tokio::sync::broadcast::Receiver<Message>)
where
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

    loop {
        tokio::select! {
            msg = snapshot_rx.recv() => {
                match msg {
                    Ok(msg) => {
                        if let Ok(serialized) = msg.to_string() {
                            if writer.send(serialized).await.is_err() {
                                break;
                            }
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
                        match Message::from_json_str(&line) {
                            Ok(_msg) => {
                                // Ignore incoming messages for now, just handle them
                            }
                            Err(_) => {
                                // S10 (update-08): reply once, then close —
                                // a client that cannot produce a valid
                                // message gets no second attempt.
                                let err_msg =
                                    Message::Error { message: "Invalid JSON".to_string() };
                                if let Ok(err_ser) = err_msg.to_string() {
                                    let _ = writer.send(err_ser).await;
                                }
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        let err_msg = Message::Error { message: format!("LinesCodec error: {}", e) };
                        if let Ok(err_ser) = err_msg.to_string() {
                            let _ = writer.send(err_ser).await;
                        }
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
    use super::PIPE_SDDL;

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
