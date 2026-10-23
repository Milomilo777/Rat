use crate::msg::Message;
use futures::{SinkExt, StreamExt};
use tokio_util::codec::Framed;

pub const SOCKET_PATH: &str = "/run/rat/rat.sock";
pub const PIPE_NAME: &str = r"\\.\pipe\rat";

#[cfg(unix)]
pub async fn start_ipc_server(
    socket_path: &str,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    snapshot_rx: tokio::sync::broadcast::Receiver<Message>,
) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)?;

    // Only set permissions if it's the real run path to avoid test errors
    if socket_path == SOCKET_PATH {
        let mut perms = std::fs::metadata(socket_path)?.permissions();
        perms.set_mode(0o660);
        std::fs::set_permissions(socket_path, perms)?;
    }

    loop {
        tokio::select! {
            _ = shutdown.recv() => {
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok((stream, _)) => {
                        let snap_rx = snapshot_rx.resubscribe();
                        tokio::spawn(async move {
                            handle_connection(stream, snap_rx).await;
                        });
                    }
                    Err(_) => {
                        // ignore errors like connection reset
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
pub async fn start_ipc_server(
    pipe_name: &str,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
    snapshot_rx: tokio::sync::broadcast::Receiver<Message>,
) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorA;

    const SDDL_REVISION_1: u32 = 1;

    let sd_val = {
        let sddl = b"D:(A;;GA;;;IU)(A;;GA;;;BA)\0";
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
                        let snap_rx = snapshot_rx.resubscribe();
                        tokio::spawn(async move {
                            handle_connection(server, snap_rx).await;
                        });
                    }
                    Err(_) => {
                        // ignore errors like connection reset
                    }
                }
            }
        }
    }
    // ensure sd_guard drops here
    let _ = sd_guard;
    Ok(())
}

async fn handle_connection<S>(stream: S, mut snapshot_rx: tokio::sync::broadcast::Receiver<Message>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let codec = tokio_util::codec::LinesCodec::new_with_max_length(10 * 1024 * 1024);
    let mut framed = Framed::new(stream, codec);

    loop {
        tokio::select! {
            msg = snapshot_rx.recv() => {
                match msg {
                    Ok(msg) => {
                        if let Ok(serialized) = serde_json::to_string(&msg) {
                            if framed.send(serialized).await.is_err() {
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
            result = framed.next() => {
                match result {
                    Some(Ok(line)) => {
                        match serde_json::from_str::<Message>(&line) {
                            Ok(_msg) => {
                                // Ignore incoming messages for now, just handle them
                            }
                            Err(_) => {
                                let err_msg = Message::Error { message: "Invalid JSON".to_string() };
                                if let Ok(err_ser) = serde_json::to_string(&err_msg) {
                                    let _ = framed.send(err_ser).await;
                                }
                            }
                        }
                    }
                    Some(Err(e)) => {
                        let err_msg = Message::Error { message: format!("LinesCodec error: {}", e) };
                        if let Ok(err_ser) = serde_json::to_string(&err_msg) {
                            let _ = framed.send(err_ser).await;
                        }
                        break;
                    }
                    None => break,
                }
            }
        }
    }
}
