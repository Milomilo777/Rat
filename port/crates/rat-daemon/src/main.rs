use rat_types::{Connection, ConnectionSource};

struct FakeSource;
impl ConnectionSource for FakeSource {
    fn sample(&mut self) -> std::io::Result<Vec<Connection>> {
        Ok(vec![])
    }
}

pub async fn run_daemon(shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
    let (snapshot_tx, snapshot_rx) = tokio::sync::broadcast::channel(16);

    let source = FakeSource;

    let shutdown_core = shutdown_rx.resubscribe();
    let shutdown_ipc = shutdown_rx.resubscribe();

    let core_task = tokio::spawn(async move {
        rat_daemon::core::run_core_loop(source, snapshot_tx, shutdown_core).await;
    });

    let ipc_task = tokio::spawn(async move {
        #[cfg(unix)]
        let _ = rat_daemon::ipc::start_ipc_server(
            rat_daemon::ipc::SOCKET_PATH,
            shutdown_ipc,
            snapshot_rx,
        )
        .await;
        #[cfg(windows)]
        let _ = rat_daemon::ipc::start_ipc_server(
            rat_daemon::ipc::PIPE_NAME,
            shutdown_ipc,
            snapshot_rx,
        )
        .await;
    });

    let _ = tokio::join!(core_task, ipc_task);
}

#[cfg(unix)]
fn main() -> std::io::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        use tokio::signal::unix::{signal, SignalKind};

        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

        tokio::spawn(async move {
            if let (Ok(mut sigterm), Ok(mut sigint)) = (
                signal(SignalKind::terminate()),
                signal(SignalKind::interrupt()),
            ) {
                tokio::select! {
                    _ = sigterm.recv() => {}
                    _ = sigint.recv() => {}
                }
            } else {
                let _ = tokio::signal::ctrl_c().await;
            }
            let _ = shutdown_tx.send(());
        });

        run_daemon(shutdown_rx).await;
    });
    Ok(())
}

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    // If run as a service, windows_service::service_dispatcher::start is used.
    // We'll just assume service mode for now or fallback to console.
    let is_service = true; // In a real app we might detect this.
    if is_service {
        if let Err(e) = rat_daemon::service::windows::run_service() {
            eprintln!("Service error: {}", e);
        }
    } else {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = shutdown_tx.send(());
            });
            run_daemon(shutdown_rx).await;
        });
    }
    Ok(())
}
