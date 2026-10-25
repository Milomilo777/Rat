#[cfg(unix)]
fn main() -> std::io::Result<()> {
    if std::env::args().any(|a| a == "--cleanup") {
        return rat_daemon::run_cleanup();
    }

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

        rat_daemon::run_daemon(shutdown_rx).await
    })
}

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    // Uninstall path (#8): `rat-daemon --cleanup` removes every rule this
    // daemon created and exits. Checked before the SCM dispatcher — the
    // service is never launched with this argument.
    if std::env::args().any(|a| a == "--cleanup") {
        return rat_daemon::run_cleanup();
    }

    // service_dispatcher::start only succeeds when the Service Control Manager
    // launched us; run by hand it errors immediately and we fall back to console.
    match rat_daemon::service::windows::run_service() {
        Ok(()) => Ok(()),
        Err(_) => run_console(),
    }
}

#[cfg(windows)]
fn run_console() -> std::io::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = shutdown_tx.send(());
        });
        rat_daemon::run_daemon(shutdown_rx).await
    })
}
