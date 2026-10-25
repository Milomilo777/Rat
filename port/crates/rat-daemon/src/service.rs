#[cfg(windows)]
pub mod windows {
    use std::ffi::OsString;
    use std::time::Duration;
    use tokio::sync::broadcast;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    const SERVICE_NAME: &str = "rat-daemon";

    define_windows_service!(ffi_service_main, my_service_main);

    pub fn run_service() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn my_service_main(arguments: Vec<OsString>) {
        if let Err(_e) = run_service_inner(arguments) {
            // Log error
        }
    }

    fn run_service_inner(_arguments: Vec<OsString>) -> windows_service::Result<()> {
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let status_handle = service_control_handler::register(
            SERVICE_NAME,
            move |control_event| match control_event {
                ServiceControl::Stop => {
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        )?;

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        // Run the sampling loop and IPC server until the SCM asks us to stop.
        // A failed run (e.g. a second daemon found the pipe already owned)
        // stops the service with a non-zero Win32 exit code.
        let exit_code = if let Ok(rt) = tokio::runtime::Runtime::new() {
            match rt.block_on(crate::run_daemon(shutdown_rx)) {
                Ok(()) => ServiceExitCode::Win32(0),
                Err(e) => {
                    eprintln!("rat-daemon service run failed: {e}");
                    ServiceExitCode::Win32(e.raw_os_error().unwrap_or(1) as u32)
                }
            }
        } else {
            ServiceExitCode::Win32(1)
        };

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        Ok(())
    }
}
