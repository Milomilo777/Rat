#[cfg(target_os = "linux")]
mod tests {
    use rat_monitor_linux::LinuxMonitor;
    use rat_types::ConnectionSource;
    use std::net::TcpListener;

    #[test]
    fn test_real_tcp_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let mut monitor = LinuxMonitor::new();
        let conns = monitor.sample().unwrap();

        let my_pid = std::process::id();

        let mut found = false;
        for c in conns {
            if c.local.port() == port && c.process.pid == my_pid {
                found = true;
                break;
            }
        }

        assert!(
            found,
            "Could not find our own listener socket in real /proc"
        );
    }
}
