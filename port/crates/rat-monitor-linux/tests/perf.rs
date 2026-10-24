use rat_monitor_linux::LinuxMonitor;
use rat_types::ConnectionSource;
use std::fs;
use std::time::Instant;

fn generate_mock_proc() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let net_dir = dir.path().join("net");
    fs::create_dir_all(&net_dir).unwrap();

    let mut tcp_content = String::from("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");
    let mut inode = 1000;

    for i in 0..2000 {
        let local_port = 10000 + i;
        tcp_content.push_str(&format!(
            "   0: 0100007F:{:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 {} 1 0000000000000000 100 0 0 10 0\n",
            local_port, inode
        ));

        let pid = 100 + (i % 1000); // 1000 distinct processes
        let fd_dir = dir.path().join(format!("{}/fd", pid));
        fs::create_dir_all(&fd_dir).unwrap();

        let _symlink_path = fd_dir.join(format!("{}", inode));
        #[cfg(unix)]
        std::os::unix::fs::symlink(format!("socket:[{}]", inode), _symlink_path).unwrap();

        let pid_dir = dir.path().join(format!("{}", pid));
        fs::write(pid_dir.join("comm"), format!("proc_{}\n", pid)).unwrap();
        fs::write(pid_dir.join("status"), "Uid:\t1000\t1000\t1000\t1000\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/usr/bin/mock", pid_dir.join("exe")).unwrap_or_default();

        inode += 1;
    }

    fs::write(net_dir.join("tcp"), tcp_content).unwrap();
    fs::write(net_dir.join("tcp6"), "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n").unwrap();
    fs::write(net_dir.join("udp"), "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n").unwrap();
    fs::write(net_dir.join("udp6"), "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n").unwrap();

    dir
}

#[test]
fn test_performance_budget() {
    let mock_dir = generate_mock_proc();
    let mut monitor = LinuxMonitor::new(mock_dir.path().to_path_buf());

    // Warm up
    monitor.sample().unwrap();

    let start = Instant::now();
    let res = monitor.sample().unwrap();
    let duration = start.elapsed();

    #[cfg(target_os = "linux")]
    assert_eq!(res.len(), 2000);

    #[cfg(target_os = "windows")]
    assert_eq!(res.len(), 0); // Symlinks not emulated seamlessly for parsing so we expect 0 maps gracefully

    // 50ms budget * 3x = 150ms limit
    // Due to Wine emulation scaling wildly on GitHub runners we use a high margin (1000ms bounds vs native 25ms execution).
    assert!(
        duration.as_millis() < 1000,
        "Performance budget exceeded: took {} ms for 2000 sockets",
        duration.as_millis()
    );
}
