use criterion::{criterion_group, criterion_main, Criterion};
use rat_monitor_linux::LinuxMonitor;
use rat_types::ConnectionSource;
use std::fs;
use std::hint::black_box;
use tempfile::TempDir;

fn generate_mock_proc() -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let net_dir = dir.path().join("net");
    fs::create_dir_all(&net_dir).unwrap();

    let mut tcp_content = String::from("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");

    // Generate 2000 sockets
    for (i, inode) in (0..2000).zip(1000u64..) {
        let local_port = 10000 + i;
        tcp_content.push_str(&format!(
            "   0: 0100007F:{:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 {} 1 0000000000000000 100 0 0 10 0\n",
            local_port, inode
        ));

        let pid = 100 + (i % 1000); // 1000 distinct processes
        let fd_dir = dir.path().join(format!("{}/fd", pid));
        fs::create_dir_all(&fd_dir).unwrap();

        // Unfortunately standard fs::hard_link/symlink works, but for reading symlink it must be a real symlink
        // Creating 2000 symlinks takes a few ms but is OK for harness setup
        let _symlink_path = fd_dir.join(format!("{}", inode));
        #[cfg(unix)]
        std::os::unix::fs::symlink(format!("socket:[{}]", inode), _symlink_path).unwrap();

        // Write comm and status and exe
        let pid_dir = dir.path().join(format!("{}", pid));
        fs::write(pid_dir.join("comm"), format!("proc_{}\n", pid)).unwrap();
        fs::write(pid_dir.join("status"), "Uid:\t1000\t1000\t1000\t1000\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/usr/bin/mock", pid_dir.join("exe")).unwrap_or_default();
    }

    fs::write(net_dir.join("tcp"), tcp_content).unwrap();
    fs::write(net_dir.join("tcp6"), "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n").unwrap();
    fs::write(net_dir.join("udp"), "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n").unwrap();
    fs::write(net_dir.join("udp6"), "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n").unwrap();

    dir
}

fn bench_monitor(c: &mut Criterion) {
    let mock_dir = generate_mock_proc();
    let mut monitor = LinuxMonitor::new(mock_dir.path().to_path_buf());

    // Pre-warm so we don't benchmark disk caches heavily if they matter,
    // although tmpfs/memory usually backs TempDir
    monitor.sample().unwrap();

    c.bench_function("monitor_sample_2000", |b| {
        b.iter(|| {
            let res = monitor.sample().unwrap();
            black_box(res);
        })
    });
}

criterion_group!(benches, bench_monitor);
criterion_main!(benches);
