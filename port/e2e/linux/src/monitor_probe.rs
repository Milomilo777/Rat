//! Takes one `rat-monitor-linux` sample of /proc and prints it as JSON
//! (the same `Connection` structs the daemon puts in a Snapshot).
use rat_monitor_linux::LinuxMonitor;
use rat_types::ConnectionSource;
use std::path::PathBuf;

fn main() {
    // `monitor-probe diag`: dump the raw sock_diag byte counters (inode -> in/out).
    if std::env::args().nth(1).as_deref() == Some("diag") {
        let map = rat_monitor_linux::diag::get_socket_counters();
        let mut rows: Vec<_> = map.iter().collect();
        rows.sort_by_key(|&(k, _)| *k);
        println!("DIAG count={}", rows.len());
        for (inode, c) in rows {
            println!("{} in={:?} out={:?}", inode, c.bytes_in, c.bytes_out);
        }
        return;
    }
    let mut monitor = LinuxMonitor::new(PathBuf::from("/proc"));
    match monitor.sample() {
        Ok(conns) => match serde_json::to_string(&conns) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("serialize error: {}", e);
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("sample error: {}", e);
            std::process::exit(1);
        }
    }
}
