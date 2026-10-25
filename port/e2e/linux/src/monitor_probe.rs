//! Takes one `rat-monitor-linux` sample of /proc and prints it as JSON
//! (the same `Connection` structs the daemon puts in a Snapshot).
use rat_monitor_linux::LinuxMonitor;
use rat_types::ConnectionSource;
use std::path::PathBuf;

fn main() {
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
