use rat_monitor_windows::WindowsMonitor;
use rat_types::ConnectionSource;

pub fn run_w5() {
    println!("Starting W5 Shared Services test");
    let mut monitor = WindowsMonitor::new();
    let conns = monitor.sample().unwrap();

    for c in conns {
        if c.process.name.to_lowercase() == "svchost.exe" {
            println!("svchost connection: {:?}", c);
        }
    }
}
