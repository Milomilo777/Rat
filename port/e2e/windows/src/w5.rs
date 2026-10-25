//! W5 Shared services: report which connections are attributed to svchost.exe
//! and whether a service name is known. Report-only (no blocking).
use crate::common::Report;
use rat_monitor_windows::WindowsMonitor;
use rat_types::ConnectionSource;

pub fn run(r: &mut Report) {
    let mut monitor = WindowsMonitor::new();
    let conns = match monitor.sample() {
        Ok(c) => c,
        Err(e) => return r.harness("sample", format!("{e}")),
    };
    if conns.is_empty() {
        return r.harness("sample", "monitor returned no connection at all");
    }
    r.pass("sample", format!("{} connections sampled", conns.len()));

    let sv: Vec<_> = conns
        .iter()
        .filter(|c| {
            c.process.name.to_lowercase().starts_with("svchost")
                || c.process.exe.as_ref().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().eq_ignore_ascii_case("svchost.exe")) == Some(true)
        })
        .collect();
    for c in sv.iter().take(15) {
        println!("W5 svchost: pid={} name={} exe={:?} {:?} {:?}->{:?} listening={}", c.process.pid, c.process.name, c.process.exe, c.protocol, c.local, c.remote, c.listening);
    }
    let pids: std::collections::BTreeSet<u32> = sv.iter().map(|c| c.process.pid).collect();
    println!("W5 REPORT svchost connections={} distinct svchost pids={}", sv.len(), pids.len());
    println!("W5 REPORT service name known: ProcessInfo exposes only pid/exe/name/user; no per-connection service name field -> NOT known (all svchost.exe instances look alike)");
    r.pass("report", format!("{} svchost connections over {} processes listed (informational)", sv.len(), pids.len()));
}
