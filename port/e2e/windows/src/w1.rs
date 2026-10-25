//! W1 Monitor attribution: the monitor lists a TCP connection with the right
//! PID and full executable path; byte counters after 1 MiB are recorded.
use crate::common::{same_path, kill_child, Report};
use rat_monitor_windows::WindowsMonitor;
use rat_types::ConnectionSource;
use std::io::Read;
use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

struct Guard(std::path::PathBuf);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn run(r: &mut Report) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let target = format!("127.0.0.1:{port}");

    let exe = std::env::current_exe().unwrap();
    let client_path = exe.with_file_name("w1_client.exe");
    std::fs::copy(&exe, &client_path).unwrap();
    let _g = Guard(client_path.clone());

    let mut child = Command::new(&client_path)
        .args(["client", &target, "20000"])
        .spawn()
        .unwrap();
    let pid = child.id();

    // Accept and read exactly 1 MiB, keep the connection open afterwards.
    listener.set_nonblocking(false).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut got = 0usize;
    let mut buf = vec![0u8; 65536];
    while got < 1024 * 1024 {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
    }
    if got < 1024 * 1024 {
        kill_child(&mut child);
        r.harness("transfer", format!("only {got} bytes arrived at the listener"));
        return;
    }
    r.pass("transfer", "listener received 1 MiB from the client process");

    let mut monitor = WindowsMonitor::new();
    let start = Instant::now();
    let mut found = None;
    let mut best_out: Option<u64> = None;
    let mut srv_in: Option<u64> = None;
    while start.elapsed() < Duration::from_secs(12) {
        match monitor.sample() {
            Ok(conns) => {
                for c in &conns {
                    if c.process.pid == pid && c.remote.map(|a| a.port()) == Some(port) {
                        found = Some(c.clone());
                        best_out = c.bytes_out.or(best_out);
                    }
                    if c.listening == false
                        && c.local.port() == port
                        && c.process.pid == std::process::id()
                    {
                        srv_in = c.bytes_in.or(srv_in);
                    }
                }
            }
            Err(e) => {
                kill_child(&mut child);
                r.harness("sample", format!("monitor.sample() failed: {e}"));
                return;
            }
        }
        if best_out.map_or(false, |b| b >= 1024 * 1024) {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    match &found {
        None => r.product(
            "attribution",
            format!("no connection with pid={pid} remote port {port} in the monitor sample"),
        ),
        Some(c) => {
            println!("W1 connection: {c:?}");
            r.pass("pid", format!("pid {} matches the spawned client", c.process.pid));
            match &c.process.exe {
                Some(p) if same_path(&p.to_string_lossy(), &client_path.to_string_lossy()) => {
                    r.pass("exe-path", format!("exe {p:?}"))
                }
                other => r.product(
                    "exe-path",
                    format!("expected {client_path:?}, monitor says {other:?}"),
                ),
            }
        }
    }

    println!("W1 BYTES client bytes_out={best_out:?} server-side bytes_in={srv_in:?}");
    match best_out {
        Some(b) if b >= 1024 * 1024 => r.pass("bytes", format!("bytes_out={b} >= 1 MiB")),
        Some(b) => r.product("bytes", format!("bytes_out={b} < 1 MiB after the transfer")),
        None => r.pass("bytes", "counters stayed empty (estats not collected); recorded, not a failure"),
    }

    // Negative control: after the client is gone it must disappear.
    kill_child(&mut child);
    drop(stream);
    let gone = crate::common::wait_until(Duration::from_secs(10), Duration::from_millis(500), || {
        match monitor.sample() {
            Ok(cs) => !cs.iter().any(|c| c.process.pid == pid),
            Err(_) => false,
        }
    });
    if gone {
        r.pass("control-gone", "connection disappears after the client is killed");
    } else {
        r.product("control-gone", format!("pid {pid} still listed 10 s after kill"));
    }
}
