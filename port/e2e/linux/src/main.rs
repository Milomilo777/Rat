use rat_types::ConnectionSource;
use rat_monitor_linux::LinuxMonitor;
use rat_enforcer::linux::LinuxEnforcer;
use rat_enforcer::{Blocklist, Enforcer};
use std::time::Duration;
use std::path::PathBuf;
use std::process::{Command, Stdio, Child};
use tokio::time::sleep;
use tokio::net::{TcpListener, TcpStream};
use std::fs;

struct CleanupGuard {
    files: Vec<PathBuf>,
    daemon_started: bool,
    children: Vec<Child>,
}

impl CleanupGuard {
    fn new() -> Self { Self { files: Vec::new(), daemon_started: false, children: Vec::new() } }
    fn add_file(&mut self, path: PathBuf) { self.files.push(path); }
    fn add_child(&mut self, child: Child) { self.children.push(child); }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        for f in &self.files { let _ = fs::remove_file(f); }
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = LinuxEnforcer.cleanup();

        if self.daemon_started {
            let _ = Command::new("sudo").args(["systemctl", "stop", "rat-daemon"]).status();
            let _ = Command::new("sudo").args(["systemctl", "disable", "rat-daemon"]).status();
            let _ = Command::new("sudo").args(["rm", "-f", "/etc/systemd/system/rat-daemon.service"]).status();
            let _ = Command::new("sudo").args(["systemctl", "daemon-reload"]).status();
        }
    }
}

async fn ensure_daemon(guard: &mut CleanupGuard) -> Result<(), String> {
    let mut unit_src = PathBuf::from("port/packaging/linux/rat-daemon.service");
    if !unit_src.exists() {
        unit_src = PathBuf::from("../../packaging/linux/rat-daemon.service");
    }
    if !unit_src.exists() {
        unit_src = PathBuf::from("/home/runner/work/Rat/Rat/port/packaging/linux/rat-daemon.service");
    }
    if !unit_src.exists() {
        unit_src = PathBuf::from("/app/port/packaging/linux/rat-daemon.service");
    }

    if !unit_src.exists() {
        return Err(format!("Unit not found, last tried: {:?}", unit_src).into());
    }

    let _ = Command::new("sudo").args(["groupadd", "-f", "rat"]).status();
    let cp_st = Command::new("sudo").args(["cp", unit_src.to_str().unwrap(), "/etc/systemd/system/"]).status();
    if cp_st.is_err() || !cp_st.unwrap().success() { return Err("Failed to cp systemd unit".into()); }

    let dr_st = Command::new("sudo").args(["systemctl", "daemon-reload"]).status();
    if dr_st.is_err() || !dr_st.unwrap().success() { return Err("Failed systemctl daemon-reload".into()); }

    let st_st = Command::new("sudo").args(["systemctl", "start", "rat-daemon"]).status();
    if st_st.is_err() || !st_st.unwrap().success() { return Err("Failed to start rat-daemon".into()); }
    guard.daemon_started = true;

    let mut socket_ready = false;
    for _ in 0..20 {
         if std::fs::metadata("/run/rat/rat.sock").is_ok() { socket_ready = true; break; }
         sleep(Duration::from_millis(100)).await;
    }

    if !socket_ready { return Err("Daemon socket missing after start".into()); }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Running E2E tests...");

    if !std::path::Path::new("/proc").exists() {
        println!("Skipping since /proc doesn't exist");
        return Ok(());
    }

    // In CI we just run as-is, since workflow builds test-client and copies daemon.

    let mut results: Vec<(&'static str, &'static str, String)> = vec![];

    macro_rules! run_test {
        ($test:expr, $name:expr) => {
            println!("--- Running {} ---", $name);
            match $test.await {
                Ok(_) => { println!("{} PASS", $name); results.push(($name, "PASS", "".to_string())); },
                Err(e) => {
                    let is_fail_product = e.contains("FAIL-PRODUCT");
                    let prefix = if is_fail_product { "" } else { "FAIL-PRODUCT: " };
                    println!("{} Error: {}{}", $name, prefix, e);
                    results.push(($name, "FAIL-PRODUCT", format!("{}{}", prefix, e)));
                }
            }
        };
    }

    run_test!(test_l1_monitor_attribution(), "L1");
    run_test!(test_l2_enforcer_real_rules(), "L2");
    run_test!(test_l3_per_app_isolation(), "L3");
    run_test!(test_l4_short_lived_processes(), "L4");
    run_test!(test_l5_daemon_lifecycle(), "L5");
    run_test!(test_l6_gui_to_daemon_gap(), "L6");

    let failed = results.iter().filter(|(_, status, _)| *status == "FAIL-PRODUCT").count();

    println!("--- E2E Summary ---");
    for (name, status, err) in results {
        if !err.is_empty() {
             println!("{}: {} {}", name, status, err);
        } else {
             println!("{}: {}", name, status);
        }
    }

    if failed > 0 {
        std::process::exit(1);
    }

    println!("All E2E tests passed.");
    Ok(())
}

fn test_client_path() -> PathBuf {
    std::env::current_exe().unwrap().parent().unwrap().join("test-client")
}

fn get_nft_ruleset() -> String {
    let out = Command::new("sudo").args(["nft", "list", "ruleset"]).output();
    if let Ok(out) = out { String::from_utf8_lossy(&out.stdout).to_string() } else { String::new() }
}

async fn test_l1_monitor_attribution() -> Result<(), String> {
    let mut guard = CleanupGuard::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = vec![0; 1024 * 1024];
            let _ = socket.read_exact(&mut buf).await;
        }
    });

    let client_exec = test_client_path();
    if !client_exec.exists() {
         return Err("test-client executable not found".into());
    }
    let mut client = Command::new(&client_exec).arg("127.0.0.1").arg(port.to_string()).stdin(Stdio::piped()).spawn().unwrap();
    let client_id = client.id();

    let mut stdin = client.stdin.take().unwrap();
    guard.add_child(client);

    std::thread::spawn(move || {
        use std::io::Write;
        let chunk = vec![1u8; 1024 * 100];
        for _ in 0..15 { let _ = stdin.write_all(&chunk); std::thread::sleep(Duration::from_millis(10)); }
    });

    let mut monitor = LinuxMonitor::new(PathBuf::from("/proc"));
    let mut found = false;
    let mut bytes_out_valid = false;

    for _ in 0..20 {
        sleep(Duration::from_millis(50)).await;
        for conn in monitor.sample().unwrap_or_default() {
            if conn.process.pid == client_id && conn.remote.is_some_and(|r| r.port() == port) {
                found = true;
                if let Some(out) = conn.bytes_out {
                    if out >= 1024 * 1024 { bytes_out_valid = true; }
                }
            }
        }
        if found && bytes_out_valid { break; }
    }

    if !found { return Err("L1: Client connection not detected".into()); }
    if !bytes_out_valid { return Err("FAIL-PRODUCT: L1: Bytes out counter not properly returning >= 1MB".into()); }
    Ok(())
}

async fn test_l2_enforcer_real_rules() -> Result<(), String> {
    let mut guard = CleanupGuard::new();
    let enforcer = LinuxEnforcer;
    let ruleset_before = get_nft_ruleset();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        loop { if let Ok((mut socket, _)) = listener.accept().await { let _ = socket.write_all(b"hello").await; } }
    });

    let client_exec = test_client_path();
    let client = Command::new(&client_exec).arg("127.0.0.1").arg(port.to_string()).arg("loop").spawn().unwrap();
    let client_id = client.id();
    guard.add_child(client);

    sleep(Duration::from_millis(100)).await;

    let mut monitor = LinuxMonitor::new(PathBuf::from("/proc"));
    let mut c_local_port = 0;

    for c in monitor.sample().unwrap_or_default() {
        if c.process.pid == client_id { c_local_port = c.local.port(); }
    }

    let blocklist = Blocklist { paths: vec![], local_ports: vec![c_local_port] };

    // Negative control
    std::env::set_var("RAT_DRY_RUN", "1");
    let apply_res = enforcer.apply(&enforcer.plan(&blocklist));
    if apply_res.is_err() {
         return Err("FAIL-PRODUCT: L2 Apply error (dry run)".into());
    }

    // Wait to confirm connection still works during dry run
    let is_blocked_dry = match tokio::time::timeout(
        Duration::from_millis(500),
        async {
            TcpStream::connect(("127.0.0.1", port)).await
        }
    ).await {
        Ok(Ok(_)) => false,
        _ => true,
    };
    if is_blocked_dry {
        return Err("FAIL-PRODUCT: L2 Negative Control: Traffic blocked during dry run".into());
    }
    std::env::remove_var("RAT_DRY_RUN");

    enforcer.apply(&enforcer.plan(&blocklist)).map_err(|e| format!("FAIL-PRODUCT: L2 Apply error: {}", e))?;

    let status = Command::new("sudo").args(["nft", "-j", "list", "table", "inet", "rat"]).status().unwrap();
    if !status.success() { return Err("FAIL-PRODUCT: L2: Failed to list nft table".into()); }

    // To test if blocked correctly, kill the old client to release c_local_port
    let mut client = guard.children.pop().unwrap();
    let _ = client.kill();
    let _ = client.wait();

    let is_blocked = match tokio::time::timeout(
        Duration::from_millis(500),
        async {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.set_reuseport(true).unwrap_or(());
            socket.set_reuseaddr(true).unwrap_or(());
            if let Ok(_) = socket.bind(format!("127.0.0.1:{}", c_local_port).parse().unwrap()) {
                 socket.connect(format!("127.0.0.1:{}", port).parse().unwrap()).await
            } else {
                 Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, "in use"))
            }
        }
    ).await {
        Ok(Ok(_)) => false,
        Ok(Err(e)) => if e.kind() == std::io::ErrorKind::AddrInUse { return Err("L2 Error: Address still in use".to_string()); } else { true },
        _ => true,
    };

    enforcer.cleanup().unwrap();

    let ruleset_after = get_nft_ruleset();
    if ruleset_before != ruleset_after { return Err("FAIL-PRODUCT: L2: Host ruleset modified beyond `inet rat` table".into()); }
    if !is_blocked { return Err("FAIL-PRODUCT: L2: Traffic was not blocked by enforcer".into()); }

    Ok(())
}

async fn test_l3_per_app_isolation() -> Result<(), String> {
    let mut guard = CleanupGuard::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        loop { if let Ok((mut socket, _)) = listener.accept().await { let _ = socket.write_all(b"hello").await; } }
    });

    let app_a_path = std::env::current_exe().unwrap().parent().unwrap().join("app_a_exec");
    let app_b_path = std::env::current_exe().unwrap().parent().unwrap().join("app_b_exec");
    std::fs::copy(test_client_path(), &app_a_path).unwrap();
    std::fs::copy(test_client_path(), &app_b_path).unwrap();
    guard.add_file(app_a_path.clone());
    guard.add_file(app_b_path.clone());
    std::fs::set_permissions(&app_a_path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&app_b_path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

    let client_a = Command::new(&app_a_path).arg("127.0.0.1").arg(port.to_string()).arg("loop").spawn().unwrap();
    let client_b = Command::new(&app_b_path).arg("127.0.0.1").arg(port.to_string()).arg("loop").spawn().unwrap();
    let client_a_id = client_a.id();
    let client_b_id = client_b.id();
    guard.add_child(client_a);
    guard.add_child(client_b);

    sleep(Duration::from_millis(100)).await;

    let mut monitor = LinuxMonitor::new(PathBuf::from("/proc"));
    let mut a_local_port = 0;

    for c in monitor.sample().unwrap_or_default() {
        if c.process.pid == client_a_id { a_local_port = c.local.port(); }
    }

    let enforcer = LinuxEnforcer;
    let blocklist = Blocklist { paths: vec![app_a_path.to_string_lossy().to_string()], local_ports: if a_local_port > 0 { vec![a_local_port] } else { vec![] } };
    enforcer.apply(&enforcer.plan(&blocklist)).map_err(|e| format!("FAIL-PRODUCT: L3 Enforcer apply error: {}", e))?;

    let mut b_local_port = 0;
    for c in monitor.sample().unwrap_or_default() {
        if c.process.pid == client_b_id { b_local_port = c.local.port(); }
    }

    // Kill processes so we can rebind
    let mut c_b = guard.children.pop().unwrap(); let _ = c_b.kill(); let _ = c_b.wait();
    let mut c_a = guard.children.pop().unwrap(); let _ = c_a.kill(); let _ = c_a.wait();

    let a_blocked = match tokio::time::timeout(
        Duration::from_millis(500),
        async {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.set_reuseaddr(true).unwrap_or(());
            if let Ok(_) = socket.bind(format!("127.0.0.1:{}", a_local_port).parse().unwrap()) {
                 socket.connect(format!("127.0.0.1:{}", port).parse().unwrap()).await
            } else {
                 Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, "in use"))
            }
        }
    ).await {
        Ok(Ok(_)) => false,
        Ok(Err(e)) => if e.kind() == std::io::ErrorKind::AddrInUse { return Err("L3 Error: Address still in use".to_string()); } else { true },
        _ => true,
    };

    let b_blocked = match tokio::time::timeout(
        Duration::from_millis(500),
        async {
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.set_reuseaddr(true).unwrap_or(());
            if let Ok(_) = socket.bind(format!("127.0.0.1:{}", b_local_port).parse().unwrap()) {
                 socket.connect(format!("127.0.0.1:{}", port).parse().unwrap()).await
            } else {
                 Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, "in use"))
            }
        }
    ).await {
        Ok(Ok(_)) => false,
        Ok(Err(e)) => if e.kind() == std::io::ErrorKind::AddrInUse { return Err("L3 Error: Address still in use".to_string()); } else { true },
        _ => true,
    };

    if !a_blocked {
        return Err("FAIL-PRODUCT: L3: App A was not blocked by its rule".into());
    }

    if b_blocked {
        return Err("FAIL-PRODUCT: L3: App B was blocked when it shouldn't be (isolation failed)".into());
    }

    Ok(())
}

async fn test_l4_short_lived_processes() -> Result<(), String> {
    let mut guard = CleanupGuard::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { loop { let _ = listener.accept().await; } });

    let mut monitor = LinuxMonitor::new(PathBuf::from("/proc"));
    let mut hits = 0;
    let n = 100;
    let tmp_path = test_client_path();

    for i in 0..n {
        let mut client = Command::new(&tmp_path).arg("127.0.0.1").arg(port.to_string()).arg("loop").spawn().unwrap();
        let client_id = client.id();
        guard.add_child(client);

        let mut found = false;
        let mut c_local_port = 0;
        for _ in 0..20 {
            if let Ok(conns) = monitor.sample() {
                for c in conns { if c.process.pid == client_id { found = true; c_local_port = c.local.port(); break; } }
            }
            if found { break; }
            sleep(Duration::from_millis(5)).await;
        }
        if found { hits += 1; }

        let mut client = guard.children.pop().unwrap();
        let _ = client.kill();
        let _ = client.wait();

        if i == n - 1 && c_local_port != 0 {
            let enforcer = LinuxEnforcer;
            let blocklist = Blocklist { paths: vec![], local_ports: vec![c_local_port] };
            enforcer.apply(&enforcer.plan(&blocklist)).map_err(|e| format!("FAIL-PRODUCT: L4 Enforcer apply error: {}", e))?;

            let is_blocked = match tokio::time::timeout(
                Duration::from_millis(500),
                async {
                    let socket = tokio::net::TcpSocket::new_v4().unwrap();
                    socket.set_reuseaddr(true).unwrap_or(());
                    if socket.bind(format!("127.0.0.1:{}", c_local_port).parse().unwrap()).is_ok() {
                        socket.connect(format!("127.0.0.1:{}", port).parse().unwrap()).await
                    } else {
                        Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, "in use"))
                    }
                }
            ).await {
                Ok(Ok(_)) => false,
                Ok(Err(e)) => if e.kind() == std::io::ErrorKind::AddrInUse { false } else { true },
                _ => true,
            };
            if is_blocked { return Err("FAIL-PRODUCT: L4: New allowed app reusing same ephemeral port is blocked".into()); }
        }
    }

    if hits < 50 { return Err(format!("FAIL-PRODUCT: L4 Hit rate too low ({}/{})", hits, n)); }
    Ok(())
}

async fn test_l5_daemon_lifecycle() -> Result<(), String> {
    let mut guard = CleanupGuard::new();
    ensure_daemon(&mut guard).await?;

    if let Ok(meta) = std::fs::metadata("/run/rat/rat.sock") {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o777 != 0o660 { return Err("FAIL-PRODUCT: L5: Daemon socket mode is not 0660".into()); }

        let out = Command::new("stat").args(["-c", "%G", "/run/rat/rat.sock"]).output().unwrap();
        let group = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if group != "rat" {
            return Err("FAIL-PRODUCT: L5: Daemon socket group is not rat".into());
        }
    }

    // Switch user test
    let _ = Command::new("sudo").args(["useradd", "testnobody"]).status();
    let su_out = Command::new("sudo").args(["-u", "testnobody", "nc", "-U", "/run/rat/rat.sock"]).output();
    let _ = Command::new("sudo").args(["userdel", "testnobody"]).status();

    if su_out.is_ok() {
        let code = su_out.unwrap().status.code().unwrap_or(0);
        if code == 0 {
             return Err("FAIL-PRODUCT: L5: Unprivileged user could connect to daemon socket".into());
        }
    }

    let mut error_msg = String::new();
    let s = std::os::unix::net::UnixStream::connect("/run/rat/rat.sock");
    if let Ok(mut sock) = s {
        use std::io::Write;
        let large_msg = vec![b'A'; 70000];
        let _ = sock.write_all(&large_msg);

        let mut conns = vec![];
        let mut refused = false;
        for _ in 0..100 {
            if let Ok(c) = std::os::unix::net::UnixStream::connect("/run/rat/rat.sock") {
                conns.push(c);
            } else {
                refused = true; break;
            }
        }
        if !refused { error_msg.push_str("FAIL-PRODUCT: L5: Client connection limit not respected (or >100). "); }
        drop(conns);

        let enforcer = LinuxEnforcer;
        enforcer.apply(&enforcer.plan(&Blocklist{paths: vec![], local_ports: vec![8080]})).unwrap_or(());

        let _ = Command::new("sudo").args(["systemctl", "kill", "-s", "9", "rat-daemon"]).status();

        let mut is_active = false;
        for _ in 0..20 {
             let stat = Command::new("sudo").args(["systemctl", "is-active", "rat-daemon"]).output().unwrap();
             if String::from_utf8_lossy(&stat.stdout).trim() == "active" {
                  is_active = true; break;
             }
             sleep(Duration::from_millis(100)).await;
        }

        if !is_active { error_msg.push_str("FAIL-PRODUCT: L5: Daemon did not restart after SIGKILL. "); }

        let mut table_deleted = false;
        for _ in 0..20 {
            let nft_out = Command::new("sudo").args(["nft", "list", "table", "inet", "rat"]).output().unwrap();
            if !nft_out.status.success() {
                table_deleted = true; break;
            }
            sleep(Duration::from_millis(100)).await;
        }

        if !table_deleted {
             error_msg.push_str("FAIL-PRODUCT: L5: inet rat table not deleted after daemon kill. ");
        }
    } else {
        return Err("FAIL-PRODUCT: L5: Daemon socket not reachable".into());
    }

    if !error_msg.is_empty() { return Err(error_msg); }
    Ok(())
}

async fn test_l6_gui_to_daemon_gap() -> Result<(), String> {
    let mut guard = CleanupGuard::new();
    ensure_daemon(&mut guard).await?;

    let s = std::os::unix::net::UnixStream::connect("/run/rat/rat.sock");
    if let Ok(mut sock) = s {
        use std::io::Write;
        use std::io::Read;
        // Test apply rules
        let rule = "{\"type\": \"ApplyRules\", \"rules\": []}\n";
        let _ = sock.write_all(rule.as_bytes());

        let mut status = false;
        for _ in 0..20 {
             let st = Command::new("sudo").args(["nft", "-j", "list", "table", "inet", "rat"]).status();
             if st.is_ok() && st.unwrap().success() {
                  status = true; break;
             }
             sleep(Duration::from_millis(100)).await;
        }
        if !status {
             return Err("FAIL-PRODUCT: L6: IPC sent rules but nft table not updated correctly".into());
        }

        // Test snapshot
        let snap = "{\"type\": \"RequestSnapshot\"}\n";
        let _ = sock.write_all(snap.as_bytes());
        let mut buf = [0u8; 1024];
        if let Ok(n) = sock.read(&mut buf) {
             let response = String::from_utf8_lossy(&buf[..n]);
             if !response.contains("connections") {
                  return Err("FAIL-PRODUCT: L6: IPC Snapshot does not contain real connections".into());
             }
        } else {
             return Err("FAIL-PRODUCT: L6: Failed to read from IPC socket for Snapshot".into());
        }
    } else {
         return Err("FAIL-PRODUCT: L6: Daemon socket missing, cannot test GUI-to-daemon gap".into());
    }

    Ok(())
}
