//! W6 GUI-to-daemon gap: a real IPC protocol v1 client against a console
//! daemon. Does Hello work, does a Snapshot carry real connections, does
//! SetRules reach the firewall? Control: the same flow under RAT_DRY_RUN=1.
use crate::common::*;
use crate::ipc::{Ipc, Recv};
use rat_daemon::msg::{ClientMessage, ServerMessage};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

struct Guard {
    children: Vec<Child>,
    files: Vec<PathBuf>,
}
impl Drop for Guard {
    fn drop(&mut self) {
        for c in &mut self.children {
            kill_child(c);
        }
        remove_rat_rules();
        for f in &self.files {
            let _ = std::fs::remove_file(f);
        }
    }
}

fn deny_rule(path: &str) -> ClientMessage {
    let v = serde_json::json!([{
        "verdict": "deny",
        "processPath": path,
        "enabled": true,
        "approved": true,
        "lifetime": "forever"
    }]);
    let rules: Vec<rat_core::Rule> = serde_json::from_value(v).expect("rule json parses as rat_core::Rule");
    ClientMessage::SetRules { rules }
}

fn spawn_daemon(daemon: &Path, rules_file: &Path, dry: bool) -> std::io::Result<Child> {
    let mut c = Command::new(daemon);
    c.env("RAT_RULES_FILE", rules_file);
    if dry {
        c.env("RAT_DRY_RUN", "1");
    } else {
        c.env_remove("RAT_DRY_RUN");
    }
    c.spawn()
}

fn one_shot(first: &[u8]) -> String {
    match Ipc::connect(Duration::from_secs(10)) {
        Err(e) => format!("connect failed: {e}"),
        Ok(mut c) => {
            let _ = c.send_raw(first);
            let a = c.recv(Duration::from_secs(5));
            let b = c.recv(Duration::from_secs(3));
            format!("{} then {}", fmt(&a), fmt(&b))
        }
    }
}

fn fmt(r: &Recv) -> String {
    match r {
        Recv::Line(l) => format!("line {:?}", &l[..l.len().min(160)]),
        Recv::Eof => "EOF".into(),
        Recv::Timeout => "timeout".into(),
        Recv::Err(e) => format!("error {e}"),
    }
}

/// One daemon session. `dry` = control run (rule must NOT appear).
fn session(r: &mut Report, g: &mut Guard, daemon: &Path, dry: bool, denied: &Path, client_exe: &Path, rules_file: &Path) {
    let tag = if dry { "control-dry" } else { "real" };
    // The pipe must be free (previous session / W4 service gone).
    if !wait_pipe("rat", false, Duration::from_secs(15)) {
        return r.harness(&format!("{tag}-pipe-free"), r"\\.\pipe\rat is still taken before starting the daemon");
    }
    let child = match spawn_daemon(daemon, rules_file, dry) {
        Ok(c) => c,
        Err(e) => return r.harness(&format!("{tag}-spawn"), format!("{e}")),
    };
    g.children.push(child);
    let idx = g.children.len() - 1;
    if !wait_pipe("rat", true, Duration::from_secs(20)) {
        let st = g.children[idx].try_wait();
        return r.product(&format!("{tag}-pipe"), format!("daemon did not publish the pipe in 20 s (process status {st:?})"));
    }
    let denied_s = denied.to_string_lossy().to_string();

    if !dry {
        // Protocol negative controls.
        let a = one_shot(br#"{"SetRules":{"rules":[]}}"#);
        if a.contains("must be Hello") {
            r.pass("proto-first-must-be-hello", a);
        } else {
            r.product("proto-first-must-be-hello", a);
        }
        let b = one_shot(br#"{"Hello":{"protocol_version":99}}"#);
        if b.contains("unsupported protocol version") {
            r.pass("proto-bad-version", b);
        } else {
            r.product("proto-bad-version", b);
        }
        let c = one_shot(b"not json");
        if c.contains("Invalid JSON") {
            r.pass("proto-garbage", c);
        } else {
            r.product("proto-garbage", c);
        }
        // The old harness' raw legacy line must be refused too.
        let d = one_shot(br#"{"ApplyPlan":{"add":["C:\\x.exe"],"remove":[],"local_ports":[]}}"#);
        if d.contains("Error") {
            r.pass("proto-legacy-raw-line-refused", d);
        } else {
            r.product("proto-legacy-raw-line-refused", d);
        }
    }

    let mut ipc = match Ipc::connect(Duration::from_secs(10)) {
        Ok(c) => c,
        Err(e) => return r.harness(&format!("{tag}-connect"), format!("{e}")),
    };
    let _ = ipc.hello();
    match ipc.recv_msg(Duration::from_secs(5)) {
        Ok(ServerMessage::HelloAck { protocol_version: 1 }) => r.pass(&format!("{tag}-hello-ack"), "HelloAck protocol_version 1"),
        other => return r.product(&format!("{tag}-hello-ack"), format!("expected HelloAck, got {}", match other { Ok(m) => format!("{m:?}"), Err(x) => fmt(&x) })),
    }

    // A real connection the monitor can see: client_exe -> local listener.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let cl = Command::new(client_exe).args(["client", &format!("127.0.0.1:{port}"), "60000"]).spawn().unwrap();
    let cl_pid = cl.id();
    g.children.push(cl);
    let (_held, _) = listener.accept().unwrap();

    // Send the deny rule.
    if let Err(e) = ipc.send(&deny_rule(&denied_s)) {
        return r.harness(&format!("{tag}-setrules"), format!("{e}"));
    }

    // Snapshot with the real connection (real session only is asserted).
    let start = Instant::now();
    let mut seen_snapshots = 0;
    let mut found = false;
    let mut total = 0;
    while start.elapsed() < Duration::from_secs(12) && !found {
        match ipc.recv_msg(Duration::from_secs(2)) {
            Ok(ServerMessage::Snapshot { connections }) => {
                seen_snapshots += 1;
                total = connections.len();
                found = connections.iter().any(|c| {
                    c.process.pid == cl_pid
                        && c.process.exe.as_ref().map(|p| same_path(&p.to_string_lossy(), &client_exe.to_string_lossy())) == Some(true)
                });
            }
            Ok(_) => {}
            Err(Recv::Timeout) => {}
            Err(x) => return r.product(&format!("{tag}-stream"), format!("connection ended while waiting for a Snapshot: {}", fmt(&x))),
        }
    }
    println!("W6 {tag}: snapshots={seen_snapshots} last-size={total} found-client={found}");
    if !dry {
        if found {
            r.pass("snapshot-real-connections", format!("Snapshot lists pid {cl_pid} with the right exe ({seen_snapshots} snapshots, {total} connections)"));
        } else if seen_snapshots == 0 {
            r.product("snapshot-real-connections", "no Snapshot message within 12 s after Hello");
        } else {
            r.product("snapshot-real-connections", format!("{seen_snapshots} snapshots but none contains pid {cl_pid}"));
        }
    }

    // Firewall effect of SetRules.
    let appears = wait_until(
        Duration::from_secs(if dry { 8 } else { 20 }),
        Duration::from_secs(1),
        || rat_rules().map(|v| v.iter().any(|x| x.name.starts_with("Rat:path:") && same_path(&x.program, &denied_s))).unwrap_or(false),
    );
    if dry {
        if !appears {
            r.pass("control-dry-no-rule", "RAT_DRY_RUN=1 daemon accepted SetRules but created no firewall rule");
        } else {
            r.harness("control-dry-no-rule", "rule appeared although RAT_DRY_RUN=1");
        }
    } else {
        let rules = rat_rules();
        if appears {
            r.pass("setrules-creates-rule", format!("{rules:?}"));
        } else {
            r.product("setrules-creates-rule", format!("deny rule for {denied_s} sent over IPC but no Rat:path rule within 20 s; rules={rules:?}"));
        }
        // Removal: an empty rule set must remove it again.
        if appears {
            let _ = ipc.send(&ClientMessage::SetRules { rules: vec![] });
            let gone = wait_until(Duration::from_secs(20), Duration::from_secs(1), || {
                rat_rules().map(|v| !v.iter().any(|x| same_path(&x.program, &denied_s))).unwrap_or(false)
            });
            if gone {
                r.pass("setrules-empty-removes-rule", "rule removed after SetRules []");
            } else {
                r.product("setrules-empty-removes-rule", format!("rule still present 20 s after SetRules []: {:?}", rat_rules()));
            }
        }
    }
    drop(ipc);
    drop(_held);
    // stop the daemon and the helper client
    for c in g.children.drain(..) {
        let mut c = c;
        kill_child(&mut c);
    }
    remove_rat_rules();
}

pub fn run(r: &mut Report) {
    let daemon = match std::env::var("RAT_DAEMON_EXE") {
        Ok(p) => PathBuf::from(p),
        Err(_) => return r.harness("setup", "RAT_DAEMON_EXE not set"),
    };
    if !daemon.is_file() {
        return r.harness("setup", format!("daemon exe not found: {daemon:?}"));
    }
    let me = std::env::current_exe().unwrap();
    let denied = me.with_file_name("w6_denied.exe");
    let client = me.with_file_name("w6_client.exe");
    let rules_file = me.with_file_name("w6_rules.json");
    std::fs::copy(&me, &denied).unwrap();
    std::fs::copy(&me, &client).unwrap();
    let mut g = Guard {
        children: Vec::new(),
        files: vec![denied.clone(), client.clone(), rules_file.clone()],
    };
    // Negative control for the client: with no daemon, connecting must fail.
    match Ipc::connect(Duration::from_secs(1)) {
        Err(_) => r.pass("control-no-daemon", "pipe connect fails while no daemon runs"),
        Ok(_) => return r.harness("control-no-daemon", r"something already serves \\.\pipe\rat"),
    }
    session(r, &mut g, &daemon, true, &denied, &client, &rules_file);
    let _ = std::fs::remove_file(&rules_file);
    session(r, &mut g, &daemon, false, &denied, &client, &rules_file);
}
