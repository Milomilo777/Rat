//! W4 Service and pipe security: rat-daemon as a LocalSystem service, pipe
//! existence + DACL, non-admin user, >64 KiB line, kill + stale-rule repair.
use crate::common::*;
use crate::ipc::{Ipc, Recv};
use std::path::PathBuf;
use std::time::Duration;

const SVC: &str = "RatDaemon";
const USER: &str = "rat_test_user";
const USER_SECRET: &str = "Zq9!rT4#vLm27xW";
const WORK: &str = r"C:\ProgramData\rat_w4";
const DOC_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;IU)";
const SCRIPT_DACL: &str = include_str!("../ps/pipe_dacl.ps1");
const SCRIPT_USER: &str = include_str!("../ps/user_pipe.ps1");

// ------------------------------------------------------------- SDDL parsing

pub fn alias_mask(s: &str) -> Option<u32> {
    if let Some(h) = s.strip_prefix("0x") {
        return u32::from_str_radix(h, 16).ok();
    }
    let mut m = 0u32;
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    for i in (0..s.len()).step_by(2) {
        m |= match &s[i..i + 2] {
            "GA" => 0x1000_0000,
            "GR" => 0x8000_0000,
            "GW" => 0x4000_0000,
            "GX" => 0x2000_0000,
            "RC" => 0x0002_0000,
            "SD" => 0x0001_0000,
            "WD" => 0x0004_0000,
            "WO" => 0x0008_0000,
            "FA" => 0x001f_01ff,
            "FR" => 0x0012_0089,
            "FW" => 0x0012_0116,
            "FX" => 0x0012_00a0,
            _ => return None,
        };
    }
    Some(m)
}

const FILE_CREATE_PIPE_INSTANCE: u32 = 0x4;
const WRITE_DAC: u32 = 0x0004_0000;

fn is_full_control(mask: u32) -> bool {
    mask == 0x1000_0000 || mask == 0x001f_01ff
}

/// Compares a DACL (SDDL "Access" form) with the documented design:
/// protected, exactly SY + BA full control and IU = 0x12019b. GA is accepted
/// next to FA because Windows maps generic rights when the pipe is created.
/// Returns the list of problems (empty = matches).
pub fn dacl_problems(sddl: &str) -> Vec<String> {
    let mut p = Vec::new();
    let Some(d) = sddl.find("D:") else {
        return vec![format!("no D: section in {sddl:?}")];
    };
    let body = &sddl[d + 2..];
    let flags_end = body.find('(').unwrap_or(body.len());
    if !body[..flags_end].contains('P') {
        p.push(format!("DACL not protected (flags {:?})", &body[..flags_end]));
    }
    let mut aces: Vec<(String, u32, String)> = Vec::new();
    for part in body[flags_end..].split('(').skip(1) {
        let inner = part.split(')').next().unwrap_or("");
        let f: Vec<&str> = inner.split(';').collect();
        if f.len() < 6 {
            p.push(format!("unparsable ACE {inner:?}"));
            continue;
        }
        if f[0] != "A" {
            p.push(format!("non-allow ACE {inner:?}"));
        }
        match alias_mask(f[2]) {
            Some(m) => aces.push((f[5].to_string(), m, f[2].to_string())),
            None => p.push(format!("unknown rights {:?}", f[2])),
        }
    }
    if aces.len() != 3 {
        p.push(format!("expected 3 ACEs, found {}", aces.len()));
    }
    for sid in ["SY", "BA"] {
        match aces.iter().find(|a| a.0 == sid) {
            Some(a) if is_full_control(a.1) => {}
            Some(a) => p.push(format!("{sid} is {} (0x{:x}), not full control", a.2, a.1)),
            None => p.push(format!("no ACE for {sid}")),
        }
    }
    match aces.iter().find(|a| a.0 == "IU") {
        Some(a) => {
            if a.1 != 0x0012_019b {
                p.push(format!("IU rights 0x{:x} != documented 0x12019b", a.1));
            }
            if a.1 & FILE_CREATE_PIPE_INSTANCE != 0 {
                p.push("IU has FILE_CREATE_PIPE_INSTANCE".into());
            }
            if a.1 & WRITE_DAC != 0 || a.1 & 0x1000_0000 != 0 {
                p.push("IU has WRITE_DAC / GENERIC_ALL".into());
            }
        }
        None => p.push("no ACE for IU".into()),
    }
    p
}

// ---------------------------------------------------------------- service

fn sc_query() -> (String, Option<u32>) {
    let o = exec("sc.exe", &["queryex", SVC]);
    let state = o
        .stdout
        .lines()
        .find(|l| l.contains("STATE"))
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|| format!("(no STATE line) {}", o.stdout.trim()));
    let pid = o
        .stdout
        .lines()
        .find(|l| l.trim_start().starts_with("PID"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|p| *p != 0);
    (state, pid)
}

fn wait_running(timeout: Duration, not_pid: Option<u32>) -> Option<u32> {
    let mut found = None;
    wait_until(timeout, Duration::from_millis(500), || {
        let (st, pid) = sc_query();
        if st.contains("RUNNING") && pid.is_some() && pid != not_pid {
            found = pid;
            true
        } else {
            false
        }
    });
    found
}

struct Guard {
    stale: PathBuf,
}
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = exec("sc.exe", &["stop", SVC]);
        wait_until(Duration::from_secs(15), Duration::from_millis(500), || {
            sc_query().0.contains("STOPPED") || sc_query().0.contains("no STATE")
        });
        let _ = exec("sc.exe", &["delete", SVC]);
        let _ = exec("net.exe", &["user", USER, "/delete"]);
        remove_rat_rules();
        let _ = std::fs::remove_dir_all(WORK);
        let _ = std::fs::remove_file(&self.stale);
    }
}

fn diag(r: &mut Report, name: &str) {
    let qc = exec("sc.exe", &["qc", SVC]);
    let ev = ps("Get-WinEvent -LogName System -MaxEvents 40 -ErrorAction SilentlyContinue | Where-Object {$_.ProviderName -eq 'Service Control Manager'} | ForEach-Object { $_.TimeCreated.ToString('s') + ' ' + $_.Message }");
    println!("W4 DIAG ({name}) sc qc:\n{}\nevents:\n{}", qc.stdout, ev.stdout);
    let _ = r;
}

pub fn run(r: &mut Report) {
    // Control: the parser must flag a bad DACL (IU = GENERIC_ALL) and accept the design.
    let bad = dacl_problems("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)");
    let good = dacl_problems("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019b;;;IU)");
    if bad.is_empty() || !good.is_empty() {
        return r.harness("control-dacl-parser", format!("bad={bad:?} good={good:?}"));
    }
    r.pass("control-dacl-parser", format!("flags IU=GA ({bad:?}); accepts the documented DACL"));

    let daemon = match std::env::var("RAT_DAEMON_EXE") {
        Ok(p) => PathBuf::from(p),
        Err(_) => return r.harness("setup", "RAT_DAEMON_EXE not set"),
    };
    if !daemon.is_file() || daemon.to_string_lossy().contains(' ') {
        return r.harness("setup", format!("daemon exe missing or path has spaces: {daemon:?}"));
    }
    let me = std::env::current_exe().unwrap();
    let stale = me.with_file_name("w4_stale_target.exe");
    std::fs::copy(&me, &stale).unwrap();
    let _g = Guard { stale: stale.clone() };
    let _ = std::fs::create_dir_all(WORK);

    // ---- install + start
    let o = exec("sc.exe", &["create", SVC, "binPath=", &daemon.to_string_lossy(), "type=", "own", "start=", "demand", "obj=", "LocalSystem"]);
    if o.code != 0 {
        return r.harness("sc-create", format!("{} {}", o.stdout, o.stderr));
    }
    let _ = exec("sc.exe", &["failure", SVC, "reset=", "0", "actions=", "restart/1000/restart/1000/restart/1000"]);
    let o = exec("sc.exe", &["start", SVC]);
    println!("W4 sc start: code={} {}", o.code, o.stdout);
    let Some(pid1) = wait_running(Duration::from_secs(30), None) else {
        diag(r, "not running");
        return r.product("service-running", format!("service never reached RUNNING: {:?}", sc_query().0));
    };
    let qc = exec("sc.exe", &["qc", SVC]);
    r.pass("service-running", format!("{} pid={pid1}", sc_query().0));
    if qc.stdout.contains("LocalSystem") {
        r.pass("service-account", "SERVICE_START_NAME LocalSystem");
    } else {
        r.harness("service-account", qc.stdout);
    }

    // ---- pipe existence (negative control on a pipe that was never created)
    match pipe_listed("rat_never_created_zz") {
        Ok(false) => r.pass("control-pipe-absent", "listing does not contain a never-created pipe"),
        other => return r.harness("control-pipe-absent", format!("{other:?}")),
    }
    if wait_pipe("rat", true, Duration::from_secs(20)) {
        r.pass("pipe-exists", r"\\.\pipe\rat is listed by Directory.GetFiles while the service is RUNNING");
    } else {
        diag(r, "pipe missing");
        r.product("pipe-exists", format!(r"\\.\pipe\rat not listed within 20 s while service state is {:?}", sc_query().0));
        return;
    }

    // ---- DACL
    let o = ps(SCRIPT_DACL);
    println!("W4 DACL script output:\n{}\n{}", o.stdout, o.stderr);
    let sddl = o
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("SDDL1=").or_else(|| l.strip_prefix("SDDL2=")))
        .map(|s| s.trim().to_string());
    match sddl {
        None => r.harness("pipe-dacl", "could not read the DACL by either method (see output above)"),
        Some(s) => {
            let pr = dacl_problems(&s);
            if pr.is_empty() {
                r.pass("pipe-dacl", format!("read {s}; equals documented {DOC_SDDL} after generic-right mapping"));
            } else {
                r.product("pipe-dacl", format!("read {s}; documented {DOC_SDDL}; problems {pr:?}"));
            }
        }
    }

    // ---- non-admin user
    user_checks(r);

    // ---- >64 KiB line (admin client)
    line_limit(r);

    // ---- kill + stale rule
    kill_and_repair(r, &stale, pid1);
}

fn user_checks(r: &mut Report) {
    let o = exec("net.exe", &["user", USER, USER_SECRET, "/add"]);
    if o.code != 0 {
        return r.not_run("non-admin-user", format!("net user /add failed: {} {}", o.stdout, o.stderr));
    }
    let _ = exec("icacls.exe", &[WORK, "/grant", "*S-1-1-0:(OI)(CI)M"]);
    let script = format!(r"{WORK}\user_pipe.ps1");
    let out = format!(r"{WORK}\user_out.txt");
    std::fs::write(&script, SCRIPT_USER).unwrap();
    let launcher = format!(
        r#"
$sec = ConvertTo-SecureString '{USER_SECRET}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('.\{USER}', $sec)
try {{
  $p = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -Credential $cred -WorkingDirectory '{WORK}' -WindowStyle Hidden -PassThru -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','{script}','{out}'
  if ($p.WaitForExit(90000)) {{ Write-Output ('EXIT=' + $p.ExitCode) }} else {{ Write-Output 'WAIT=TIMEOUT'; Stop-Process -Id $p.Id -Force }}
}} catch {{ Write-Output ('STARTFAIL=' + $_.Exception.Message) }}
Write-Output 'END'
"#
    );
    let o = ps(&launcher);
    println!("W4 user launcher: {}{}", o.stdout, o.stderr);
    let text = std::fs::read_to_string(&out).unwrap_or_default();
    println!("W4 user output:\n{text}");
    if !text.contains("END") {
        return r.not_run("non-admin-user", format!("could not run a process as {USER}: {}", o.stdout.trim()));
    }
    if !text.contains("HAS_ADMIN_SID=False") {
        r.harness("non-admin-user", "test user's token lists the Administrators SID");
    }
    let get = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)).unwrap_or("").to_string();
    let c2 = get("CREATE2=");
    if c2.starts_with("FAILED:UnauthorizedAccessException") {
        r.pass("user-cannot-create-pipe-instance", c2);
    } else if c2.starts_with("SUCCEEDED") {
        r.product("user-cannot-create-pipe-instance", "non-admin user created a second instance of \\\\.\\pipe\\rat");
    } else {
        r.not_run("user-cannot-create-pipe-instance", format!("failed for another reason (not an access denial): {c2}"));
    }
    println!("W4 REPORT non-admin client: interactive-SID={} CONNECT={} HELLO={}", get("HAS_INTERACTIVE_SID="), get("CONNECT="), get("HELLO_REPLY="));
    let hello = get("HELLO_REPLY=");
    if hello.contains("HelloAck") {
        r.product("user-client-refused", format!("non-admin user completed the handshake: {hello}"));
    } else if get("CONNECT=").starts_with("OK") {
        r.pass("user-client-refused", format!("non-admin user connects (DACL allows IU) but gets no handshake: {hello}"));
    } else {
        r.pass("user-client-refused", format!("non-admin user cannot even connect: {}", get("CONNECT=")));
    }
}

fn line_limit(r: &mut Report) {
    let mut c = match Ipc::connect(Duration::from_secs(10)) {
        Ok(c) => c,
        Err(e) => return r.harness("line-limit", format!("admin client cannot connect: {e}")),
    };
    if c.hello().is_err() {
        return r.harness("line-limit", "cannot send Hello");
    }
    match c.recv(Duration::from_secs(5)) {
        Recv::Line(l) if l.contains("HelloAck") => r.pass("admin-handshake", l),
        other => {
            return r.product("admin-handshake", format!("elevated admin client got no HelloAck: {}", describe(&other)));
        }
    }
    // Control: a 60000-byte line (valid JSON + trailing spaces) is accepted.
    let mut ok_line = br#"{"Hello":{"protocol_version":1}}"#.to_vec();
    ok_line.extend(std::iter::repeat(b' ').take(60000));
    let _ = c.send_raw(&ok_line);
    match c.recv(Duration::from_secs(5)) {
        Recv::Line(l) if l.contains("already handshaked") => r.pass("control-60k-line-accepted", "60000-byte line parsed (reply: already handshaked)"),
        other => return r.harness("control-60k-line-accepted", describe(&other)),
    }
    // A 70000-byte line must be rejected.
    let mut big = br#"{"Hello":{"protocol_version":1}}"#.to_vec();
    big.extend(std::iter::repeat(b' ').take(70000));
    let _ = c.send_raw(&big);
    let first = c.recv(Duration::from_secs(5));
    let second = if matches!(first, Recv::Line(_)) { c.recv(Duration::from_secs(5)) } else { Recv::Timeout };
    let rejected = matches!(&first, Recv::Line(l) if l.contains("Error")) || matches!(first, Recv::Eof);
    if rejected {
        r.pass("line-over-64KiB-rejected", format!("first={} then={}", describe(&first), describe(&second)));
    } else {
        r.product("line-over-64KiB-rejected", format!("70000-byte line not rejected: first={}", describe(&first)));
    }
}

fn describe(r: &Recv) -> String {
    match r {
        Recv::Line(l) => format!("line {:?}", &l[..l.len().min(200)]),
        Recv::Eof => "EOF".into(),
        Recv::Timeout => "timeout".into(),
        Recv::Err(e) => format!("error {e}"),
    }
}

fn kill_and_repair(r: &mut Report, stale: &PathBuf, pid1: u32) {
    let stale_s = stale.to_string_lossy().to_string();
    let netsh = format!(r"{}\System32\netsh.exe", std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()));
    let name = format!("name=Rat:path:{stale_s}");
    let prog = format!("program={stale_s}");
    let o = exec(&netsh, &["advfirewall", "firewall", "add", "rule", &name, "dir=out", "action=block", &prog]);
    if o.code != 0 {
        return r.harness("stale-rule-setup", format!("{} {}", o.stdout, o.stderr));
    }
    match rat_rules() {
        Ok(v) if v.iter().any(|x| same_path(&x.program, &stale_s)) => r.pass("stale-rule-planted", format!("{} rule(s) present", v.len())),
        other => return r.harness("stale-rule-planted", format!("{other:?}")),
    }
    let rules_file = std::path::Path::new(r"C:\ProgramData\rat\rules.json");
    println!("W4 INFO saved plan file {:?} exists={} len={:?}", rules_file, rules_file.exists(), std::fs::metadata(rules_file).map(|m| m.len()));

    // Kill exactly the service process we queried.
    let o = exec("taskkill.exe", &["/F", "/PID", &pid1.to_string()]);
    println!("W4 taskkill pid {pid1}: code={} {}", o.code, o.stdout);
    if o.code != 0 {
        return r.harness("kill-service-process", format!("{} {}", o.stdout, o.stderr));
    }
    let pid2 = wait_running(Duration::from_secs(25), Some(pid1));
    let pid2 = match pid2 {
        Some(p) => {
            r.pass("service-restarts", format!("SCM restarted the service: pid {pid1} -> {p}"));
            p
        }
        None => {
            println!("W4 state after kill: {:?}", sc_query().0);
            let _ = exec("sc.exe", &["start", SVC]);
            match wait_running(Duration::from_secs(20), Some(pid1)) {
                Some(p) => {
                    r.not_run("service-restarts", "SCM did not restart the service by itself within 25 s (started manually)");
                    p
                }
                None => return r.product("service-restarts", "service did not come back RUNNING after the kill"),
            }
        }
    };
    println!("W4 new service pid {pid2}");
    if !wait_pipe("rat", true, Duration::from_secs(20)) {
        diag(r, "pipe after restart");
        return r.product("pipe-after-restart", "pipe not listed after the service restarted");
    }
    let gone = wait_until(Duration::from_secs(15), Duration::from_secs(1), || {
        rat_rules().map(|v| !v.iter().any(|x| same_path(&x.program, &stale_s))).unwrap_or(false)
    });
    if gone {
        r.pass("stale-rule-removed", "stale Rat:path rule is gone after the service restarted");
    } else {
        println!("W4 rules after restart: {:?}", rat_rules());
        println!("W4 INFO saved plan file exists={}", rules_file.exists());
        r.product("stale-rule-removed", format!("stale rule for {stale_s} still present 15 s after restart"));
    }
}
