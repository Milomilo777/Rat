//! Shared helpers: result reporting, PowerShell runner, firewall queries.
//!
//! Status vocabulary (one per check; a requirement takes the worst):
//!   PASS          the check ran and the product behaved correctly
//!   NOT-RUN       the check could not run (reason printed); never a pass
//!   FAIL-HARNESS  the harness itself is broken or the environment is wrong
//!   FAIL-PRODUCT  the check ran and the product is wrong (evidence printed)
use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const HTTPS_URL: &str = "https://www.example.com";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Status {
    Pass,
    NotRun,
    FailHarness,
    FailProduct,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::NotRun => "NOT-RUN",
            Status::FailHarness => "FAIL-HARNESS",
            Status::FailProduct => "FAIL-PRODUCT",
        }
    }
}

pub struct Report {
    pub id: &'static str,
    checks: Vec<(Status, String)>,
}

impl Report {
    pub fn new(id: &'static str) -> Self {
        println!("=== {} start ===", id);
        Report {
            id,
            checks: Vec::new(),
        }
    }

    pub fn add(&mut self, s: Status, name: &str, detail: impl AsRef<str>) {
        println!("CHECK {} {} {}: {}", self.id, s.label(), name, detail.as_ref());
        self.checks.push((s, name.to_string()));
    }
    pub fn pass(&mut self, name: &str, detail: impl AsRef<str>) {
        self.add(Status::Pass, name, detail)
    }
    pub fn product(&mut self, name: &str, detail: impl AsRef<str>) {
        self.add(Status::FailProduct, name, detail)
    }
    pub fn harness(&mut self, name: &str, detail: impl AsRef<str>) {
        self.add(Status::FailHarness, name, detail)
    }
    pub fn not_run(&mut self, name: &str, detail: impl AsRef<str>) {
        self.add(Status::NotRun, name, detail)
    }

    /// True once any check failed (product or harness): later checks that
    /// depend on earlier ones should stop.
    pub fn failed(&self) -> bool {
        self.checks.iter().any(|(s, _)| *s >= Status::FailHarness)
    }

    /// Prints the RESULT line and returns the process exit code.
    pub fn finish(self) -> i32 {
        let worst = self
            .checks
            .iter()
            .map(|(s, _)| *s)
            .max()
            .unwrap_or(Status::NotRun);
        let (label, code) = match worst {
            Status::Pass => ("PASS", 0),
            Status::NotRun => ("PARTIAL(some checks NOT-RUN)", 3),
            Status::FailHarness => ("FAIL-HARNESS", 20),
            Status::FailProduct => ("FAIL-PRODUCT", 10),
        };
        let n = |s: Status| self.checks.iter().filter(|(x, _)| *x == s).count();
        println!(
            "RESULT {} {} (pass={} not-run={} fail-harness={} fail-product={})",
            self.id,
            label,
            n(Status::Pass),
            n(Status::NotRun),
            n(Status::FailHarness),
            n(Status::FailProduct)
        );
        code
    }
}

// ---------------------------------------------------------------- PowerShell

pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for ch in bytes.chunks(3) {
        let b = [ch[0], *ch.get(1).unwrap_or(&0), *ch.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if ch.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if ch.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

/// Runs a PowerShell script (Windows PowerShell 5.1) via -EncodedCommand so
/// no quoting layer can mangle it.
pub fn ps(script: &str) -> Out {
    let full = format!(
        "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Continue'; {script}"
    );
    let utf16: Vec<u8> = full.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &base64(&utf16),
        ])
        .stdin(Stdio::null())
        .output();
    match out {
        Ok(o) => Out {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).to_string(),
            stderr: String::from_utf8_lossy(&o.stderr).to_string(),
        },
        Err(e) => Out {
            code: -1,
            stdout: String::new(),
            stderr: format!("cannot spawn powershell.exe: {e}"),
        },
    }
}

/// Runs a plain executable and captures its output.
pub fn exec(exe: &str, args: &[&str]) -> Out {
    match Command::new(exe).args(args).stdin(Stdio::null()).output() {
        Ok(o) => Out {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).to_string(),
            stderr: String::from_utf8_lossy(&o.stderr).to_string(),
        },
        Err(e) => Out {
            code: -1,
            stdout: String::new(),
            stderr: format!("cannot spawn {exe}: {e}"),
        },
    }
}

pub fn wait_until(timeout: Duration, interval: Duration, mut f: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    loop {
        if f() {
            return true;
        }
        if start.elapsed() >= timeout {
            return false;
        }
        std::thread::sleep(interval);
    }
}

// ------------------------------------------------------------------ firewall

#[derive(Debug, Clone)]
pub struct RatRule {
    pub name: String,
    pub direction: String,
    pub action: String,
    pub enabled: String,
    pub program: String,
}

/// Every firewall rule whose display name starts with `Rat:`. Err when the
/// query itself did not complete (the END sentinel is missing).
pub fn rat_rules() -> Result<Vec<RatRule>, String> {
    let o = ps(r#"
$r = Get-NetFirewallRule -DisplayName 'Rat:*' -ErrorAction SilentlyContinue
foreach ($x in $r) {
  $f = $x | Get-NetFirewallApplicationFilter
  Write-Output ('RULE|' + $x.DisplayName + '|' + $x.Direction + '|' + $x.Action + '|' + $x.Enabled + '|' + $f.Program)
}
Write-Output 'END'
"#);
    if !o.stdout.contains("\nEND") && !o.stdout.starts_with("END") {
        return Err(format!("rule query incomplete: {} {}", o.stdout, o.stderr));
    }
    let mut v = Vec::new();
    for l in o.stdout.lines() {
        if let Some(rest) = l.trim().strip_prefix("RULE|") {
            let p: Vec<&str> = rest.splitn(5, '|').collect();
            if p.len() == 5 {
                v.push(RatRule {
                    name: p[0].to_string(),
                    direction: p[1].to_string(),
                    action: p[2].to_string(),
                    enabled: p[3].to_string(),
                    program: p[4].to_string(),
                });
            }
        }
    }
    Ok(v)
}

/// Display names of ALL firewall rules (for before/after comparison).
pub fn rule_names() -> Result<BTreeSet<String>, String> {
    let o = ps(r#"
Get-NetFirewallRule -ErrorAction SilentlyContinue | ForEach-Object { Write-Output ('N|' + $_.DisplayName) }
Write-Output 'END'
"#);
    if !o.stdout.contains("\nEND") && !o.stdout.starts_with("END") {
        return Err(format!("name query incomplete: {} {}", o.stdout, o.stderr));
    }
    Ok(o.stdout
        .lines()
        .filter_map(|l| l.trim_end().strip_prefix("N|").map(|s| s.to_string()))
        .collect())
}

pub fn same_path(a: &str, b: &str) -> bool {
    let n = |s: &str| s.trim_start_matches(r"\\?\").to_lowercase().replace('/', "\\");
    n(a) == n(b)
}

pub fn remove_rat_rules() {
    let _ = ps("Get-NetFirewallRule -DisplayName @('Rat:path:*','Rat:port:*') -ErrorAction SilentlyContinue | Remove-NetFirewallRule");
}

// ------------------------------------------------------------- HTTPS probing

/// Runs `<exe> curl <url>` (the harness binary's own mode). Some(true) =
/// request succeeded, Some(false) = request failed, None = could not decide.
pub fn probe(exe: &Path, url: &str) -> Option<bool> {
    let mut child = Command::new(exe)
        .arg("curl")
        .arg(url)
        .stdin(Stdio::null())
        .spawn()
        .ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                return match st.code() {
                    Some(0) => Some(true),
                    Some(1) => Some(false),
                    _ => None,
                }
            }
            Ok(None) => {}
            Err(_) => return None,
        }
        if start.elapsed() > Duration::from_secs(30) {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Probe with retries until it equals `want` (firewall changes need a moment).
pub fn probe_until(exe: &Path, url: &str, want: bool, tries: u32) -> Option<bool> {
    let mut last = None;
    for _ in 0..tries {
        last = probe(exe, url);
        if last == Some(want) {
            return last;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    last
}

pub fn system_curl_ok(url: &str) -> bool {
    exec("curl.exe", &["-s", "-S", "-I", "--max-time", "15", "-o", "NUL", url]).code == 0
}

pub fn kill_child(c: &mut Child) {
    let _ = c.kill();
    let _ = c.wait();
}

// -------------------------------------------------------------------- pipes

/// Is `\\.\pipe\<name>` listed by Directory.GetFiles('\\.\pipe\')?
pub fn pipe_listed(name: &str) -> Result<bool, String> {
    let script = format!(
        r#"$l = [System.IO.Directory]::GetFiles('\\.\pipe\'); Write-Output ('LISTED=' + ($l -contains '\\.\pipe\{name}')); Write-Output ('COUNT=' + $l.Count); Write-Output 'END'"#
    );
    let o = ps(&script);
    if !o.stdout.contains("END") {
        return Err(format!("pipe listing failed: {} {}", o.stdout, o.stderr));
    }
    if o.stdout.contains("LISTED=True") {
        Ok(true)
    } else if o.stdout.contains("LISTED=False") {
        Ok(false)
    } else {
        Err(format!("unparsable pipe listing: {}", o.stdout))
    }
}

pub fn wait_pipe(name: &str, present: bool, timeout: Duration) -> bool {
    wait_until(timeout, Duration::from_millis(500), || {
        pipe_listed(name) == Ok(present)
    })
}
