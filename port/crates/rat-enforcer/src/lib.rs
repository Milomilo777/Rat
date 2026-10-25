use std::io::{self, Read, Write};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

#[cfg(not(windows))]
pub mod linux;
pub mod nft_plan;
#[cfg(windows)]
pub mod windows;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Blocklist {
    pub paths: Vec<String>,
    pub local_ports: Vec<u16>,
}

pub trait Enforcer {
    type Plan;
    fn plan(&self, wanted: &Blocklist) -> Self::Plan;
    /// apply() OWNS the enforcer's notion of the current
    /// state. A Windows implementation advances `current` to the plan's
    /// outcome on success (so re-planning an unchanged wanted state is an
    /// empty diff) and leaves it behind on failure (the next diff retries);
    /// its add path must be idempotent, because netsh duplicates a rule when
    /// the name already exists.
    fn apply(&mut self, plan: &Self::Plan) -> io::Result<()>;
    /// remove every rule this enforcer created. Called on
    /// start and on clean shutdown (daemon wiring) so
    /// persistent rules do not survive crashes as duplicates; systemd's
    /// ExecStopPost covers the linux daemon meanwhile. On success the
    /// enforcer's own view of the rules is empty again (hence `&mut self`).
    fn cleanup(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// the enforcer RUNS by default; `RAT_DRY_RUN=1` is the
/// explicit opt-out for tests and dry runs. (Previously nothing was ever
/// enforced unless `RAT_ENFORCE=1` was set — including in production.)
pub fn dry_run_enabled(env_value: Option<&str>) -> bool {
    env_value == Some("1")
}

/// How long any firewall tool child process (netsh, PowerShell, nft) may run
/// before [`run_with_timeout`] kills it: netsh rule changes finish in well
/// under a second and a cold PowerShell module load takes a few seconds, so
/// 30 s is a bound that is never hit in practice and always ends a hang.
pub const TOOL_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval of the deadline wait loop.
const WAIT_POLL: Duration = Duration::from_millis(25);

/// ONE shared "run with timeout" for every child process the daemon spawns
/// (netsh, PowerShell, nft): spawn, wait with a deadline, KILL the child on
/// timeout, and return a clear error naming the tool and the limit — a hung
/// firewall tool can never stall the enforcement pipeline (or the startup
/// read-back) forever. `stdin_data` (the nft `-f -` script) is written by a
/// helper thread so a child that never reads cannot block the deadline, and
/// stdout/stderr are drained by threads so a child that writes more than the
/// pipe buffer cannot deadlock against the wait. Without `stdin_data` the
/// child's stdin is null.
pub fn run_with_timeout(
    mut cmd: Command,
    tool: &str,
    limit: Duration,
    stdin_data: Option<&[u8]>,
) -> io::Result<Output> {
    cmd.stdin(if stdin_data.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;

    let writer = stdin_data.map(|data| {
        let mut stdin = child.stdin.take().expect("stdin piped above");
        let data = data.to_vec();
        std::thread::spawn(move || stdin.write_all(&data))
    });
    let mut stdout_pipe = child.stdout.take().expect("stdout piped above");
    let stdout_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let mut stderr_pipe = child.stderr.take().expect("stderr piped above");
    let stderr_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    let status = wait_child_deadline(&mut child, tool, limit)?;
    // the child is reaped now, so its ends of the pipes are closed: the
    // writer (broken pipe) and the readers (EOF) are guaranteed to finish.
    if let Some(writer) = writer {
        match writer.join() {
            Ok(Ok(())) => {}
            // a failed script write must fail the call, not pass silently
            // (the old inline write propagated its error after the wait too).
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::Error::other("stdin writer thread panicked")),
        }
    }
    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

/// Wait for `child` no longer than `limit`: on the deadline the child is
/// killed AND reaped, and the error names the tool and the limit.
fn wait_child_deadline(child: &mut Child, tool: &str, limit: Duration) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            // the exit may have landed between the poll and the deadline
            if let Some(status) = child.try_wait()? {
                return Ok(status);
            }
            let _ = child.kill();
            let _ = child.wait(); // reap, so no zombie is left behind
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{tool} did not exit within {} ms and was killed",
                    limit.as_millis()
                ),
            ));
        }
        std::thread::sleep(WAIT_POLL);
    }
}

/// Longest tool output quoted in a [`tool_failure`] error.
const FAILURE_DETAIL_MAX: usize = 400;

/// An error for a firewall tool that exited non-zero: `what` plus the exit
/// status and the tool's own stderr (or stdout when stderr is empty),
/// trimmed and cut to [`FAILURE_DETAIL_MAX`] characters. The output is
/// captured by [`run_with_timeout`], so without this the reason would be lost.
pub fn tool_failure(what: &str, out: &Output) -> io::Error {
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    let cut: String = detail.chars().take(FAILURE_DETAIL_MAX).collect();
    io::Error::other(format!("{what} ({}): {cut}", out.status))
}

/// The rejection rules of [`validate_path`] WITHOUT the canonicalize: `None`
/// means the path would pass. plan decides reject-vs-report
/// with this — it is pure string work (no filesystem access, so the
/// plan budget holds) and it is EXACTLY apply()'s rejection
/// set, because the canonicalize step never rejects (a not-yet-existing
/// target passes as-is). UNC paths are refused here, so the refusal
/// happens before any canonicalisation.
pub fn path_validation_error(path: &str) -> Option<&'static str> {
    // Refuse UNC spellings first, as pure string work: fs::canonicalize on
    // a UNC target does network I/O (a dead server would stall the
    // caller), and a live target comes back mangled — the verbatim form
    // `\\?\UNC\server\share` loses its `\\?\` prefix to validate_path's
    // strip and yields `UNC\server\share`, which is not a path a rule can
    // name. Windows treats / and \ as the same separator, so the
    // forward-slash spelling is the same UNC path there; on POSIX `//` is
    // an ordinary absolute path and stays accepted.
    let bytes = path.as_bytes();
    if bytes.starts_with(b"\\\\") || (cfg!(windows) && bytes.starts_with(b"//")) {
        return Some(
            "network (UNC) and device or verbatim paths are not supported; use a plain drive path",
        );
    }
    // Byte-level scans, exactly equivalent to the char-level checks: every
    // delimiter and match target is ASCII, and UTF-8 continuation bytes are
    // never ASCII, so a multibyte character can neither match nor split.
    // plan() runs this per path per tick and the
    // debug-build char-pattern iterators measured ~4µs per 25-char path
    // (39ms/10000) — the byte scan is ~10x cheaper.
    if path
        .as_bytes()
        .iter()
        .any(|b| matches!(b, b'"' | b';' | b'\n' | b'\r'))
    {
        return Some("invalid characters in path");
    }
    // Equivalent to a Component::ParentDir scan: a `..` segment on either
    // separator is the same defect.
    if path
        .as_bytes()
        .split(|b| *b == b'/' || *b == b'\\')
        .any(|seg| seg == b"..")
    {
        return Some("parent-directory components are not allowed");
    }
    if !std::path::Path::new(path).is_absolute() {
        return Some("path must be absolute");
    }
    None
}

/// an enforcer path must be absolute, free of `..` segments,
/// free of characters that cannot occur in a real filename or that could
/// confuse netsh's `name=` parsing (`"` is impossible in a Windows filename,
/// CR/LF are control characters; `;` stays rejected as defense-in-depth even
/// though no shell is involved), not a UNC path (`\\server\share`,
/// `\\?\UNC\...` — refused before canonicalisation, which on a UNC target
/// does network I/O and cannot yield a nameable rule path), and
/// canonicalized (symlinks/junctions resolved) when the target exists, so a
/// rule cannot point validation at one file and enforcement at another.
/// `'` IS accepted — it is a legal Windows filename character
/// and no shell is involved anywhere (netsh is spawned via Command::args), so
/// an apostrophe in a user path (O'Brien) must not make the path
/// unenforceable.
pub fn validate_path(path: &str) -> Result<String, &'static str> {
    if let Some(err) = path_validation_error(path) {
        return Err(err);
    }
    let p = std::path::Path::new(path);
    match std::fs::canonicalize(p) {
        Ok(real) => {
            let s = real.to_string_lossy();
            // netsh rejects \\?\ verbatim prefixes; keep the plain form
            Ok(s.strip_prefix(r"\\?\").unwrap_or(&s).to_string())
        }
        // A not-yet-existing target still passed every check above.
        Err(_) => Ok(path.to_string()),
    }
}

/// Windows hosts that run work for MANY apps at once — the services host
/// (svchost.exe: DNS/Dnscache, DHCP and much more), COM activation
/// (dllhost.exe), Store-app brokering (RuntimeBroker.exe,
/// backgroundTaskHost.exe), scheduled-task hosting (taskhostw.exe), shell
/// infrastructure (sihost.exe), console hosting (conhost.exe), generic DLL
/// hosting (rundll32.exe) and WMI providers (WmiPrvSE.exe). A per-program
/// block rule for any of them cuts them all at once, so whole-program
/// enforcement of a shared host is refused instead (see
/// `WindowsPlan::refused`); block by the denied sockets' local ports or a
/// future per-service mechanism instead. Matching is on the executable
/// FILE NAME, case-insensitive (Windows reports `SVCHOST.EXE` as often as
/// `svchost.exe`), so full System32/SysWOW64 paths match. This is the ONE
/// list: rat-ledger's `shared` classification keys its notes to it
/// (test-pinned set equality), so every caller sees the same membership.
/// The crate stays std-only; macOS/Linux equivalents and the
/// human-readable notes live in rat-ledger's `shared` module.
pub const SHARED_SERVICE_HOSTS: &[&str] = &[
    "svchost.exe",
    "dllhost.exe",
    "runtimebroker.exe",
    "taskhostw.exe",
    "backgroundtaskhost.exe",
    "sihost.exe",
    "conhost.exe",
    "rundll32.exe",
    "wmiprvse.exe",
];

/// True when the path names a shared service host (see
/// [`SHARED_SERVICE_HOSTS`]): whole-program enforcement of it is refused.
pub fn is_shared_service_host(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    SHARED_SERVICE_HOSTS
        .iter()
        .any(|host| name.eq_ignore_ascii_case(host))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_dry_run_is_opt_in() {
        // enforcing by default; RAT_DRY_RUN=1 opts out.
        assert!(!dry_run_enabled(None), "must enforce when unset");
        assert!(dry_run_enabled(Some("1")));
        assert!(!dry_run_enabled(Some("0")));
        assert!(!dry_run_enabled(Some("")));
    }

    #[test]
    fn test_shared_service_host_detection() {
        // svchost.exe must never be blocked per-program.
        assert!(is_shared_service_host("C:\\Windows\\System32\\svchost.exe"));
        assert!(is_shared_service_host("C:\\Windows\\System32\\SVCHOST.EXE"));
        assert!(is_shared_service_host("svchost.exe"));
        assert!(!is_shared_service_host("C:\\Windows\\System32\\netsh.exe"));
        assert!(!is_shared_service_host("/usr/bin/curl"));
        assert!(!is_shared_service_host("mysvchost.exe.fake"));
    }

    #[test]
    fn test_shared_service_host_list_covers_windows_brokers() {
        // svchost.exe is not the only host that runs work for MANY apps at
        // once: COM activation (dllhost), Store-app brokering
        // (RuntimeBroker, backgroundTaskHost), scheduled-task and console
        // hosting, rundll32 and WMI providers all share one process across
        // apps — a per-program block on any of them would cut them all.
        // Matching stays on the executable file name, case-insensitive, so
        // full System32/SysWOW64 paths and Windows-cased spellings match.
        for host in [
            "dllhost.exe",
            "RuntimeBroker.exe",
            "taskhostw.exe",
            "backgroundTaskHost.exe",
            "sihost.exe",
            "conhost.exe",
            "rundll32.exe",
            "WmiPrvSE.exe",
        ] {
            assert!(
                is_shared_service_host(&format!(r"C:\Windows\System32\{host}")),
                "full System32 path must match: {host}"
            );
            assert!(
                is_shared_service_host(&format!(
                    r"C:\Windows\SysWOW64\{}",
                    host.to_ascii_uppercase()
                )),
                "uppercased SysWOW64 path must match: {host}"
            );
            assert!(
                is_shared_service_host(host),
                "bare file name must match: {host}"
            );
        }
        // look-alike names that work for themselves stay blockable
        for not in [
            "mydllhost.exe.fake",
            "rundll32x.exe",
            "conhost2.exe",
            r"C:\Windows\System32\netsh.exe",
        ] {
            assert!(!is_shared_service_host(not), "{not} works for itself");
        }
    }

    use proptest::prelude::*;

    #[test]
    fn test_validation_path() {
        let plain = if cfg!(windows) {
            r"C:\ProgramFiles\App"
        } else {
            "/usr/bin/app"
        };
        let spaced = if cfg!(windows) {
            r"C:\Program Files\应用"
        } else {
            "/usr/bin/应用"
        };
        assert!(validate_path(plain).is_ok());
        assert!(validate_path(spaced).is_ok());
        assert!(validate_path("/usr/bin/app; rm -rf /").is_err());
        assert!(validate_path("/usr/bin/app\"").is_err());
        assert!(validate_path("/usr/bin/app\n").is_err());
        assert!(validate_path("/usr/bin/app\r").is_err());
        // an apostrophe is a legal filename character on
        // Windows and no shell is involved (netsh is spawned via
        // Command::args), so O'Brien-style paths must be enforceable.
        if cfg!(windows) {
            assert!(validate_path(r"C:\Users\O'Brien\app.exe").is_ok());
        } else {
            assert!(validate_path("/usr/bin/app'").is_ok());
        }
        assert!(validate_path("/usr/bin/رنامه").is_ok() || cfg!(windows));
        // relative, parent-hopping, and env-var strings are rejected.
        assert!(validate_path("app.exe").is_err(), "relative rejected");
        assert!(validate_path("./app").is_err(), "dot-relative rejected");
        assert!(validate_path("/usr/bin/../app").is_err(), ".. rejected");
        assert!(
            validate_path("$HOME/app").is_err(),
            "env-var string rejected"
        );
        assert!(
            validate_path("%SystemRoot%\\notepad.exe").is_err(),
            "env-var string rejected"
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_validation_path_canonicalizes() {
        // Existing targets come back canonicalized (case resolved, verbatim
        // prefix stripped), so rules always name the real binary.
        let out = validate_path(r"c:\windows\system32\netsh.exe").expect("valid path");
        assert!(
            out.starts_with(r"C:\Windows\"),
            "expected canonical casing, got {out}"
        );
        assert!(std::path::Path::new(&out).is_file());
        assert!(!out.contains(r"\\?\"));
    }

    // --- run_with_timeout: the ONE shared "run with timeout" for every
    // firewall tool child (netsh / PowerShell / nft — known issue "No
    // timeouts on netsh / PowerShell / nft child processes"). The slow child
    // is harmless: loopback ping on Windows, sleep on unix.

    #[cfg(windows)]
    fn system32_tool(name: &str) -> std::path::PathBuf {
        let root = std::env::var_os("SystemRoot")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
        root.join("System32").join(name)
    }

    /// a harmless command that runs far longer than any test limit
    #[cfg(windows)]
    fn slow_command() -> std::process::Command {
        let mut c = std::process::Command::new(system32_tool("ping.exe"));
        c.args(["-n", "30", "127.0.0.1"]);
        c
    }

    #[cfg(unix)]
    fn slow_command() -> std::process::Command {
        let mut c = std::process::Command::new("sleep");
        c.arg("30");
        c
    }

    /// a command that finishes at once and prints a known marker
    #[cfg(windows)]
    fn fast_command() -> std::process::Command {
        let mut c = std::process::Command::new(system32_tool("cmd.exe"));
        c.args(["/c", "echo rat-timeout-ok"]);
        c
    }

    #[cfg(unix)]
    fn fast_command() -> std::process::Command {
        let mut c = std::process::Command::new("sh");
        c.args(["-c", "echo rat-timeout-ok"]);
        c
    }

    /// `sort` reads stdin and echoes it sorted — the nft `-f -` shape
    fn stdin_command() -> std::process::Command {
        #[cfg(windows)]
        {
            std::process::Command::new(system32_tool("sort.exe"))
        }
        #[cfg(not(windows))]
        {
            std::process::Command::new("sort")
        }
    }

    #[test]
    fn test_run_with_timeout_kills_slow_child_and_names_tool_and_limit() {
        let start = std::time::Instant::now();
        let err = run_with_timeout(
            slow_command(),
            "ping",
            std::time::Duration::from_secs(2),
            None,
        )
        .expect_err("a slow child must be killed at the deadline, not awaited");
        let msg = err.to_string();
        assert!(msg.contains("ping"), "error must name the tool: {msg}");
        assert!(msg.contains("2000"), "error must name the limit: {msg}");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::TimedOut,
            "a timeout must be distinguishable from a tool failure"
        );
        assert!(
            start.elapsed() < std::time::Duration::from_secs(15),
            "the child must be killed at the ~2 s deadline, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn test_run_with_timeout_fast_child_succeeds_and_captures_stdout() {
        let out = run_with_timeout(fast_command(), "cmd", TOOL_TIMEOUT, None)
            .expect("a fast child must succeed within the limit");
        assert!(out.status.success());
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("rat-timeout-ok"),
            "stdout must be captured: {stdout:?}"
        );
    }

    #[test]
    fn test_run_with_timeout_writes_stdin_and_returns_its_output() {
        let out = run_with_timeout(
            stdin_command(),
            "sort",
            TOOL_TIMEOUT,
            Some(b"pear\napple\n"),
        )
        .expect("sort must run");
        assert!(out.status.success());
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.trim_start().starts_with("apple"),
            "stdin_data must reach the child and its output come back: {stdout:?}"
        );
    }

    /// a command that writes to stderr and exits 3
    fn failing_command() -> std::process::Command {
        #[cfg(windows)]
        {
            let mut c = std::process::Command::new(system32_tool("cmd.exe"));
            c.args(["/c", "echo rat-boom 1>&2 & exit /b 3"]);
            c
        }
        #[cfg(not(windows))]
        {
            let mut c = std::process::Command::new("sh");
            c.args(["-c", "echo rat-boom >&2; exit 3"]);
            c
        }
    }

    #[test]
    fn test_tool_failure_keeps_the_tools_stderr() {
        // the output is captured by run_with_timeout, so a failed tool's
        // own message must travel in the error, not vanish
        let out = run_with_timeout(failing_command(), "cmd", TOOL_TIMEOUT, None)
            .expect("the child runs; only its exit code is non-zero");
        assert!(!out.status.success());
        let msg = tool_failure("Failed to clean up Rat firewall rules", &out).to_string();
        assert!(
            msg.starts_with("Failed to clean up Rat firewall rules"),
            "{msg}"
        );
        assert!(msg.contains("rat-boom"), "stderr must be quoted: {msg}");
        assert!(msg.contains('3'), "the exit status must be named: {msg}");
    }

    #[test]
    fn test_validation_path_rejects_unc() {
        // UNC must be refused as pure string work BEFORE any
        // canonicalisation: fs::canonicalize on a UNC target does network
        // I/O (a dead server stalls the tick), and a live target comes
        // back mangled — \\?\UNC\server\share strips to UNC\server\share,
        // which is not a path a rule can name. The refused spellings are
        // the plain \\\\server form, the \\\\?\\UNC\\ verbatim form, and
        // (Windows, where / and \ are the same separator) //server/share.
        for unc in [
            r"\\server\share\app.exe",
            r"\\?\UNC\server\share\app.exe",
            r"\\localhost\c$\Windows\System32\netsh.exe",
        ] {
            assert_eq!(
                path_validation_error(unc),
                Some("network (UNC) and device or verbatim paths are not supported; use a plain drive path"),
                "{unc} must be refused by the string gate"
            );
            assert_eq!(
                validate_path(unc).unwrap_err(),
                "network (UNC) and device or verbatim paths are not supported; use a plain drive path",
                "{unc} must be refused before canonicalisation"
            );
        }
        #[cfg(windows)]
        assert_eq!(
            path_validation_error("//server/share/app.exe"),
            Some("network (UNC) and device or verbatim paths are not supported; use a plain drive path"),
            "//server/share is the same UNC path on Windows"
        );
    }

    #[test]
    fn test_validation_path_unc_refusal_is_prefix_only() {
        // The refusal keys on a leading UNC prefix, not on backslashes or
        // `?` in general: ordinary local paths stay valid. A verbatim
        // local spelling (\\\\?\\C:\\...) is refused with the same error
        // because rules must name the plain drive path (netsh rejects
        // `\\?\` anyway).
        if cfg!(windows) {
            assert_eq!(
                path_validation_error(r"C:\Windows\System32\netsh.exe"),
                None
            );
            assert_eq!(
                path_validation_error(r"\\?\C:\Windows\System32\netsh.exe"),
                Some("network (UNC) and device or verbatim paths are not supported; use a plain drive path")
            );
        } else {
            assert_eq!(path_validation_error("/usr/bin/netsh"), None);
        }
    }

    proptest! {
        #[test]
        fn proptest_validate_path_no_panic(s in "\\PC*") {
            let _ = validate_path(&s);
        }

        #[test]
        // `'` is legal, so it left the rejected class.
        fn proptest_validate_path_rejects_bad_chars(s in ".*[\";\n\r].*") {
            assert!(validate_path(&s).is_err());
        }

        #[test]
        fn proptest_validate_path_accepts_good_absolute_paths(s in "[^\";\n\r/\\\\]+") {
            let base = if cfg!(windows) { r"C:\x" } else { "/x" };
            assert!(validate_path(&format!("{base}{s}")).is_ok());
        }
    }
}
