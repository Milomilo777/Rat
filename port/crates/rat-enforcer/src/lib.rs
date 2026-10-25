use std::io;

#[cfg(not(windows))]
pub mod linux;
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
    /// review-01 R6: apply() OWNS the enforcer's notion of the current
    /// state. A Windows implementation advances `current` to the plan's
    /// outcome on success (so re-planning an unchanged wanted state is an
    /// empty diff) and leaves it behind on failure (the next diff retries);
    /// its add path must be idempotent, because netsh duplicates a rule when
    /// the name already exists.
    fn apply(&mut self, plan: &Self::Plan) -> io::Result<()>;
    /// S8 (update-08): remove every rule this enforcer created. Called on
    /// start and on clean shutdown (daemon wiring, PROPOSALS #10) so
    /// persistent rules do not survive crashes as duplicates; systemd's
    /// ExecStopPost covers the linux daemon meanwhile.
    fn cleanup(&self) -> io::Result<()> {
        Ok(())
    }
}

/// S7 (update-08): the enforcer RUNS by default; `RAT_DRY_RUN=1` is the
/// explicit opt-out for tests and dry runs. (Previously nothing was ever
/// enforced unless `RAT_ENFORCE=1` was set — including in production.)
pub fn dry_run_enabled(env_value: Option<&str>) -> bool {
    env_value == Some("1")
}

/// The rejection rules of [`validate_path`] WITHOUT the canonicalize: `None`
/// means the path would pass. review-01 R8: plan() decides reject-vs-report
/// with this — it is pure string work (no filesystem access, so the
/// PROPOSALS #7 plan budget holds) and it is EXACTLY apply()'s rejection
/// set, because the canonicalize step never rejects (a not-yet-existing
/// target passes as-is).
pub fn path_validation_error(path: &str) -> Option<&'static str> {
    // Byte-level scans, exactly equivalent to the char-level checks: every
    // delimiter and match target is ASCII, and UTF-8 continuation bytes are
    // never ASCII, so a multibyte character can neither match nor split.
    // plan() runs this per path per tick (PROPOSALS #7 budget) and the
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

/// S6 (update-08): an enforcer path must be absolute, free of `..` segments,
/// free of characters that cannot occur in a real filename or that could
/// confuse netsh's `name=` parsing (`"` is impossible in a Windows filename,
/// CR/LF are control characters; `;` stays rejected as defense-in-depth even
/// though no shell is involved — PROPOSALS review-01 R8 follow-up), and
/// canonicalized (symlinks/junctions resolved) when the target exists, so a
/// rule cannot point validation at one file and enforcement at another.
/// review-01 R8: `'` IS accepted — it is a legal Windows filename character
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

/// W2 (update-04 architecture review / PROPOSALS #1): svchost.exe hosts DNS
/// (Dnscache), DHCP and many other services for the WHOLE machine — a
/// per-program block rule for it cuts them all at once. Whole-program
/// enforcement of shared service hosts is refused instead (see
/// `WindowsPlan::refused`); block by the denied sockets' local ports or a
/// future per-service mechanism instead. Kept local and minimal so the crate
/// stays std-only; the cross-platform classification table lives in
/// rat-ledger's `shared` module.
pub fn is_shared_service_host(path: &str) -> bool {
    let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
    name.eq_ignore_ascii_case("svchost.exe")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_dry_run_is_opt_in() {
        // S7 (update-08): enforcing by default; RAT_DRY_RUN=1 opts out.
        assert!(!dry_run_enabled(None), "must enforce when unset");
        assert!(dry_run_enabled(Some("1")));
        assert!(!dry_run_enabled(Some("0")));
        assert!(!dry_run_enabled(Some("")));
    }

    #[test]
    fn test_shared_service_host_detection() {
        // W2 / PROPOSALS #1: svchost.exe must never be blocked per-program.
        assert!(is_shared_service_host("C:\\Windows\\System32\\svchost.exe"));
        assert!(is_shared_service_host("C:\\Windows\\System32\\SVCHOST.EXE"));
        assert!(is_shared_service_host("svchost.exe"));
        assert!(!is_shared_service_host("C:\\Windows\\System32\\netsh.exe"));
        assert!(!is_shared_service_host("/usr/bin/curl"));
        assert!(!is_shared_service_host("mysvchost.exe.fake"));
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
        // review-01 R8: an apostrophe is a legal filename character on
        // Windows and no shell is involved (netsh is spawned via
        // Command::args), so O'Brien-style paths must be enforceable.
        if cfg!(windows) {
            assert!(validate_path(r"C:\Users\O'Brien\app.exe").is_ok());
        } else {
            assert!(validate_path("/usr/bin/app'").is_ok());
        }
        assert!(validate_path("/usr/bin/رنامه").is_ok() || cfg!(windows));
        // S6: relative, parent-hopping, and env-var strings are rejected.
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

    proptest! {
        #[test]
        fn proptest_validate_path_no_panic(s in "\\PC*") {
            let _ = validate_path(&s);
        }

        #[test]
        // review-01 R8: `'` is legal, so it left the rejected class.
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
