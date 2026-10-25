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
    fn apply(&self, plan: &Self::Plan) -> io::Result<()>;
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

/// S6 (update-08): an enforcer path must be absolute, free of shell-meta
/// characters and `..` segments, and canonicalized (symlinks/junctions
/// resolved) when the target exists, so a rule cannot point validation at
/// one file and enforcement at another.
pub fn validate_path(path: &str) -> Result<String, &'static str> {
    if path.contains(['"', '\'', ';', '\n', '\r']) {
        return Err("invalid characters in path");
    }
    let p = std::path::Path::new(path);
    if !p.is_absolute() {
        return Err("path must be absolute");
    }
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("parent-directory components are not allowed");
    }
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
        assert!(validate_path("/usr/bin/app'").is_err());
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
        fn proptest_validate_path_rejects_bad_chars(s in ".*[\"';\n\r].*") {
            assert!(validate_path(&s).is_err());
        }

        #[test]
        fn proptest_validate_path_accepts_good_absolute_paths(s in "[^\"';\n\r/\\\\]+") {
            let base = if cfg!(windows) { r"C:\x" } else { "/x" };
            assert!(validate_path(&format!("{base}{s}")).is_ok());
        }
    }
}
