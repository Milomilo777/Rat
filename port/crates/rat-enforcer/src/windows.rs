use std::collections::HashSet;
use std::io;

use crate::{Blocklist, Enforcer};

/// test seam: stands in for the spawned netsh child. When set,
/// apply() routes EVERY command through it instead of spawning (and instead
/// of the dry-run print) — the seam owns execution, so tests can model real
/// netsh semantics. `Ok(true)` = exit success, `Ok(false)` = failure exit —
/// except on `delete rule` commands, where `Ok(false)`
/// models netsh's no-match exit ("No rules match the specified criteria"),
/// which the reconcile remove loops tolerate; a real delete failure is
/// `Err` there.
pub type NetshRunner =
    std::sync::Arc<dyn Fn(&std::path::Path, &[String]) -> io::Result<bool> + Send + Sync>;

pub struct WindowsEnforcer {
    pub current: Blocklist,
    /// None = production behavior (RAT_DRY_RUN prints, otherwise spawn).
    pub runner: Option<NetshRunner>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsPlan {
    pub add: Vec<String>,
    pub remove: Vec<String>,
    /// denied LOCAL ports to add as per-port rules — the
    /// Windows mirror of the Linux backend's `rat_ports` nft set and the
    /// macOS Ledger's local-port blocks (Ledger.swift:330-332). This is also
    /// what a refused shared host's denied socket gets instead of a silent
    /// no-op ("block by port instead").
    pub add_ports: Vec<u16>,
    pub remove_ports: Vec<u16>,
    /// wanted whole-program blocks that were REFUSED
    /// because the target is a shared service host (svchost.exe, dllhost.exe
    /// and friends run work for the whole machine). The caller decides how to tell
    /// the user; per-port rules below still apply.
    pub refused: Vec<String>,
    /// whole-program entries (from `wanted` or from `current`)
    /// that FAILED path validation. They are reported here and skipped — no
    /// rule is ever created from or deleted by an unvalidated string (the validation
    /// invariant), they are never claimed into the enforcer's `current`, and
    /// the REST of the plan still applies. Same contract as `refused`: the
    /// caller decides how to tell the user.
    pub rejected: Vec<String>,
}

pub fn generate_windows_plan(current: &Blocklist, wanted: &Blocklist) -> WindowsPlan {
    // Avoid O(n^2) nested loops by converting one list to a HashSet, giving O(n) average time complexity.
    let current_set: HashSet<&str> = current.paths.iter().map(String::as_str).collect();
    // the wanted set in NORMALISED form (what apply() stores in
    // `current`), so a differently-spelled path (letter case, symlink,
    // trailing dot) diffs equal instead of churning remove + add each tick.
    let mut wanted_set: HashSet<String> = HashSet::new();

    let mut add = Vec::new();
    let mut refused = Vec::new();
    // entries that fail path validation are REPORTED here and
    // skipped — one unenforceable entry must not fail (or silently void) the
    // rest of the plan. Same channel as `refused`: the caller tells the user.
    let mut rejected = Vec::new();
    for path in &wanted.paths {
        // run apply's own validation (rules AND
        // canonicalisation) FIRST. An invalid wanted path is reported and
        // never becomes a rule; the rest of the plan is unaffected.
        let normalised = match crate::validate_path(path) {
            Ok(n) => n,
            Err(_) => {
                rejected.push(path.clone());
                continue;
            }
        };
        wanted_set.insert(normalised.clone());
        // never block a shared service host per-program — checked on the
        // RAW and the NORMALISED form (a non-canonical spelling can resolve
        // to one, and apply() aborts the whole plan on such an add). The
        // caller's own spelling is what gets reported.
        if crate::is_shared_service_host(path) || crate::is_shared_service_host(&normalised) {
            if !refused.contains(path) {
                refused.push(path.clone());
            }
            continue;
        }
        if !current_set.contains(normalised.as_str()) {
            add.push(normalised);
        }
    }

    let mut remove = Vec::new();
    for path in &current.paths {
        if wanted_set.contains(path) {
            continue;
        }
        // a rule name that fails the validation rules
        // (e.g. a hostile hand-made `Rat:path:*` rule picked up by the
        // read-back) cannot be built into a netsh delete command. It is
        // reported and never enters `remove`, so apply() cannot claim it
        // gone — the entry stays in `current` (no diff churn) and the
        // uninstall cleanup still removes every Rat rule.
        if crate::path_validation_error(path).is_some() {
            rejected.push(path.clone());
            continue;
        }
        remove.push(path.clone());
    }

    // the port axis diffs like the path axis. Local ports are
    // ephemeral, so their churn (denied socket opens/closes) is expected —
    // the ledger's plan drops a closed socket's port from the wanted set and
    // the diff removes the rule.
    let current_ports: HashSet<u16> = current.local_ports.iter().copied().collect();
    let wanted_ports: HashSet<u16> = wanted.local_ports.iter().copied().collect();
    let mut add_ports: Vec<u16> = wanted
        .local_ports
        .iter()
        .copied()
        .filter(|p| !current_ports.contains(p))
        .collect();
    let mut remove_ports: Vec<u16> = current
        .local_ports
        .iter()
        .copied()
        .filter(|p| !wanted_ports.contains(p))
        .collect();

    // Sort to make plan output deterministic
    add.sort();
    add.dedup();
    remove.sort();
    refused.sort();
    rejected.sort();
    rejected.dedup();
    add_ports.sort();
    add_ports.dedup();
    remove_ports.sort();
    remove_ports.dedup();

    WindowsPlan {
        add,
        remove,
        add_ports,
        remove_ports,
        refused,
        rejected,
    }
}

pub fn format_rule_name(path: &str) -> String {
    format!("Rat:path:{}", path)
}

/// per-port rules share one name per port so the delete path
/// removes every variant at once.
pub fn format_port_rule_name(port: u16) -> String {
    format!("Rat:port:{}", port)
}

/// The netsh arguments for one per-program block rule (dir=out block on the
/// validated program path). Shape pinned by tests; tests never run netsh.
fn path_rule_args(name: &str, program: &str) -> Vec<String> {
    vec![
        "advfirewall".to_string(),
        "firewall".to_string(),
        "add".to_string(),
        "rule".to_string(),
        format!("name={name}"),
        "dir=out".to_string(),
        "action=block".to_string(),
        format!("program={program}"),
    ]
}

/// The netsh arguments to delete every rule carrying one display name (the
/// reconcile remove loop, and the pre-add dedupe).
fn path_delete_args(name: &str) -> Vec<String> {
    vec![
        "advfirewall".to_string(),
        "firewall".to_string(),
        "delete".to_string(),
        "rule".to_string(),
        format!("name={name}"),
    ]
}

/// The netsh arguments for one per-port block rule. `localport=` needs a
/// concrete protocol (netsh rejects port parameters with protocol=any), and
/// the Linux backend blocks both tcp and udp in both directions
/// (linux.rs drop_out sport / drop_in dport), so one port yields four rules
/// that all share [`format_port_rule_name`].
fn port_rule_args(port: u16, dir: &str, proto: &str) -> Vec<String> {
    vec![
        "advfirewall".to_string(),
        "firewall".to_string(),
        "add".to_string(),
        "rule".to_string(),
        format!("name={}", format_port_rule_name(port)),
        format!("dir={dir}"),
        "action=block".to_string(),
        format!("protocol={proto}"),
        format!("localport={port}"),
    ]
}

/// The netsh arguments to remove every variant of one port's rules (name
/// match covers all four directions/protocols).
fn port_delete_args(port: u16) -> Vec<String> {
    vec![
        "advfirewall".to_string(),
        "firewall".to_string(),
        "delete".to_string(),
        "rule".to_string(),
        format!("name={}", format_port_rule_name(port)),
    ]
}

/// resolve netsh from %SystemRoot% instead of PATH / the
/// working directory, so a tampered PATH cannot substitute the binary the
/// privileged daemon shells out to.
pub fn netsh_path() -> io::Result<std::path::PathBuf> {
    let root = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
    let candidate = root.join(r"System32\netsh.exe");
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "netsh.exe not found under SystemRoot",
        ))
    }
}

/// resolve powershell from %SystemRoot% for the wildcard
/// rule cleanup (netsh cannot delete by name pattern); same PATH-hardening
/// rationale as [`netsh_path`].
pub fn powershell_path() -> io::Result<std::path::PathBuf> {
    let root = std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows"));
    let candidate = root.join(r"System32\WindowsPowerShell\v1.0\powershell.exe");
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "powershell.exe not found under SystemRoot",
        ))
    }
}

impl Enforcer for WindowsEnforcer {
    type Plan = WindowsPlan;

    fn plan(&self, wanted: &Blocklist) -> Self::Plan {
        generate_windows_plan(&self.current, wanted)
    }

    #[cfg(not(windows))]
    fn apply(&mut self, _plan: &Self::Plan) -> io::Result<()> {
        // Only for compiling tests on Linux
        Ok(())
    }

    #[cfg(windows)]
    fn apply(&mut self, plan: &Self::Plan) -> io::Result<()> {
        use std::env;
        use std::process::Command;

        // validate AND canonicalize every path before use,
        // so rule names and program= targets always name the real binary.
        // ONE invalid path must not fail the whole plan (the
        // previous `collect()?` aborted every other entry — a hostile
        // read-back rule name or one weird path disabled ALL enforcement).
        // Entries that fail validation are SKIPPED on BOTH axes: no rule is
        // ever created from or deleted by an unvalidated string (the validation
        // invariant), the skipped entry is never claimed into `current`, and
        // plan() reports it via `WindowsPlan::rejected` for plan-built plans
        // (the caller tells the user); a hand-built plan's skips are the
        // caller's own to observe. The shared-host refusal below is the
        // one remaining whole-plan abort: it refuses to CREATE a dangerous
        // rule, a different class than tolerating an unenforceable one.
        let partition = |paths: &[String]| -> (Vec<String>, Vec<String>) {
            let mut ok = Vec::new();
            let mut bad = Vec::new();
            for p in paths {
                match crate::validate_path(p) {
                    Ok(v) => ok.push(v),
                    Err(_) => bad.push(p.clone()),
                }
            }
            (ok, bad)
        };
        let (remove, _skipped_removes) = partition(&plan.remove);
        let (add, _skipped_adds) = partition(&plan.add);

        // plan already refuses shared service hosts; a
        // hand-built plan must not be able to smuggle one through — fail
        // closed, also in dry-run.
        if let Some(path) = add.iter().find(|p| crate::is_shared_service_host(p)) {
            return Err(io::Error::other(format!(
                "refusing whole-program block of shared service host {path} (would cut shared system services machine-wide); block by port instead"
            )));
        }

        let dry_run = crate::dry_run_enabled(env::var("RAT_DRY_RUN").ok().as_deref());
        let netsh = netsh_path()?;
        let runner = self.runner.clone();
        // One netsh invocation. An injected runner (tests) owns execution;
        // otherwise RAT_DRY_RUN=1 prints the same command and succeeds, or
        // the real child is spawned under the shared timeout helper — a hung
        // netsh is killed at TOOL_TIMEOUT with an error naming tool+limit
        // instead of stalling the pipeline forever.
        let run = |args: &[String], dry_line: String| -> io::Result<bool> {
            if let Some(runner) = &runner {
                runner(&netsh, args)
            } else if dry_run {
                println!("{dry_line}");
                Ok(true)
            } else {
                let mut cmd = Command::new(&netsh);
                cmd.args(args);
                Ok(
                    crate::run_with_timeout(cmd, "netsh", crate::TOOL_TIMEOUT, None)?
                        .status
                        .success(),
                )
            }
        };
        // the reconcile remove loops' delete of
        // an ALREADY-GONE rule (user/GPO removed it) exits 1 — success for
        // that delete, because its desired state is already reached. The
        // decision is by EXIT CODES, never by message text: the old
        // English-only "no rules match" grep failed open on a localized
        // Windows (every tick errored, `current` never advanced, no new
        // block was ever applied). After a non-zero delete, probe
        // `show rule name=<n>`: it exits non-zero exactly when the rule is
        // absent — locale-stable. Show failing = tolerate; show succeeding =
        // the rule is still there = a real delete failure, which still
        // aborts the plan (fail-closed, `current` stays behind, the next
        // diff retries). The runner seam follows the SAME path (its bool is
        // the child's exit status), so the seam tests exercise the probe.
        let run_delete = |name: &str, args: &[String], dry_line: String| -> io::Result<bool> {
            if runner.is_none() && dry_run {
                println!("{dry_line}");
                return Ok(true);
            }
            let run_netsh = |a: &[String]| -> io::Result<bool> {
                if let Some(runner) = &runner {
                    runner(&netsh, a)
                } else {
                    let mut cmd = Command::new(&netsh);
                    cmd.args(a);
                    Ok(
                        crate::run_with_timeout(cmd, "netsh", crate::TOOL_TIMEOUT, None)?
                            .status
                            .success(),
                    )
                }
            };
            if run_netsh(args)? {
                return Ok(true);
            }
            let show_args = [
                "advfirewall".to_string(),
                "firewall".to_string(),
                "show".to_string(),
                "rule".to_string(),
                format!("name={name}"),
            ];
            Ok(!run_netsh(&show_args)?)
        };

        for path in &remove {
            let name = format_rule_name(path);
            // a verified-gone rule's delete is tolerated (see
            // run_delete); a real failure aborts.
            if !run_delete(
                &name,
                &path_delete_args(&name),
                format!("netsh advfirewall firewall delete rule name=\"{name}\""),
            )? {
                return Err(io::Error::other("Failed to delete firewall rule"));
            }
        }

        for path in &add {
            let name = format_rule_name(path);
            // netsh `add rule` DUPLICATES a rule whose name already
            // exists, so delete any same-name rule first — a stale diff
            // (restart with a failed read-back, a canonicalized rename)
            // would otherwise pile up copies. Best-effort: "no rules match"
            // is netsh exit 1 and the normal first-add case, while a real
            // failure still surfaces at the checked add below, so this
            // delete's status is ignored.
            let _ = run(
                &path_delete_args(&name),
                format!("netsh advfirewall firewall delete rule name=\"{name}\""),
            )?;
            if !run(
                &path_rule_args(&name, path),
                format!(
                    "netsh advfirewall firewall add rule name=\"{name}\" dir=out action=block program=\"{path}\""
                ),
            )? {
                return Err(io::Error::other("Failed to add firewall rule"));
            }
        }

        // the port axis. One delete per port (removes all four
        // variants), four adds per new port (out/in x TCP/UDP).
        for port in &plan.remove_ports {
            let name = format_port_rule_name(*port);
            // the same exit-code tolerance as the path delete site.
            if !run_delete(
                &name,
                &port_delete_args(*port),
                format!("netsh advfirewall firewall delete rule name=\"{name}\""),
            )? {
                return Err(io::Error::other(format!(
                    "Failed to delete firewall port rule {port}"
                )));
            }
        }

        for port in &plan.add_ports {
            let name = format_port_rule_name(*port);
            // the same pre-add dedupe as the path axis; one delete
            // removes all four variants of the port.
            let _ = run(
                &port_delete_args(*port),
                format!("netsh advfirewall firewall delete rule name=\"{name}\""),
            )?;
            for (dir, proto) in [("out", "TCP"), ("out", "UDP"), ("in", "TCP"), ("in", "UDP")] {
                let name = format_port_rule_name(*port);
                if !run(
                    &port_rule_args(*port, dir, proto),
                    format!(
                        "netsh advfirewall firewall add rule name=\"{name}\" dir={dir} action=block protocol={proto} localport={port}"
                    ),
                )? {
                    return Err(io::Error::other(format!(
                        "Failed to add firewall port rule {port} dir={dir} protocol={proto}"
                    )));
                }
            }
        }

        // Part 1: apply owns the crate's view of reality. Advance
        // `current` to what the firewall now holds — the VALIDATED names the
        // rules were actually created under, so a later read-back reconcile
        // sees the same strings (raw-vs-validated normalization is separate). On
        // any failure above, the early returns leave `current` behind so the
        // next diff retries the same change; the pre-add deletes make that
        // retry idempotent instead of duplicating.
        let removed: HashSet<&String> = remove.iter().collect();
        let mut paths: Vec<String> = self
            .current
            .paths
            .iter()
            .filter(|p| !removed.contains(*p))
            .cloned()
            .collect();
        paths.extend(add.iter().cloned());
        paths.sort();
        paths.dedup();
        let removed_ports: HashSet<u16> = plan.remove_ports.iter().copied().collect();
        let mut local_ports: Vec<u16> = self
            .current
            .local_ports
            .iter()
            .copied()
            .filter(|p| !removed_ports.contains(p))
            .collect();
        local_ports.extend(plan.add_ports.iter().copied());
        local_ports.sort();
        local_ports.dedup();
        self.current = Blocklist { paths, local_ports };
        Ok(())
    }

    /// netsh cannot delete by name pattern, so the wildcard
    /// cleanup goes through PowerShell's NetSecurity module.
    fn cleanup(&self) -> io::Result<()> {
        use std::env;
        use std::process::Command;

        let dry_run = crate::dry_run_enabled(env::var("RAT_DRY_RUN").ok().as_deref());
        if dry_run {
            println!("powershell: {CLEANUP_RULES_QUERY}");
            return Ok(());
        }

        let mut cmd = Command::new(powershell_path()?);
        cmd.args(["-NoProfile", "-Command", CLEANUP_RULES_QUERY]);
        let out = crate::run_with_timeout(cmd, "powershell", crate::TOOL_TIMEOUT, None)?;
        if !out.status.success() {
            return Err(crate::tool_failure(
                "Failed to clean up Rat firewall rules",
                &out,
            ));
        }
        Ok(())
    }
}

/// the wildcard cleanup must remove BOTH rule families this
/// daemon creates — per-program (`Rat:path:*`) and per-port (`Rat:port:*`).
pub(crate) const CLEANUP_RULES_QUERY: &str = "Get-NetFirewallRule -DisplayName @('Rat:path:*','Rat:port:*') -ErrorAction SilentlyContinue | Remove-NetFirewallRule";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_powershell_resolved_absolute() {
        let p = powershell_path().expect("powershell must resolve under SystemRoot");
        assert!(
            p.is_absolute(),
            "powershell must be resolved absolutely: {p:?}"
        );
        assert!(p.is_file(), "resolved powershell does not exist: {p:?}");
    }

    #[test]
    fn test_windows_cleanup_is_dry_run_safe() {
        // with the dry-run opt-out set, cleanup must not spawn
        // any process (verified by it succeeding instantly offline).
        std::env::set_var("RAT_DRY_RUN", "1");
        let enforcer = WindowsEnforcer {
            current: Blocklist::default(),
            runner: None,
        };
        enforcer.cleanup().expect("dry-run cleanup must succeed");
    }

    #[test]
    fn test_netsh_resolved_absolute() {
        let p = netsh_path().expect("netsh must resolve under SystemRoot");
        assert!(p.is_absolute(), "netsh must be resolved absolutely: {p:?}");
        assert!(p.is_file(), "resolved netsh does not exist: {p:?}");
        assert_eq!(
            p.file_name().and_then(|n| n.to_str()),
            Some("netsh.exe"),
            "unexpected binary: {p:?}"
        );
    }
    use proptest::prelude::*;
    use std::time::Instant;

    #[test]
    fn test_windows_plan_diff() {
        // plan() validates every path it diffs, so these must
        // be absolute paths that are valid on the host this test runs on
        // (the plan stage is where an invalid entry is reported and skipped).
        let (old, new) = if cfg!(windows) {
            (r"C:\Apps\Old\app.exe", r"C:\Apps\New\app.exe")
        } else {
            ("/usr/bin/old", "/usr/bin/new")
        };
        let current = Blocklist {
            paths: vec![old.to_string()],
            local_ports: vec![],
        };
        let wanted = Blocklist {
            paths: vec![new.to_string()],
            local_ports: vec![],
        };

        let enforcer = WindowsEnforcer {
            current,
            runner: None,
        };
        let plan = enforcer.plan(&wanted);

        assert_eq!(plan.add.len(), 1);
        if let Some(first_add) = plan.add.first() {
            assert_eq!(first_add, new);
        }

        assert_eq!(plan.remove.len(), 1);
        if let Some(first_remove) = plan.remove.first() {
            assert_eq!(first_remove, old);
        }
        assert!(plan.rejected.is_empty(), "valid paths are never rejected");
    }

    #[test]
    fn test_windows_plan_refuses_shared_service_host() {
        // svchost.exe must never become a program= rule;
        // the refusal is reported, not silently dropped.
        let wanted = Blocklist {
            paths: vec![
                r"C:\Apps\Denied\app.exe".to_string(),
                r"C:\Windows\System32\svchost.exe".to_string(),
            ],
            local_ports: vec![],
        };
        let enforcer = WindowsEnforcer {
            current: Blocklist::default(),
            runner: None,
        };
        let plan = enforcer.plan(&wanted);
        assert_eq!(plan.add, vec![r"C:\Apps\Denied\app.exe".to_string()]);
        assert_eq!(
            plan.refused,
            vec![r"C:\Windows\System32\svchost.exe".to_string()]
        );
    }

    #[test]
    fn test_windows_plan_rejects_invalid_path_and_reports_it() {
        // ONE invalid path (a `"` cannot occur in a real
        // Windows filename) must not fail or void the plan — it is reported
        // in `rejected` and skipped, the rest of the plan still applies.
        let good = r"C:\Apps\Denied\app.exe";
        let bad = r#"C:\Users\bad"; app.exe"#;
        let wanted = Blocklist {
            paths: vec![good.to_string(), bad.to_string()],
            local_ports: vec![],
        };
        let enforcer = WindowsEnforcer {
            current: Blocklist::default(),
            runner: None,
        };
        let plan = enforcer.plan(&wanted);
        assert_eq!(plan.add, vec![good.to_string()], "the good path is added");
        assert_eq!(
            plan.rejected,
            vec![bad.to_string()],
            "the invalid path is reported, not silently dropped"
        );
        assert!(plan.refused.is_empty());
    }

    #[test]
    fn test_windows_plan_invalid_current_path_reported_not_removed() {
        // Remove axis: a rule name that fails validation (a
        // hostile read-back entry, e.g. a hand-made `Rat:path:*` rule) cannot
        // be built into a netsh delete command. It is reported and never
        // enters `remove` — so apply() cannot claim it gone and the entry
        // stays in `current` instead of churning the diff forever.
        let good_gone = r"C:\Apps\Old\gone.exe";
        let bad = r#"C:\Users\bad"; app.exe"#;
        let current = Blocklist {
            paths: vec![good_gone.to_string(), bad.to_string()],
            local_ports: vec![],
        };
        let wanted = Blocklist {
            paths: vec![r"C:\Apps\Kept\app.exe".to_string()],
            local_ports: vec![],
        };
        let enforcer = WindowsEnforcer {
            current,
            runner: None,
        };
        let plan = enforcer.plan(&wanted);
        assert_eq!(
            plan.remove,
            vec![good_gone.to_string()],
            "only valid stale entries are removed"
        );
        assert_eq!(plan.rejected, vec![bad.to_string()]);
    }

    /// test helper: a private temp directory removed on drop.
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static N: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!(
                "rat-v2-{tag}-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&dir).expect("create temp dir");
            TempDir(dir)
        }
        fn file(&self, name: &str) -> std::path::PathBuf {
            let p = self.0.join(name);
            std::fs::write(&p, b"x").expect("create temp file");
            p
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_plan_normalised_path_no_churn_across_ticks() {
        // current holds NORMALISED paths (apply() stores them). The same
        // program wanted in another letter case must diff equal, not churn
        // a remove + add every tick.
        let dir = TempDir::new("case");
        let real = dir.file("CaseApp.exe");
        let real = real.to_string_lossy().to_string();
        let swapped: String = real
            .chars()
            .map(|c| {
                if c.is_ascii_lowercase() {
                    c.to_ascii_uppercase()
                } else {
                    c.to_ascii_lowercase()
                }
            })
            .collect();
        assert_ne!(real, swapped);

        let mut enforcer = WindowsEnforcer {
            current: Blocklist::default(),
            runner: None,
        };
        let plan1 = enforcer.plan(&Blocklist {
            paths: vec![real.clone()],
            local_ports: vec![],
        });
        assert_eq!(plan1.add.len(), 1);
        // What apply() does: current advances to the planned (normalised) adds.
        enforcer.current = Blocklist {
            paths: plan1.add.clone(),
            local_ports: vec![],
        };
        let plan2 = enforcer.plan(&Blocklist {
            paths: vec![swapped],
            local_ports: vec![],
        });
        assert!(plan2.add.is_empty(), "no re-add churn: {:?}", plan2.add);
        assert!(
            plan2.remove.is_empty(),
            "no remove churn: {:?}",
            plan2.remove
        );
        assert!(plan2.rejected.is_empty());
    }

    #[test]
    fn test_windows_plan_noncanonical_shared_host_is_refused() {
        // a path that only NORMALISES to a shared service host (trailing
        // dot on Windows, a symlink elsewhere) must be refused at plan time,
        // not planned and then abort apply(); other adds are still planned.
        let dir = TempDir::new("shared");
        let good = dir.file("good.exe");
        let good = good.to_string_lossy().to_string();
        let host = dir.file("svchost.exe");
        #[cfg(windows)]
        let sneaky = format!("{}.", host.to_string_lossy());
        #[cfg(unix)]
        let sneaky = {
            let link = dir.0.join("innocent.exe");
            std::os::unix::fs::symlink(&host, &link).expect("symlink");
            link.to_string_lossy().to_string()
        };
        #[cfg(not(any(windows, unix)))]
        let sneaky = host.to_string_lossy().to_string();

        let enforcer = WindowsEnforcer {
            current: Blocklist::default(),
            runner: None,
        };
        let plan = enforcer.plan(&Blocklist {
            paths: vec![sneaky.clone(), good.clone()],
            local_ports: vec![],
        });
        assert_eq!(plan.refused, vec![sneaky], "refused, not planned");
        assert_eq!(
            plan.add.len(),
            1,
            "other adds still planned: {:?}",
            plan.add
        );
        assert!(plan.add[0].to_ascii_lowercase().ends_with("good.exe"));
        assert!(plan.rejected.is_empty());
    }

    #[test]
    fn test_windows_plan_invalid_wanted_path_reported_valid_planned() {
        // validation runs first; an invalid wanted path is reported in
        // `rejected` and the valid existing paths are still planned
        // (in normalised form).
        let dir = TempDir::new("invalid");
        let a = dir.file("a.exe");
        let b = dir.file("b.exe");
        let bad = format!("{}\"; evil", a.to_string_lossy());
        let enforcer = WindowsEnforcer {
            current: Blocklist::default(),
            runner: None,
        };
        let plan = enforcer.plan(&Blocklist {
            paths: vec![
                a.to_string_lossy().to_string(),
                bad.clone(),
                b.to_string_lossy().to_string(),
            ],
            local_ports: vec![],
        });
        assert_eq!(plan.rejected, vec![bad]);
        assert_eq!(plan.add.len(), 2);
        assert!(plan.refused.is_empty());
    }

    #[test]
    fn test_windows_apply_refuses_shared_service_host_plan() {
        // Fail closed even for a hand-built plan, also in dry-run.
        std::env::set_var("RAT_DRY_RUN", "1");
        let plan = WindowsPlan {
            add: vec![r"C:\Windows\System32\svchost.exe".to_string()],
            remove: vec![],
            add_ports: vec![],
            remove_ports: vec![],
            refused: vec![],
            rejected: vec![],
        };
        let mut enforcer = WindowsEnforcer {
            current: Blocklist::default(),
            runner: None,
        };
        let err = enforcer.apply(&plan).unwrap_err();
        assert!(
            err.to_string().contains("shared service host"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_windows_plan_ports_diff() {
        // the port axis diffs like the path axis, sorted and
        // deduplicated.
        let current = Blocklist {
            paths: vec![],
            local_ports: vec![2, 1],
        };
        let wanted = Blocklist {
            paths: vec![],
            local_ports: vec![3, 2, 2],
        };
        let enforcer = WindowsEnforcer {
            current,
            runner: None,
        };
        let plan = enforcer.plan(&wanted);
        assert_eq!(plan.add_ports, vec![3]);
        assert_eq!(plan.remove_ports, vec![1]);
        assert!(plan.add.is_empty());
        assert!(plan.remove.is_empty());
    }

    #[test]
    fn test_windows_plan_refused_host_keeps_port_axis() {
        // a refused shared service host must not be a silent
        // no-op — the denied socket's local port still becomes a per-port
        // rule ("block by port instead").
        let svchost = r"C:\Windows\System32\svchost.exe";
        let wanted = Blocklist {
            paths: vec![svchost.to_string()],
            local_ports: vec![5353],
        };
        let enforcer = WindowsEnforcer {
            current: Blocklist::default(),
            runner: None,
        };
        let plan = enforcer.plan(&wanted);
        assert_eq!(plan.refused, vec![svchost.to_string()]);
        assert!(plan.add.is_empty(), "the shared host itself is never added");
        assert_eq!(plan.add_ports, vec![5353]);
    }

    #[test]
    fn test_windows_port_rule_args_shape() {
        // The netsh command shape is pinned here because tests never run
        // netsh for real (dry-run prints the same builders).
        let args = port_rule_args(5300, "out", "TCP");
        for want in [
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=Rat:port:5300",
            "dir=out",
            "action=block",
            "protocol=TCP",
            "localport=5300",
        ] {
            assert!(
                args.iter().any(|a| a == want),
                "missing {want:?} in {args:?}"
            );
        }
        let del = port_delete_args(5300);
        assert!(del.contains(&"delete".to_string()));
        assert!(del.contains(&"name=Rat:port:5300".to_string()));
    }

    #[test]
    fn test_windows_cleanup_covers_both_rule_families() {
        // cleanup must remove per-path AND per-port rules.
        assert!(CLEANUP_RULES_QUERY.contains("'Rat:path:*'"));
        assert!(CLEANUP_RULES_QUERY.contains("'Rat:port:*'"));
        assert!(CLEANUP_RULES_QUERY.contains("Remove-NetFirewallRule"));
    }

    #[test]
    fn test_windows_plan_spaces_non_ascii() {
        let current = Blocklist {
            paths: vec!["C:\\Program Files\\App".to_string()],
            local_ports: vec![],
        };
        let wanted = Blocklist {
            paths: vec!["C:\\Program Files\\App".to_string(), "C:\\应用".to_string()],
            local_ports: vec![],
        };
        let enforcer = WindowsEnforcer {
            current,
            runner: None,
        };
        let plan = enforcer.plan(&wanted);
        assert_eq!(plan.add.len(), 1);
        if let Some(first_add) = plan.add.first() {
            assert_eq!(first_add, "C:\\应用");
        }
        assert_eq!(plan.remove.len(), 0);
    }

    #[test]
    fn test_windows_apply_reports_invalid_path_and_applies_rest() {
        // The no-rule-for-an-invalid-path invariant stands
        // — no rule is ever created for a path that fails validate_path, not
        // even in dry-run — but ONE invalid path must no longer abort the
        // whole plan: it is reported (plan.rejected) and skipped, the rest
        // applies. (Previously this test pinned the abort the reviewer
        // flagged: `collect()?` failed the plan on the first invalid entry.)
        std::env::set_var("RAT_DRY_RUN", "1");
        let current = Blocklist::default();
        let good = r"C:\Program Files\App\app.exe";
        let bad = "C:\\Program Files\\App\"; evil";
        let wanted = Blocklist {
            paths: vec![good.to_string(), bad.to_string()],
            local_ports: vec![],
        };
        let mut enforcer = WindowsEnforcer {
            current,
            runner: None,
        };
        let plan = enforcer.plan(&wanted);
        assert_eq!(plan.add, vec![good.to_string()]);
        assert_eq!(plan.rejected, vec![bad.to_string()]);
        enforcer
            .apply(&plan)
            .expect("an invalid path must not fail the whole plan");
        assert_eq!(
            enforcer.current.paths,
            vec![good.to_string()],
            "only the valid path is claimed into current"
        );
    }

    #[test]
    fn test_windows_plan_performance_budget() {
        // plan() validates (and canonicalizes) every path, so
        // the budget must hold WITH that cost, on host-valid absolute paths.
        let prefix = if cfg!(windows) {
            r"C:\Apps\Perf"
        } else {
            "/usr/bin/perf"
        };
        let mut current_paths = Vec::new();
        let mut wanted_paths = Vec::new();
        for i in 0..5000 {
            current_paths.push(format!("{prefix}_old_{}", i));
        }
        for i in 2500..7500 {
            wanted_paths.push(format!("{prefix}_new_{}", i));
        }

        let current = Blocklist {
            paths: current_paths,
            local_ports: vec![],
        };
        let wanted = Blocklist {
            paths: wanted_paths,
            local_ports: vec![],
        };

        let enforcer = WindowsEnforcer {
            current,
            runner: None,
        };

        let start = Instant::now();
        let plan = enforcer.plan(&wanted);
        let duration = start.elapsed();

        // Budget for a 5000-path diff. Since v1 the plan canonicalises
        // every wanted path once (one filesystem call each, ~30 us on Windows,
        // measured ~150 ms here in a debug build), so the old 50 ms no-I/O
        // budget no longer applies; real rule sets hold tens of paths.
        assert!(
            duration.as_millis() < 500,
            "5000-path plan took {duration:?} (debug build, loaded-host flake possible)"
        );

        // Memory usage bounds (string array pointers should be small, actual allocations too).
        assert!(plan.add.capacity() * std::mem::size_of::<String>() < 20_000_000);
        assert!(plan.remove.capacity() * std::mem::size_of::<String>() < 20_000_000);
    }

    proptest! {
        #[test]
        fn proptest_windows_plan_no_panic(
            current_paths in prop::collection::vec(".*", 0..100),
            wanted_paths in prop::collection::vec(".*", 0..100)
        ) {
            let current = Blocklist {
                paths: current_paths,
                local_ports: vec![],
            };
            let wanted = Blocklist {
                paths: wanted_paths,
                local_ports: vec![],
            };

            let enforcer = WindowsEnforcer { current, runner: None };
            let _ = enforcer.plan(&wanted);
        }

        #[test]
        fn proptest_windows_plan_order_independent(
            wanted_paths in prop::collection::vec(".*", 0..100)
        ) {
            let current = Blocklist {
                paths: vec![],
                local_ports: vec![],
            };
            let enforcer = WindowsEnforcer { current, runner: None };

            let wanted1 = Blocklist {
                paths: wanted_paths.clone(),
                local_ports: vec![],
            };
            let plan1 = enforcer.plan(&wanted1);

            let mut reversed_paths = wanted_paths.clone();
            reversed_paths.reverse();
            let wanted2 = Blocklist {
                paths: reversed_paths,
                local_ports: vec![],
            };
            let plan2 = enforcer.plan(&wanted2);

            assert_eq!(plan1, plan2);
        }

        #[test]
        fn proptest_format_rule_name(path in ".*") {
            let name = format_rule_name(&path);
            assert!(name.starts_with("Rat:path:"));
            assert!(name.ends_with(&path));
        }
    }

    // apply() twice must leave the live rule count at the plan
    // size. Real netsh cannot run in tests, so these inject a runner that
    // models its actual duplicate-on-add semantics.
    #[cfg(windows)]
    mod apply_twice {
        use super::*;
        use std::collections::HashMap;
        use std::path::Path;
        use std::sync::{Arc, Mutex};

        /// Stands in for netsh.exe with its REAL semantics: `add rule name=N`
        /// on an existing N adds a DUPLICATE;
        /// `delete rule name=N` removes every N, or exits nonzero when none
        /// match ("No rules match the specified criteria"); `show rule name=N`
        /// is read-only and exits 0 iff a rule named N exists.
        struct FakeNetsh {
            rules: Mutex<HashMap<String, usize>>,
        }

        impl FakeNetsh {
            fn run(&self, exe: &Path, args: &[String]) -> io::Result<bool> {
                assert!(exe.ends_with("netsh.exe"), "unexpected exe {exe:?}");
                let mut verb = "";
                let mut name = None;
                for a in args {
                    match a.as_str() {
                        "add" | "delete" | "show" => verb = a,
                        "rule" => {}
                        other => {
                            if let Some(n) = other.strip_prefix("name=") {
                                name = Some(n.to_string());
                            }
                        }
                    }
                }
                let name = name.expect("netsh rule command carries name=");
                let mut rules = self.rules.lock().unwrap();
                if verb == "add" {
                    *rules.entry(name).or_insert(0) += 1;
                    Ok(true)
                } else if verb == "show" {
                    Ok(rules.contains_key(&name))
                } else {
                    Ok(rules.remove(&name).is_some())
                }
            }

            fn count(&self, name: &str) -> usize {
                self.rules.lock().unwrap().get(name).copied().unwrap_or(0)
            }
        }

        fn runner(fake: Arc<FakeNetsh>) -> NetshRunner {
            Arc::new(move |exe: &Path, args: &[String]| fake.run(exe, args))
        }

        fn wanted() -> Blocklist {
            Blocklist {
                paths: vec![r"C:\Apps\Denied\app.exe".to_string()],
                local_ports: vec![5353],
            }
        }

        const APP: &str = r"C:\Apps\Denied\app.exe";

        #[test]
        fn test_windows_apply_twice_live_count_equals_plan_size() {
            // One plan's worth of firewall rules: 1 per-program rule + 4
            // per-port variants (out/in x TCP/UDP).
            let fake = Arc::new(FakeNetsh {
                rules: Mutex::new(HashMap::new()),
            });
            let mut enforcer = WindowsEnforcer {
                current: Blocklist::default(),
                runner: Some(runner(Arc::clone(&fake))),
            };

            let plan1 = enforcer.plan(&wanted());
            enforcer.apply(&plan1).expect("first apply");
            assert_eq!(
                fake.count(&format_rule_name(APP)),
                1,
                "one live path rule after the first apply"
            );
            assert_eq!(
                fake.count(&format_port_rule_name(5353)),
                4,
                "four live port rules after the first apply"
            );

            // Part 1: apply must advance `current`, so planning the same
            // wanted state again is empty — and the second apply cannot touch
            // the firewall. (Pre-fix, `current` stayed empty and the plan was
            // identical, so netsh added every rule a second time.)
            let plan2 = enforcer.plan(&wanted());
            assert!(
                plan2.add.is_empty()
                    && plan2.remove.is_empty()
                    && plan2.add_ports.is_empty()
                    && plan2.remove_ports.is_empty(),
                "current must advance on apply, got {plan2:?}"
            );
            enforcer.apply(&plan2).expect("second apply");
            assert_eq!(
                fake.count(&format_rule_name(APP)),
                1,
                "apply twice -> live rule count == plan size (path)"
            );
            assert_eq!(
                fake.count(&format_port_rule_name(5353)),
                4,
                "apply twice -> live rule count == plan size (port)"
            );
        }

        #[test]
        fn test_windows_apply_fresh_enforcer_never_duplicates() {
            // Part 2: a NEW enforcer (restart; read-back failed so
            // `current` is empty again) re-plans the same wanted state. netsh
            // add duplicates on an existing name, so apply deletes any
            // same-name rule before adding: the live count stays at the plan
            // size even when the diff is stale.
            let fake = Arc::new(FakeNetsh {
                rules: Mutex::new(HashMap::new()),
            });
            let mut first = WindowsEnforcer {
                current: Blocklist::default(),
                runner: Some(runner(Arc::clone(&fake))),
            };
            let plan = first.plan(&wanted());
            first.apply(&plan).expect("first enforcer apply");
            assert_eq!(fake.count(&format_rule_name(APP)), 1);
            assert_eq!(fake.count(&format_port_rule_name(5353)), 4);

            let mut second = WindowsEnforcer {
                current: Blocklist::default(),
                runner: Some(runner(Arc::clone(&fake))),
            };
            let plan2 = second.plan(&wanted());
            second.apply(&plan2).expect("second enforcer apply");
            assert_eq!(
                fake.count(&format_rule_name(APP)),
                1,
                "a stale diff re-apply must dedupe, not duplicate (path)"
            );
            assert_eq!(
                fake.count(&format_port_rule_name(5353)),
                4,
                "a stale diff re-apply must dedupe, not duplicate (port)"
            );
            // The fresh enforcer now holds the state, too.
            assert!(second.plan(&wanted()).add.is_empty());
        }

        // `delete rule name=N` on an ALREADY-GONE rule (the
        // user or GPO removed it behind the daemon's back) exits 1 with "No
        // rules match the specified criteria". That is success for a
        // reconcile delete — the rule's desired state is already reached —
        // and the rest of the plan must still be applied. Both delete sites
        // (path and port) get their own test.
        #[test]
        fn test_windows_apply_survives_pre_deleted_path_rule() {
            let fake = Arc::new(FakeNetsh {
                rules: Mutex::new(HashMap::new()),
            });
            let gone = r"C:\Apps\Old\gone.exe";
            let mut enforcer = WindowsEnforcer {
                current: Blocklist {
                    paths: vec![gone.to_string()],
                    local_ports: vec![],
                },
                runner: Some(runner(Arc::clone(&fake))),
            };
            let wanted = Blocklist {
                paths: vec![APP.to_string()],
                local_ports: vec![],
            };
            let plan = enforcer.plan(&wanted);
            assert_eq!(plan.remove, vec![gone.to_string()]);

            enforcer
                .apply(&plan)
                .expect("a no-match delete must not abort the plan");
            assert_eq!(
                fake.count(&format_rule_name(APP)),
                1,
                "the rest of the plan (the new block) is applied after the no-match delete"
            );
            // The verified-gone rule leaves `current` too, so the next diff
            // does not retry the delete forever.
            assert!(
                enforcer.plan(&wanted).remove.is_empty(),
                "current must advance past a no-match delete"
            );
        }

        #[test]
        fn test_windows_apply_survives_pre_deleted_port_rule() {
            // The per-port delete site has the same
            // !success() -> Err pattern and the same tolerance.
            let fake = Arc::new(FakeNetsh {
                rules: Mutex::new(HashMap::new()),
            });
            let mut enforcer = WindowsEnforcer {
                current: Blocklist {
                    paths: vec![],
                    local_ports: vec![5353],
                },
                runner: Some(runner(Arc::clone(&fake))),
            };
            let wanted = Blocklist {
                paths: vec![],
                local_ports: vec![5300],
            };
            let plan = enforcer.plan(&wanted);
            assert_eq!(plan.remove_ports, vec![5353]);

            enforcer
                .apply(&plan)
                .expect("a no-match port delete must not abort the plan");
            assert_eq!(
                fake.count(&format_port_rule_name(5300)),
                4,
                "the rest of the plan (the new port) is applied after the no-match delete"
            );
            assert!(
                enforcer.plan(&wanted).remove_ports.is_empty(),
                "current must advance past a no-match port delete"
            );
        }

        // a hand-built plan (the daemon never builds one — this
        // is apply()'s own defense) with ONE invalid entry must not abort the
        // whole plan either: the invalid entry is skipped (no rule is created
        // from or deleted by an unvalidated string),
        // never claimed into `current`, and the rest applies. Both validated()
        // call sites (add and remove axis) get their own test.
        #[test]
        fn test_windows_apply_skips_hand_built_invalid_add() {
            let fake = Arc::new(FakeNetsh {
                rules: Mutex::new(HashMap::new()),
            });
            let bad = r#"C:\Users\bad"; app.exe"#;
            let mut enforcer = WindowsEnforcer {
                current: Blocklist::default(),
                runner: Some(runner(Arc::clone(&fake))),
            };
            let plan = WindowsPlan {
                add: vec![bad.to_string(), APP.to_string()],
                remove: vec![],
                add_ports: vec![],
                remove_ports: vec![],
                refused: vec![],
                rejected: vec![],
            };
            enforcer
                .apply(&plan)
                .expect("an invalid add must not fail the whole plan");
            assert_eq!(
                fake.count(&format_rule_name(APP)),
                1,
                "the rest of the plan (the valid block) is applied"
            );
            assert_eq!(
                fake.count(&format_rule_name(bad)),
                0,
                "no rule is ever created for an unvalidated path"
            );
            assert_eq!(
                enforcer.current.paths,
                vec![APP.to_string()],
                "the skipped entry is never claimed into current"
            );
        }

        #[test]
        fn test_windows_apply_skips_hand_built_invalid_remove() {
            let fake = Arc::new(FakeNetsh {
                rules: Mutex::new(HashMap::new()),
            });
            let bad = r#"C:\Users\bad"; app.exe"#;
            let gone = r"C:\Apps\Old\gone.exe";
            let shared = Arc::clone(&fake);
            let mut enforcer = WindowsEnforcer {
                current: Blocklist {
                    paths: vec![gone.to_string(), bad.to_string()],
                    local_ports: vec![],
                },
                runner: Some(Arc::new(move |exe: &Path, args: &[String]| {
                    if args.iter().any(|a| a.contains("bad")) {
                        // If apply ever built a delete from the unvalidated
                        // name, this Err would abort the plan (earlier shape).
                        return Err(io::Error::other("delete attempted on unvalidated name"));
                    }
                    shared.run(exe, args)
                })),
            };
            let plan = WindowsPlan {
                add: vec![],
                remove: vec![bad.to_string(), gone.to_string()],
                add_ports: vec![],
                remove_ports: vec![],
                refused: vec![],
                rejected: vec![],
            };
            enforcer
                .apply(&plan)
                .expect("an invalid remove must not fail the whole plan");
            // The valid stale entry was deleted (no-match is tolerated);
            // the invalid name was never touched.
            assert_eq!(fake.count(&format_rule_name(gone)), 0);
            assert!(
                enforcer.current.paths.contains(&bad.to_string()),
                "the skipped remove is never claimed out of current"
            );
        }

        #[test]
        fn test_windows_apply_real_delete_failure_still_aborts() {
            // the tolerance is only for the no-match exit: a real delete
            // failure (seam Err) still fails the apply, so `current` stays
            // behind and the next diff retries — nothing else is applied.
            let fake = Arc::new(FakeNetsh {
                rules: Mutex::new(HashMap::new()),
            });
            let shared = Arc::clone(&fake);
            let mut enforcer = WindowsEnforcer {
                current: Blocklist {
                    paths: vec![r"C:\Apps\Old\stuck.exe".to_string()],
                    local_ports: vec![],
                },
                runner: Some(Arc::new(move |exe: &Path, args: &[String]| {
                    if args.iter().any(|a| a == "delete") {
                        return Err(io::Error::other("access denied"));
                    }
                    shared.run(exe, args)
                })),
            };
            let wanted = Blocklist {
                paths: vec![APP.to_string()],
                local_ports: vec![],
            };
            let plan = enforcer.plan(&wanted);

            let err = enforcer.apply(&plan).unwrap_err();
            assert!(
                err.to_string().contains("access denied"),
                "unexpected error: {err}"
            );
            assert_eq!(
                fake.count(&format_rule_name(APP)),
                0,
                "a real delete failure aborts before any add runs"
            );
        }

        // the already-gone decision must never depend on the
        // message TEXT (the old English-only "no rules match" grep fails
        // open on a localized Windows: every tick errors, `current` never
        // advances, no new block is ever applied). The decision is by EXIT
        // CODES: after a non-zero delete, probe `show rule name=<n>` — show
        // failing = rule absent = tolerate, show succeeding = rule still
        // there = real error. LocalizedNetsh models a Persian-language
        // netsh: its delete ALWAYS exits 1 (message text invisible to the
        // seam, as to production), and it logs every command so the tests
        // can pin that the decision went through the probe.
        struct LocalizedNetsh {
            rules: Mutex<HashMap<String, usize>>,
            seen: Mutex<Vec<String>>,
        }

        impl LocalizedNetsh {
            fn run(&self, exe: &Path, args: &[String]) -> io::Result<bool> {
                assert!(exe.ends_with("netsh.exe"), "unexpected exe {exe:?}");
                let mut verb = "";
                let mut name = None;
                for a in args {
                    match a.as_str() {
                        "add" | "delete" | "show" => verb = a,
                        "rule" => {}
                        other => {
                            if let Some(n) = other.strip_prefix("name=") {
                                name = Some(n.to_string());
                            }
                        }
                    }
                }
                let name = name.expect("netsh rule command carries name=");
                self.seen.lock().unwrap().push(format!("{verb} {}", name));
                let mut rules = self.rules.lock().unwrap();
                match verb {
                    "add" => {
                        *rules.entry(name).or_insert(0) += 1;
                        Ok(true)
                    }
                    "show" => Ok(rules.contains_key(&name)),
                    // Localized delete: exit 1 no matter what, text unknown.
                    _ => Ok(false),
                }
            }

            fn count(&self, name: &str) -> usize {
                self.rules.lock().unwrap().get(name).copied().unwrap_or(0)
            }
        }

        fn localized_runner(fake: Arc<LocalizedNetsh>) -> NetshRunner {
            Arc::new(move |exe: &Path, args: &[String]| fake.run(exe, args))
        }

        #[test]
        fn test_windows_apply_localized_no_match_delete_probes_show_and_tolerates() {
            // The user removed the rule behind the daemon's back; netsh is
            // localized, so the delete exits 1 with an unreadable message.
            // The show probe for the exact gone-rule name also exits nonzero
            // (absent) -> tolerated, the rest of the plan still applies, and
            // `current` advances.
            let fake = Arc::new(LocalizedNetsh {
                rules: Mutex::new(HashMap::new()),
                seen: Mutex::new(Vec::new()),
            });
            let gone = r"C:\Apps\Old\gone.exe";
            let mut enforcer = WindowsEnforcer {
                current: Blocklist {
                    paths: vec![gone.to_string()],
                    local_ports: vec![],
                },
                runner: Some(localized_runner(Arc::clone(&fake))),
            };
            let wanted = Blocklist {
                paths: vec![APP.to_string()],
                local_ports: vec![],
            };
            let plan = enforcer.plan(&wanted);
            assert_eq!(plan.remove, vec![gone.to_string()]);

            enforcer
                .apply(&plan)
                .expect("a localized no-match delete must be tolerated");
            assert_eq!(
                fake.count(&format_rule_name(APP)),
                1,
                "the rest of the plan (the new block) is applied after the localized no-match delete"
            );
            assert!(
                enforcer.plan(&wanted).remove.is_empty(),
                "current must advance past a localized no-match delete"
            );
            // The decision went through the exit-code probe, not blind
            // tolerance (the old code tolerated without probing).
            assert!(
                fake.seen
                    .lock()
                    .unwrap()
                    .contains(&format!("show {}", format_rule_name(gone))),
                "a failed delete must be followed by `show rule name=<n>` for the exact name, saw {:?}",
                fake.seen.lock().unwrap()
            );
        }

        #[test]
        fn test_windows_apply_localized_delete_on_present_rule_aborts() {
            // The rule is still there (seeded, as read back on startup); the
            // localized delete fails for a REAL reason (access denied, in
            // Persian). The show probe finds the rule -> real error, the
            // apply aborts and nothing else runs.
            let fake = Arc::new(LocalizedNetsh {
                rules: Mutex::new(HashMap::from([(
                    format_rule_name(r"C:\Apps\Old\stuck.exe"),
                    1,
                )])),
                seen: Mutex::new(Vec::new()),
            });
            let stuck = r"C:\Apps\Old\stuck.exe";
            let mut enforcer = WindowsEnforcer {
                current: Blocklist {
                    paths: vec![stuck.to_string()],
                    local_ports: vec![],
                },
                runner: Some(localized_runner(Arc::clone(&fake))),
            };
            let wanted = Blocklist {
                paths: vec![APP.to_string()],
                local_ports: vec![],
            };
            let plan = enforcer.plan(&wanted);
            assert_eq!(plan.remove, vec![stuck.to_string()]);

            let err = enforcer
                .apply(&plan)
                .expect_err("a delete that left the rule in place is a real error");
            assert!(
                err.to_string().contains("Failed to delete firewall rule"),
                "unexpected error: {err}"
            );
            assert_eq!(
                fake.count(&format_rule_name(stuck)),
                1,
                "the present rule is untouched by the aborted apply"
            );
            assert!(
                !fake
                    .seen
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|cmd| cmd.starts_with("add ")),
                "nothing is applied after a real delete failure, saw {:?}",
                fake.seen.lock().unwrap()
            );
        }
    }
}
