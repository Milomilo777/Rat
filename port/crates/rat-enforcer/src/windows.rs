use std::collections::HashSet;
use std::io;

use crate::{Blocklist, Enforcer};

pub struct WindowsEnforcer {
    pub current: Blocklist,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsPlan {
    pub add: Vec<String>,
    pub remove: Vec<String>,
    /// review-01 R5: denied LOCAL ports to add as per-port rules — the
    /// Windows mirror of the Linux backend's `rat_ports` nft set and the
    /// macOS Ledger's local-port blocks (Ledger.swift:330-332). This is also
    /// what a refused shared host's denied socket gets instead of a silent
    /// no-op ("block by port instead").
    pub add_ports: Vec<u16>,
    pub remove_ports: Vec<u16>,
    /// W2 (PROPOSALS #1): wanted whole-program blocks that were REFUSED
    /// because the target is a shared service host (svchost.exe hosts DNS,
    /// DHCP and more for the whole machine). The caller decides how to tell
    /// the user; per-port rules below still apply.
    pub refused: Vec<String>,
}

pub fn generate_windows_plan(current: &Blocklist, wanted: &Blocklist) -> WindowsPlan {
    // Avoid O(n^2) nested loops by converting one list to a HashSet, giving O(n) average time complexity.
    let current_set: HashSet<&String> = current.paths.iter().collect();
    let wanted_set: HashSet<&String> = wanted.paths.iter().collect();

    let mut add = Vec::new();
    let mut refused = Vec::new();
    for path in &wanted.paths {
        if crate::is_shared_service_host(path) {
            // W2: never block a shared service host per-program.
            if !refused.contains(path) {
                refused.push(path.clone());
            }
            continue;
        }
        if !current_set.contains(path) {
            add.push(path.clone());
        }
    }

    let mut remove = Vec::new();
    for path in &current.paths {
        if !wanted_set.contains(path) {
            remove.push(path.clone());
        }
    }

    // review-01 R5: the port axis diffs like the path axis. Local ports are
    // ephemeral, so their churn (denied socket opens/closes) is expected —
    // the ledger's plan drops a closed socket's port from the wanted set and
    // the diff removes the rule (PROPOSALS #3, Linux parity).
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
    remove.sort();
    refused.sort();
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
    }
}

pub fn format_rule_name(path: &str) -> String {
    format!("Rat:path:{}", path)
}

/// review-01 R5: per-port rules share one name per port so the delete path
/// removes every variant at once.
pub fn format_port_rule_name(port: u16) -> String {
    format!("Rat:port:{}", port)
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

/// S5 (update-08): resolve netsh from %SystemRoot% instead of PATH / the
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

/// S5 (update-08): resolve powershell from %SystemRoot% for the wildcard
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
    fn apply(&self, _plan: &Self::Plan) -> io::Result<()> {
        // Only for compiling tests on Linux
        Ok(())
    }

    #[cfg(windows)]
    fn apply(&self, plan: &Self::Plan) -> io::Result<()> {
        use std::env;
        use std::process::Command;

        // S6 (update-08): validate AND canonicalize every path before use,
        // so rule names and program= targets always name the real binary.
        let validated = |paths: &[String]| -> io::Result<Vec<String>> {
            paths
                .iter()
                .map(|p| crate::validate_path(p).map_err(io::Error::other))
                .collect()
        };
        let remove = validated(&plan.remove)?;
        let add = validated(&plan.add)?;

        // W2 (PROPOSALS #1): plan() already refuses shared service hosts; a
        // hand-built plan must not be able to smuggle one through — fail
        // closed, also in dry-run.
        if let Some(path) = add.iter().find(|p| crate::is_shared_service_host(p)) {
            return Err(io::Error::other(format!(
                "refusing whole-program block of shared service host {path} (would cut DNS/DHCP machine-wide); block by port instead"
            )));
        }

        let dry_run = crate::dry_run_enabled(env::var("RAT_DRY_RUN").ok().as_deref());

        for path in &remove {
            let name = format_rule_name(path);
            if dry_run {
                println!("netsh advfirewall firewall delete rule name=\"{}\"", name);
            } else {
                let status = Command::new(netsh_path()?)
                    .args([
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        &format!("name={}", name),
                    ])
                    .status()?;
                if !status.success() {
                    return Err(io::Error::other("Failed to delete firewall rule"));
                }
            }
        }

        for path in &add {
            let name = format_rule_name(path);
            if dry_run {
                println!(
                    "netsh advfirewall firewall add rule name=\"{}\" dir=out action=block program=\"{}\"",
                    name, path
                );
            } else {
                let args = vec![
                    "advfirewall".to_string(),
                    "firewall".to_string(),
                    "add".to_string(),
                    "rule".to_string(),
                    format!("name={}", name),
                    "dir=out".to_string(),
                    "action=block".to_string(),
                    format!("program={}", path),
                ];

                let status = Command::new(netsh_path()?).args(&args).status()?;

                if !status.success() {
                    return Err(io::Error::other("Failed to add firewall rule"));
                }
            }
        }

        // review-01 R5: the port axis. One delete per port (removes all four
        // variants), four adds per new port (out/in x TCP/UDP).
        for port in &plan.remove_ports {
            if dry_run {
                println!(
                    "netsh advfirewall firewall delete rule name=\"{}\"",
                    format_port_rule_name(*port)
                );
            } else {
                let status = Command::new(netsh_path()?)
                    .args(port_delete_args(*port))
                    .status()?;
                if !status.success() {
                    return Err(io::Error::other(format!(
                        "Failed to delete firewall port rule {port}"
                    )));
                }
            }
        }

        for port in &plan.add_ports {
            for (dir, proto) in [("out", "TCP"), ("out", "UDP"), ("in", "TCP"), ("in", "UDP")] {
                if dry_run {
                    println!(
                        "netsh advfirewall firewall add rule name=\"{}\" dir={dir} action=block protocol={proto} localport={port}",
                        format_port_rule_name(*port)
                    );
                } else {
                    let status = Command::new(netsh_path()?)
                        .args(port_rule_args(*port, dir, proto))
                        .status()?;
                    if !status.success() {
                        return Err(io::Error::other(format!(
                            "Failed to add firewall port rule {port} dir={dir} protocol={proto}"
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// S8 (update-08): netsh cannot delete by name pattern, so the wildcard
    /// cleanup goes through PowerShell's NetSecurity module.
    fn cleanup(&self) -> io::Result<()> {
        use std::env;
        use std::process::Command;

        let dry_run = crate::dry_run_enabled(env::var("RAT_DRY_RUN").ok().as_deref());
        if dry_run {
            println!("powershell: {CLEANUP_RULES_QUERY}");
            return Ok(());
        }

        let status = Command::new(powershell_path()?)
            .args(["-NoProfile", "-Command", CLEANUP_RULES_QUERY])
            .status()?;
        if !status.success() {
            return Err(io::Error::other("Failed to clean up Rat firewall rules"));
        }
        Ok(())
    }
}

/// review-01 R5: the wildcard cleanup must remove BOTH rule families this
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
        // S7+S8: with the dry-run opt-out set, cleanup must not spawn
        // any process (verified by it succeeding instantly offline).
        std::env::set_var("RAT_DRY_RUN", "1");
        let enforcer = WindowsEnforcer {
            current: Blocklist::default(),
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
        let current = Blocklist {
            paths: vec!["/usr/bin/old".to_string()],
            local_ports: vec![],
        };
        let wanted = Blocklist {
            paths: vec!["/usr/bin/new".to_string()],
            local_ports: vec![],
        };

        let enforcer = WindowsEnforcer { current };
        let plan = enforcer.plan(&wanted);

        assert_eq!(plan.add.len(), 1);
        if let Some(first_add) = plan.add.first() {
            assert_eq!(first_add, "/usr/bin/new");
        }

        assert_eq!(plan.remove.len(), 1);
        if let Some(first_remove) = plan.remove.first() {
            assert_eq!(first_remove, "/usr/bin/old");
        }
    }

    #[test]
    fn test_windows_plan_refuses_shared_service_host() {
        // W2 / PROPOSALS #1: svchost.exe must never become a program= rule;
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
        };
        let plan = enforcer.plan(&wanted);
        assert_eq!(plan.add, vec![r"C:\Apps\Denied\app.exe".to_string()]);
        assert_eq!(
            plan.refused,
            vec![r"C:\Windows\System32\svchost.exe".to_string()]
        );
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
        };
        let enforcer = WindowsEnforcer {
            current: Blocklist::default(),
        };
        let err = enforcer.apply(&plan).unwrap_err();
        assert!(
            err.to_string().contains("shared service host"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_windows_plan_ports_diff() {
        // review-01 R5: the port axis diffs like the path axis, sorted and
        // deduplicated.
        let current = Blocklist {
            paths: vec![],
            local_ports: vec![2, 1],
        };
        let wanted = Blocklist {
            paths: vec![],
            local_ports: vec![3, 2, 2],
        };
        let enforcer = WindowsEnforcer { current };
        let plan = enforcer.plan(&wanted);
        assert_eq!(plan.add_ports, vec![3]);
        assert_eq!(plan.remove_ports, vec![1]);
        assert!(plan.add.is_empty());
        assert!(plan.remove.is_empty());
    }

    #[test]
    fn test_windows_plan_refused_host_keeps_port_axis() {
        // review-01 R5: a refused shared service host must not be a silent
        // no-op — the denied socket's local port still becomes a per-port
        // rule ("block by port instead").
        let svchost = r"C:\Windows\System32\svchost.exe";
        let wanted = Blocklist {
            paths: vec![svchost.to_string()],
            local_ports: vec![5353],
        };
        let enforcer = WindowsEnforcer {
            current: Blocklist::default(),
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
        // review-01 R5: cleanup must remove per-path AND per-port rules.
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
        let enforcer = WindowsEnforcer { current };
        let plan = enforcer.plan(&wanted);
        assert_eq!(plan.add.len(), 1);
        if let Some(first_add) = plan.add.first() {
            assert_eq!(first_add, "C:\\应用");
        }
        assert_eq!(plan.remove.len(), 0);
    }

    #[test]
    fn test_windows_apply_rejects_invalid_path() {
        // S7 (update-08): tests never touch a real firewall.
        std::env::set_var("RAT_DRY_RUN", "1");
        let current = Blocklist::default();
        let wanted = Blocklist {
            paths: vec!["C:\\Program Files\\App\"; evil".to_string()],
            local_ports: vec![],
        };
        let enforcer = WindowsEnforcer { current };
        let plan = enforcer.plan(&wanted);
        // Even in dry-run mode, apply must refuse paths that fail validate_path.
        assert!(enforcer.apply(&plan).is_err());
    }

    #[test]
    fn test_windows_plan_performance_budget() {
        let mut current_paths = Vec::new();
        let mut wanted_paths = Vec::new();
        for i in 0..5000 {
            current_paths.push(format!("/usr/bin/app_{}", i));
        }
        for i in 2500..7500 {
            wanted_paths.push(format!("/usr/bin/app_{}", i));
        }

        let current = Blocklist {
            paths: current_paths,
            local_ports: vec![],
        };
        let wanted = Blocklist {
            paths: wanted_paths,
            local_ports: vec![],
        };

        let enforcer = WindowsEnforcer { current };

        let start = Instant::now();
        let plan = enforcer.plan(&wanted);
        let duration = start.elapsed();

        // Check if plan generation with 5000 rules diff takes less than 50ms
        // Note: Using a HashSet reduces this to ~5ms easily.
        assert!(
            duration.as_millis() < 50,
            "5000-path plan took {duration:?} (debug build, loaded-host flake documented in PROPOSALS #7)"
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

            let enforcer = WindowsEnforcer { current };
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
            let enforcer = WindowsEnforcer { current };

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
}
