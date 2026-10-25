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
}

pub fn generate_windows_plan(current: &Blocklist, wanted: &Blocklist) -> WindowsPlan {
    // Avoid O(n^2) nested loops by converting one list to a HashSet, giving O(n) average time complexity.
    let current_set: HashSet<&String> = current.paths.iter().collect();
    let wanted_set: HashSet<&String> = wanted.paths.iter().collect();

    let mut add = Vec::new();
    for path in &wanted.paths {
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

    // Sort to make plan output deterministic
    add.sort();
    remove.sort();

    WindowsPlan { add, remove }
}

pub fn format_rule_name(path: &str) -> String {
    format!("Rat:path:{}", path)
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

        let dry_run = env::var("RAT_ENFORCE").map(|v| v != "1").unwrap_or(true);

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

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(duration.as_millis() < 50);

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
