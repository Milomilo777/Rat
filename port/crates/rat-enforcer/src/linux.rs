use std::env;
use std::io;
use std::process::Command;

use crate::{Blocklist, Enforcer};

pub struct LinuxEnforcer;

/// resolve nft from its known absolute locations instead of
/// PATH / the working directory, so a tampered PATH cannot substitute the
/// binary the privileged daemon shells out to.
pub fn nft_path() -> io::Result<std::path::PathBuf> {
    for candidate in ["/usr/sbin/nft", "/sbin/nft"] {
        let path = std::path::PathBuf::from(candidate);
        if path.is_file() {
            return Ok(path);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "nft not found in /usr/sbin or /sbin",
    ))
}

impl Enforcer for LinuxEnforcer {
    type Plan = String;

    fn plan(&self, wanted: &Blocklist) -> Self::Plan {
        crate::nft_plan::nft_script(&wanted.local_ports)
    }

    /// drop the whole `inet rat` table on clean shutdown
    /// (systemd's ExecStopPost runs the same command after any exit).
    fn cleanup(&self) -> io::Result<()> {
        let dry_run = crate::dry_run_enabled(env::var("RAT_DRY_RUN").ok().as_deref());
        if dry_run {
            println!("nft delete table inet rat");
            return Ok(());
        }

        let status = Command::new(nft_path()?)
            .args(["delete", "table", "inet", "rat"])
            .status()?;
        if !status.success() {
            return Err(io::Error::other("failed to delete nft table inet rat"));
        }
        Ok(())
    }

    fn apply(&mut self, plan: &Self::Plan) -> io::Result<()> {
        let dry_run = crate::dry_run_enabled(env::var("RAT_DRY_RUN").ok().as_deref());

        if dry_run {
            println!("nft -f - <<EOF\n{}EOF", plan);
            Ok(())
        } else {
            let mut child = Command::new(nft_path()?)
                .arg("-f")
                .arg("-")
                .stdin(std::process::Stdio::piped())
                .spawn()?;

            use std::io::Write;
            // remember the write result but ALWAYS reap the
            // child, so a failed write cannot leave a zombie behind.
            let mut write_result = Ok(());
            if let Some(mut stdin) = child.stdin.take() {
                write_result = stdin.write_all(plan.as_bytes());
            }

            let status = child.wait()?;
            write_result?;
            if !status.success() {
                return Err(io::Error::other("nftables command failed"));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nft_resolved_absolute_when_present() {
        // Consistency: if either known location holds nft, it is returned;
        // otherwise the lookup fails instead of falling back to PATH.
        let present = ["/usr/sbin/nft", "/sbin/nft"]
            .iter()
            .find(|c| std::path::Path::new(c).is_file());
        match (present, nft_path()) {
            (Some(found), Ok(p)) => {
                assert!(p.is_absolute());
                assert_eq!(&p.to_string_lossy(), found);
            }
            (None, Err(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            (Some(_), Err(e)) => panic!("nft present but lookup failed: {e}"),
            (None, Ok(p)) => panic!("nft not present but lookup returned {p:?}"),
        }
    }
    use proptest::prelude::*;
    use std::time::Instant;

    #[test]
    fn test_linux_plan_empty() {
        let enforcer = LinuxEnforcer;
        let plan = enforcer.plan(&Blocklist::default());
        assert!(plan.contains("add table inet rat"));
        // `flush table` kept old set elements (CI bug), so the plan must
        // delete the table instead; the old expectation encoded the bug.
        assert!(!plan.contains("flush table"));
        assert!(plan.contains("delete table inet rat"));
        assert!(plan.contains("set rat_ports {"));
        assert!(!plan.contains("elements = {")); // Should be empty
    }

    #[test]
    fn test_linux_plan_with_ports() {
        let enforcer = LinuxEnforcer;
        let wanted = Blocklist {
            paths: vec![],
            local_ports: vec![8080, 443],
        };
        let plan = enforcer.plan(&wanted);
        assert!(plan.contains("elements = { 443, 8080 }"));
    }

    #[test]
    fn test_linux_plan_performance_budget() {
        let mut ports = Vec::new();
        for i in 0..5000 {
            ports.push(i as u16);
        }
        let wanted = Blocklist {
            paths: vec![],
            local_ports: ports,
        };
        let enforcer = LinuxEnforcer;

        let start = Instant::now();
        let plan = enforcer.plan(&wanted);
        let duration = start.elapsed();

        // Check if plan generation with 5000 rules takes less than 50ms
        // It takes around 300us, so 50ms is very safe.
        assert!(duration.as_millis() < 50);

        // Verify the plan size matches our expectations
        // 5000 elements * ~5 bytes per element = ~25KB
        // Should use under 20MB easily.
        assert!(plan.len() < 20_000_000);
    }

    proptest! {
        #[test]
        fn proptest_linux_plan_no_panic(local_ports in prop::collection::vec(0u16..=65535, 0..100)) {
            let enforcer = LinuxEnforcer;
            let wanted = Blocklist {
                paths: vec![],
                local_ports,
            };
            let _ = enforcer.plan(&wanted);
        }

        #[test]
        fn proptest_linux_plan_order_independent(local_ports in prop::collection::vec(0u16..=65535, 0..100)) {
            let enforcer = LinuxEnforcer;

            let wanted1 = Blocklist {
                paths: vec![],
                local_ports: local_ports.clone(),
            };
            let plan1 = enforcer.plan(&wanted1);

            let mut reversed_ports = local_ports.clone();
            reversed_ports.reverse();
            let wanted2 = Blocklist {
                paths: vec![],
                local_ports: reversed_ports,
            };
            let plan2 = enforcer.plan(&wanted2);

            assert_eq!(plan1, plan2);
        }
    }
}
