use std::env;
use std::io;
use std::process::Command;

use crate::{Blocklist, Enforcer};

pub struct LinuxEnforcer;

impl Enforcer for LinuxEnforcer {
    type Plan = String;

    fn plan(&self, wanted: &Blocklist) -> Self::Plan {
        let mut ports = wanted.local_ports.clone();
        ports.sort();
        ports.dedup();

        let ports_str = if ports.is_empty() {
            "".to_string()
        } else {
            let p: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
            format!("elements = {{ {} }}\n\t\t", p.join(", "))
        };

        format!(
            "add table inet rat\n\
             flush table inet rat\n\
             table inet rat {{\n\
                 \tset rat_ports {{\n\
                     \t\ttype inet_service\n\
                     \t\t{}\
                 }}\n\
                 \tchain drop_out {{\n\
                     \t\ttype filter hook output priority filter; policy accept;\n\
                     \t\ttcp sport @rat_ports drop\n\
                     \t\tudp sport @rat_ports drop\n\
                 \t}}\n\
                 \tchain drop_in {{\n\
                     \t\ttype filter hook input priority filter; policy accept;\n\
                     \t\ttcp dport @rat_ports drop\n\
                     \t\tudp dport @rat_ports drop\n\
                 \t}}\n\
             }}\n",
            ports_str
        )
    }

    fn apply(&self, plan: &Self::Plan) -> io::Result<()> {
        let dry_run = env::var("RAT_ENFORCE").map(|v| v != "1").unwrap_or(true);

        if dry_run {
            println!("nft -f - <<EOF\n{}EOF", plan);
            Ok(())
        } else {
            let mut child = Command::new("nft")
                .arg("-f")
                .arg("-")
                .stdin(std::process::Stdio::piped())
                .spawn()?;

            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(plan.as_bytes())?;
            }

            let status = child.wait()?;
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
    use proptest::prelude::*;
    use std::time::Instant;

    #[test]
    fn test_linux_plan_empty() {
        let enforcer = LinuxEnforcer;
        let plan = enforcer.plan(&Blocklist::default());
        assert!(plan.contains("add table inet rat"));
        assert!(plan.contains("flush table inet rat"));
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
