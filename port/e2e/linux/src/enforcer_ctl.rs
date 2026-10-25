//! Drives `rat_enforcer::linux::LinuxEnforcer` directly.
//!   enforcer-ctl apply [PORT...]   plan + apply a deny set of local ports
//!   enforcer-ctl cleanup           remove the `inet rat` table
//! Honours RAT_DRY_RUN exactly like the product (the enforcer reads it).
use rat_enforcer::linux::LinuxEnforcer;
use rat_enforcer::{Blocklist, Enforcer};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut enforcer = LinuxEnforcer;
    match args.get(1).map(|s| s.as_str()) {
        Some("apply") => {
            let mut ports = Vec::new();
            for a in &args[2..] {
                match a.parse::<u16>() {
                    Ok(p) => ports.push(p),
                    Err(_) => {
                        eprintln!("bad port {}", a);
                        std::process::exit(64);
                    }
                }
            }
            let wanted = Blocklist {
                paths: vec![],
                local_ports: ports,
            };
            let plan = enforcer.plan(&wanted);
            if let Err(e) = enforcer.apply(&plan) {
                eprintln!("apply failed: {}", e);
                std::process::exit(1);
            }
            println!("APPLIED");
        }
        Some("cleanup") => {
            if let Err(e) = enforcer.cleanup() {
                eprintln!("cleanup failed: {}", e);
                std::process::exit(1);
            }
            println!("CLEANED");
        }
        _ => {
            eprintln!("usage: enforcer-ctl apply [PORT...] | cleanup");
            std::process::exit(64);
        }
    }
}
