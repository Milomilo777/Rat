//! W3 Per-app isolation: two different executables, deny A only.
use crate::common::*;
use rat_enforcer::windows::WindowsEnforcer;
use rat_enforcer::{Blocklist, Enforcer};

struct Guard(Vec<std::path::PathBuf>);
impl Drop for Guard {
    fn drop(&mut self) {
        remove_rat_rules();
        for p in &self.0 {
            let _ = std::fs::remove_file(p);
        }
    }
}

pub fn run(r: &mut Report) {
    let exe = std::env::current_exe().unwrap();
    let a = exe.with_file_name("w3_a.exe");
    let b = exe.with_file_name("w3_b.exe");
    std::fs::copy(&exe, &a).unwrap();
    std::fs::copy(&exe, &b).unwrap();
    let _g = Guard(vec![a.clone(), b.clone()]);

    if probe_until(&a, HTTPS_URL, true, 3) != Some(true) || probe_until(&b, HTTPS_URL, true, 3) != Some(true) {
        return r.not_run("baseline", "HTTPS host unreachable for A or B before any rule");
    }
    r.pass("baseline", "A and B both reach the host before any rule");

    let mut e = WindowsEnforcer {
        current: Blocklist::default(),
        runner: None,
    };
    let mut wanted = Blocklist::default();
    wanted.paths.push(a.to_string_lossy().to_string());
    let plan = e.plan(&wanted);
    if let Err(err) = e.apply(&plan) {
        return r.product("apply", format!("apply error: {err}"));
    }

    match rat_rules() {
        // A5: the out + in pair for A and no other Rat rule
        Ok(v) => match check_block_pair(&v, &a.to_string_lossy()) {
            Ok(what) => r.pass("rule-only-for-A", format!("{what} -> {}", v[0].program)),
            Err(why) => r.product("rule-only-for-A", why),
        },
        Err(x) => r.harness("rule-only-for-A", x),
    }

    match probe_until(&a, HTTPS_URL, false, 4) {
        Some(false) => r.pass("A-blocked", "A fails while B baseline succeeded"),
        other => r.product("A-blocked", format!("A not blocked: {other:?}")),
    }
    match probe_until(&b, HTTPS_URL, true, 3) {
        Some(true) => r.pass("B-works", "B (different path) still reaches the host"),
        other => r.product("B-works", format!("B was affected by A's rule: {other:?}")),
    }

    if let Err(err) = e.cleanup() {
        r.product("cleanup", format!("{err}"));
    }
    match probe_until(&a, HTTPS_URL, true, 5) {
        Some(true) => r.pass("control-A-unblocked", "A works again after cleanup"),
        other => r.product("control-A-unblocked", format!("A still blocked after cleanup: {other:?}")),
    }
}
