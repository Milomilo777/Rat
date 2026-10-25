//! W2 Enforcer real rules: Enforcer::apply creates `Rat:path:*` rules, the
//! denied client is blocked while curl.exe is not, cleanup() removes them,
//! no other rule changes.
use crate::common::*;
use rat_enforcer::windows::WindowsEnforcer;
use rat_enforcer::{Blocklist, Enforcer};
use std::time::Duration;

struct Guard(std::path::PathBuf);
impl Drop for Guard {
    fn drop(&mut self) {
        std::env::remove_var("RAT_DRY_RUN");
        remove_rat_rules();
        let _ = std::fs::remove_file(&self.0);
    }
}

fn enforcer() -> WindowsEnforcer {
    WindowsEnforcer {
        current: Blocklist::default(),
        runner: None,
    }
}

pub fn run(r: &mut Report) {
    let exe = std::env::current_exe().unwrap();
    let client = exe.with_file_name("w2_client.exe");
    std::fs::copy(&exe, &client).unwrap();
    let _g = Guard(client.clone());
    let client_s = client.to_string_lossy().to_string();

    let before = match rule_names() {
        Ok(s) => s,
        Err(e) => return r.harness("snapshot-before", e),
    };
    println!("W2 firewall rules before: {}", before.len());
    if before.iter().any(|n| n.starts_with("Rat:")) {
        return r.harness("snapshot-before", "host already has Rat: rules before the test");
    }

    // Positive controls: the path is not blocked yet.
    match probe_until(&client, HTTPS_URL, true, 3) {
        Some(true) => r.pass("baseline-client", "test client reaches the HTTPS host before any rule"),
        other => return r.not_run("baseline-client", format!("HTTPS host unreachable from the runner ({other:?}); cannot judge blocking")),
    }
    if !system_curl_ok(HTTPS_URL) {
        return r.not_run("baseline-curl", "curl.exe cannot reach the HTTPS host");
    }

    let mut wanted = Blocklist::default();
    wanted.paths.push(client_s.clone());

    // Negative control: dry run must NOT create a rule nor block.
    std::env::set_var("RAT_DRY_RUN", "1");
    let mut dry = enforcer();
    let plan = dry.plan(&wanted);
    let res = dry.apply(&plan);
    std::env::remove_var("RAT_DRY_RUN");
    match (res, rat_rules()) {
        (Ok(()), Ok(rules)) if rules.is_empty() => {
            r.pass("control-dry-run", "RAT_DRY_RUN=1 apply created no Rat: rule")
        }
        (a, b) => return r.harness("control-dry-run", format!("apply={a:?} rules={b:?}")),
    }
    if probe(&client, HTTPS_URL) != Some(true) {
        return r.harness("control-dry-run", "client blocked although nothing was applied");
    }

    // Real apply.
    let mut e = enforcer();
    let plan = e.plan(&wanted);
    println!("W2 plan: {plan:?}");
    if plan.add.len() != 1 || !plan.refused.is_empty() || !plan.rejected.is_empty() {
        return r.product("plan", format!("expected exactly one add and no refusals: {plan:?}"));
    }
    if let Err(err) = e.apply(&plan) {
        return r.product("apply", format!("apply returned error: {err}"));
    }
    let rules = match rat_rules() {
        Ok(v) => v,
        Err(x) => return r.harness("rules-after", x),
    };
    println!("W2 Rat rules after apply: {rules:#?}");
    let ours: Vec<_> = rules
        .iter()
        .filter(|x| x.name.starts_with("Rat:path:") && same_path(&x.program, &client_s))
        .collect();
    // A5: one enabled Block rule per direction, same name, nothing else.
    match check_block_pair(ours.iter().copied(), &client_s) {
        Ok(what) => r.pass("rule-created", what),
        Err(why) => r.product("rule-created", format!("{why}; all Rat rules: {rules:?}")),
    }

    let after = match rule_names() {
        Ok(s) => s,
        Err(x) => return r.harness("snapshot-after", x),
    };
    let added: Vec<_> = after.difference(&before).cloned().collect();
    let removed: Vec<_> = before.difference(&after).cloned().collect();
    if added.len() == 1 && added[0].starts_with("Rat:path:") && removed.is_empty() {
        r.pass("no-other-rule-changed", format!("only added {added:?}, removed nothing"));
    } else {
        r.product("no-other-rule-changed", format!("added={added:?} removed={removed:?}"));
    }

    // Blocking.
    match probe_until(&client, HTTPS_URL, false, 4) {
        Some(false) => r.pass("client-blocked", "denied client's HTTPS request failed (baseline succeeded)"),
        Some(true) => r.product("client-blocked", format!("denied client still reaches {HTTPS_URL} with rule present: {rules:?}")),
        None => r.harness("client-blocked", "probe undecidable"),
    }
    if system_curl_ok(HTTPS_URL) {
        r.pass("curl-unaffected", "curl.exe from its normal path still works");
    } else {
        r.product("curl-unaffected", "curl.exe was blocked by a rule for another program");
    }

    // cleanup()
    if let Err(err) = e.cleanup() {
        r.product("cleanup", format!("cleanup returned error: {err}"));
    }
    let left = wait_until(Duration::from_secs(10), Duration::from_secs(1), || {
        rat_rules().map(|v| v.is_empty()).unwrap_or(false)
    });
    if left {
        r.pass("cleanup-removed", "no Rat: rule remains after cleanup()");
    } else {
        r.product("cleanup-removed", format!("rules after cleanup: {:?}", rat_rules()));
    }
    match rule_names() {
        Ok(s) if s == before => r.pass("snapshot-restored", "rule-name snapshot equals the one taken before"),
        Ok(s) => r.product("snapshot-restored", format!("diff +{:?} -{:?}", s.difference(&before).collect::<Vec<_>>(), before.difference(&s).collect::<Vec<_>>())),
        Err(x) => r.harness("snapshot-restored", x),
    }
    match probe_until(&client, HTTPS_URL, true, 4) {
        Some(true) => r.pass("control-unblocked", "client works again after cleanup (the block came from the rule)"),
        other => r.product("control-unblocked", format!("client still blocked after cleanup: {other:?}")),
    }
}
