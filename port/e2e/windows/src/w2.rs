use rat_enforcer::windows::WindowsEnforcer;
use rat_enforcer::{Blocklist, Enforcer};
use std::env;
use std::process::Command;

struct EnforcerCleanup {
    enforcer: WindowsEnforcer,
    path: std::path::PathBuf,
}
impl Drop for EnforcerCleanup {
    fn drop(&mut self) {
        let _ = self
            .enforcer
            .apply(&self.enforcer.plan(&Blocklist::default()));
        let _ = std::fs::remove_file(&self.path);
        let _ = self.enforcer.cleanup();
    }
}

pub fn run_w2() {
    println!("Starting W2 Enforcer test");
    let exe = env::current_exe().unwrap();
    let test_client_path = exe.with_file_name("w2_client.exe");
    std::fs::copy(&exe, &test_client_path).unwrap();

    let enforcer = WindowsEnforcer {
        current: Blocklist::default(),
    };

    let _cleanup = EnforcerCleanup {
        enforcer: WindowsEnforcer {
            current: Blocklist::default(),
        },
        path: test_client_path.clone(),
    };

    // Snapshot firewall rules before
    let rules_before = Command::new("powershell.exe")
        .arg("-Command")
        .arg("Get-NetFirewallRule | Select-Object -ExpandProperty DisplayName")
        .output()
        .unwrap();
    let rules_before_str = String::from_utf8_lossy(&rules_before.stdout);
    let count_before = rules_before_str.lines().count();

    let mut wanted = Blocklist::default();
    wanted
        .paths
        .push(test_client_path.to_string_lossy().to_string());

    let plan = enforcer.plan(&wanted);

    // Check RAT_DRY_RUN
    if env::var("RAT_DRY_RUN").is_ok() {
        println!("Dry run, skipped enforce apply");
    } else {
        enforcer.apply(&plan).unwrap();
    }

    // Check if rules are present
    let rule_output = Command::new("powershell.exe")
        .arg("-Command")
        .arg("Get-NetFirewallRule -DisplayName 'Rat:path:*' -ErrorAction SilentlyContinue")
        .output()
        .unwrap();
    let rule_str = String::from_utf8_lossy(&rule_output.stdout);
    println!("Rules created:\n{}", rule_str);

    // Snapshot firewall rules after
    let rules_after = Command::new("powershell.exe")
        .arg("-Command")
        .arg("Get-NetFirewallRule | Select-Object -ExpandProperty DisplayName")
        .output()
        .unwrap();
    let rules_after_str = String::from_utf8_lossy(&rules_after.stdout);
    let count_after = rules_after_str.lines().count();

    println!(
        "Rules before: {}, Rules after: {}",
        count_before, count_after
    );

    let output = Command::new(&test_client_path)
        .arg("curl")
        .arg("https://example.com")
        .output()
        .unwrap();

    println!("Blocked client status: {}", output.status);

    if env::var("RAT_DRY_RUN").is_ok() {
        assert!(
            output.status.success(),
            "W2 Failed: The client was blocked even on dry run"
        );
    } else {
        assert!(
            !output.status.success(),
            "W2 Failed: The blocked client was able to connect"
        );
    }

    // Test curl from normal path works
    let curl_output = Command::new("curl.exe")
        .arg("-I")
        .arg("https://example.com")
        .output()
        .unwrap();
    println!("Normal curl status: {}", curl_output.status);
    assert!(
        curl_output.status.success(),
        "W2 Failed: Normal curl was blocked"
    );
}
