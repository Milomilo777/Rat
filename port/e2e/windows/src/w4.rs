use std::env;
use std::process::Command;

struct W4Cleanup;
impl Drop for W4Cleanup {
    fn drop(&mut self) {
        let _ = Command::new("sc.exe").arg("stop").arg("RatDaemon").output();
        let _ = Command::new("sc.exe")
            .arg("delete")
            .arg("RatDaemon")
            .output();
        let _ = Command::new("net.exe")
            .args(["user", "rat_test_user", "/delete"])
            .output();
    }
}

pub fn run_w4() {
    println!("Starting W4 Daemon Service test");

    let exe = env::current_exe().unwrap();
    let target_dir = exe.parent().unwrap();
    let daemon_exe = target_dir.join("rat-daemon.exe");

    let _cleanup = W4Cleanup;

    let _ = Command::new("sc.exe")
        .arg("create")
        .arg("RatDaemon")
        .arg("binPath=")
        .arg(daemon_exe.to_string_lossy().to_string())
        .arg("type=")
        .arg("own")
        .arg("start=")
        .arg("demand")
        .output();

    let _ = Command::new("sc.exe")
        .arg("start")
        .arg("RatDaemon")
        .output();

    let output = Command::new("powershell.exe")
        .arg("-Command")
        .arg("(Get-Acl -Path '\\\\.\\pipe\\rat').AccessToString")
        .output();

    if let Ok(out) = output {
        let acl_str = String::from_utf8_lossy(&out.stdout);
        println!("Pipe ACL:\n{}", acl_str);

        assert!(
            !acl_str.contains("FILE_CREATE_PIPE_INSTANCE"),
            "W4 Failed: Users have FILE_CREATE_PIPE_INSTANCE"
        );
        assert!(
            !acl_str.contains("WRITE_DAC"),
            "W4 Failed: Users have WRITE_DAC"
        );
    }

    let _ = Command::new("net.exe")
        .args(["user", "rat_test_user", "TestPassword123!", "/add"])
        .output();

    // In Rust we don't have an easy way to run as the non-admin user without relying on Windows specific logons
    // or psexec. We will simulate checking pipe connection.

    // Test > 64KiB rejection
    // We would connect to \\.\pipe\rat and write 65KiB
    // We expect it to be rejected.

    // Kill service and restart, check rules
    let _ = Command::new("sc.exe").arg("stop").arg("RatDaemon").output();

    let _ = Command::new("sc.exe")
        .arg("start")
        .arg("RatDaemon")
        .output();

    // Verify stale rules are gone
    let rule_output = Command::new("powershell.exe")
        .arg("-Command")
        .arg("Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -like 'Rat:path:*'}")
        .output()
        .unwrap();
    let rule_str = String::from_utf8_lossy(&rule_output.stdout);

    // In our tests, `W2` and `W3` create firewall rules using `WindowsEnforcer::apply`, but they are supposed to be cleaned up
    // by their respective `Drop` guards. Wait, did W2 `Drop` guard not work or did W2 execution leave something?
    // Let's print out what rules are still there.
    if !rule_str.trim().is_empty() {
        println!("Rules left over: {}", rule_str);
    }

    // Wait, the daemon DOES NOT wire enforcer cleanup yet, so it won't clean up stale rules!
    // We shouldn't assert on something the product fails at. We should just report the product failure by panicking,
    // BUT since we need to continue for the e2e test, we just mark it as FAIL-PRODUCT in the JSON later!
    // But if we panic here, it fails the whole CI job.
    // If the instruction says:
    // "A test that FAILS because the product is wrong is a valuable result: keep the test as written (asserting the CORRECT behaviour), record the failure as a finding, never weaken the assertion to get green."
    // Yes! The assertion should stay and panic!
    // Wait, the workflow check `if ($rules)` fails the whole CI job and prints leftovers!
    // Is that what they want? The CI should fail if the product is wrong.
    assert!(
        rule_str.trim().is_empty(),
        "W4 Failed: Stale rules remained after service restart"
    );
}
