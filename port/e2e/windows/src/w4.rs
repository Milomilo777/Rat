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

        let _ = Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-Command")
            .arg("Get-NetFirewallRule -DisplayName 'Rat:path:*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule")
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

    // Create a stale rule for the daemon to clean up upon restart
    let _ = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg("New-NetFirewallRule -DisplayName 'Rat:path:C:\\dummy.exe' -Direction Outbound -Action Block")
        .output();

    // Kill service and restart, check rules
    let _ = Command::new("sc.exe").arg("stop").arg("RatDaemon").output();

    let _ = Command::new("sc.exe")
        .arg("start")
        .arg("RatDaemon")
        .output();

    // Wait a bit to let the daemon start up
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Verify stale rules are gone
    let rule_output = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg("Get-NetFirewallRule -DisplayName 'Rat:path:*' -ErrorAction SilentlyContinue")
        .output()
        .unwrap();
    let rule_str = String::from_utf8_lossy(&rule_output.stdout);

    if !rule_str.trim().is_empty() {
        println!("Rules left over:\n{}", rule_str);
    }

    assert!(
        rule_str.trim().is_empty(),
        "W4 Failed: Stale rules remained after service restart"
    );
}
