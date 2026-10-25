use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

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

fn wait_for_service_state(state: &str) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        let out = Command::new("sc.exe")
            .arg("query")
            .arg("RatDaemon")
            .output()
            .unwrap();
        let out_str = String::from_utf8_lossy(&out.stdout);
        if out_str.contains(state) {
            println!("Service reached state {}: \n{}", state, out_str);
            return;
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    // Failed to reach state
    let out_qc = Command::new("sc.exe")
        .arg("qc")
        .arg("RatDaemon")
        .output()
        .unwrap();
    let out_events = Command::new("powershell.exe")
        .arg("-Command")
        .arg("Get-WinEvent -LogName System -MaxEvents 30 | Where-Object {$_.ProviderName -eq 'Service Control Manager'} | Select-Object -ExpandProperty Message")
        .output()
        .unwrap();

    panic!(
        "W4 Failed: Service did not reach {} state in 30s.\nsc qc output:\n{}\nEvent logs:\n{}",
        state,
        String::from_utf8_lossy(&out_qc.stdout),
        String::from_utf8_lossy(&out_events.stdout)
    );
}

pub fn run_w4() {
    println!("Starting W4 Daemon Service test");

    let daemon_exe_path =
        env::var("RAT_DAEMON_EXE").expect("RAT_DAEMON_EXE environment variable not set");
    let daemon_exe = PathBuf::from(daemon_exe_path);
    assert!(
        daemon_exe.exists(),
        "W4 Failed: daemon executable not found at {:?}",
        daemon_exe
    );

    let _cleanup = W4Cleanup;

    let out = Command::new("sc.exe")
        .arg("create")
        .arg("RatDaemon")
        .arg("binPath=")
        .arg(daemon_exe.to_string_lossy().to_string())
        .arg("type=")
        .arg("own")
        .arg("start=")
        .arg("demand")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "W4 Failed: sc create failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    let out = Command::new("sc.exe")
        .arg("start")
        .arg("RatDaemon")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "W4 Failed: sc start failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );

    wait_for_service_state("RUNNING");

    // Negative control: Check pipe existence with dummy pipe to ensure we can catch absence.
    let output = Command::new("powershell.exe")
        .arg("-Command")
        .arg("if (Test-Path '\\\\.\\pipe\\rat_missing_dummy') { (Get-Acl -Path '\\\\.\\pipe\\rat_missing_dummy').AccessToString } else { throw 'nope' }")
        .output().unwrap();
    assert!(
        !output.status.success(),
        "W4 Failed: Negative control for pipe existence failed."
    );

    // Check pipe existence. If the pipe is absent, Get-Acl will error.
    let output = Command::new("powershell.exe")
        .arg("-Command")
        .arg("if (Test-Path '\\\\.\\pipe\\rat') { (Get-Acl -Path '\\\\.\\pipe\\rat').AccessToString } else { throw 'nope' }")
        .output().unwrap();

    assert!(
        output.status.success(),
        "W4 Failed: Pipe does not exist or Get-Acl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let acl_str = String::from_utf8_lossy(&output.stdout);
    assert!(!acl_str.trim().is_empty(), "W4 Failed: Pipe ACL was empty");
    println!("Pipe ACL:\n{}", acl_str);

    assert!(
        !acl_str.contains("FILE_CREATE_PIPE_INSTANCE"),
        "W4 Failed: Users have FILE_CREATE_PIPE_INSTANCE"
    );
    assert!(
        !acl_str.contains("WRITE_DAC"),
        "W4 Failed: Users have WRITE_DAC"
    );

    let out = Command::new("net.exe")
        .args(["user", "rat_test_user", "TestPassword123!", "/add"])
        .output()
        .unwrap();
    assert!(out.status.success(), "W4 Failed: net user add failed");

    // >64KiB rejection test via rust
    // Connect to the named pipe directly.
    let pipe_path = r"\\.\pipe\rat";
    if let Ok(mut pipe) = std::fs::OpenOptions::new().write(true).open(pipe_path) {
        use std::io::Write;
        let large_msg = vec![b'A'; 66000]; // 66 KB
        let write_result = pipe.write_all(&large_msg);
        assert!(
            write_result.is_err(),
            "W4 Failed: >64KiB message was not rejected"
        );
    } else {
        panic!("W4 Failed: Could not connect to pipe for >64KiB rejection test");
    }

    // Create a stale rule for the daemon to clean up upon restart
    let _ = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg("New-NetFirewallRule -DisplayName 'Rat:path:C:\\dummy.exe' -Direction Outbound -Action Block")
        .output();

    let out = Command::new("sc.exe")
        .arg("stop")
        .arg("RatDaemon")
        .output()
        .unwrap();
    assert!(out.status.success(), "W4 Failed: sc stop failed");
    wait_for_service_state("STOPPED");

    let out = Command::new("sc.exe")
        .arg("start")
        .arg("RatDaemon")
        .output()
        .unwrap();
    assert!(out.status.success(), "W4 Failed: sc start 2 failed");

    wait_for_service_state("RUNNING");

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
