use std::env;
use std::path::PathBuf;
use std::process::Command;

struct W6Cleanup(Option<std::process::Child>);
impl Drop for W6Cleanup {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = Command::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-Command")
            .arg("Get-NetFirewallRule -DisplayName 'Rat:path:C:\\w6_dummy.exe' -ErrorAction SilentlyContinue | Remove-NetFirewallRule")
            .output();
    }
}

pub fn run_w6() {
    println!("Starting W6 GUI-to-daemon gap test");

    // Test that missing pipe fails (negative control)
    let output = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(r#"$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'rat_missing', [System.IO.Pipes.PipeDirection]::InOut); $pipe.Connect(100);"#)
        .output().unwrap();
    assert!(
        !output.status.success(),
        "W6 Failed: Connection to missing pipe should have failed (Negative Control)"
    );

    let daemon_exe_path =
        env::var("RAT_DAEMON_EXE").expect("RAT_DAEMON_EXE environment variable not set");
    let daemon_exe = PathBuf::from(daemon_exe_path);
    assert!(
        daemon_exe.exists(),
        "W6 Failed: daemon executable not found at {:?}",
        daemon_exe
    );

    let daemon = Command::new(daemon_exe)
        .spawn()
        .expect("W6 Failed: Could not spawn daemon");

    let _cleanup = W6Cleanup(Some(daemon));

    // Wait for pipe to be ready
    let mut pipe_ready = false;
    for _ in 0..10 {
        let output = Command::new("powershell.exe")
            .arg("-Command")
            .arg("if (Test-Path '\\\\.\\pipe\\rat') { exit 0 } else { exit 1 }")
            .output()
            .unwrap();
        if output.status.success() {
            pipe_ready = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert!(
        pipe_ready,
        "W6 Failed: daemon pipe did not become ready in 5 seconds"
    );

    // Connect to named pipe `\\.\pipe\rat` and write the JSON Lines config
    let output = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg(r#"$pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'rat', [System.IO.Pipes.PipeDirection]::InOut); $pipe.Connect(5000); $sw = New-Object System.IO.StreamWriter($pipe); $sw.AutoFlush = $true; $sw.WriteLine('{"ApplyPlan":{"add":["C:\w6_dummy.exe"],"remove":[],"local_ports":[]}}'); $sr = New-Object System.IO.StreamReader($pipe); $sr.ReadLine()"#)
        .output().expect("Failed to execute powershell");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        panic!("W6 Failed: Pipe connection/write failed. Error: {}", stderr);
    }

    println!("W6 output: {}", stdout);

    assert!(
        !stdout.trim().is_empty(),
        "W6 Failed: No reply read from pipe"
    );

    std::thread::sleep(std::time::Duration::from_millis(1500));

    let rule_output = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-Command")
        .arg("Get-NetFirewallRule -DisplayName 'Rat:path:C:\\w6_dummy.exe' -ErrorAction SilentlyContinue")
        .output()
        .unwrap();

    let rule_str = String::from_utf8_lossy(&rule_output.stdout);

    let dry_run = env::var("RAT_DRY_RUN").is_ok();
    if !dry_run {
        assert!(
            !rule_str.trim().is_empty(),
            "W6 Failed: Rule was not created via IPC daemon command"
        );
    }
}
