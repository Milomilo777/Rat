use rat_enforcer::windows::WindowsEnforcer;
use rat_enforcer::{Blocklist, Enforcer};
use std::env;
use std::process::Command;

struct W3Cleanup {
    enforcer: WindowsEnforcer,
    path_a: std::path::PathBuf,
    path_b: std::path::PathBuf,
}
impl Drop for W3Cleanup {
    fn drop(&mut self) {
        let _ = self
            .enforcer
            .apply(&self.enforcer.plan(&Blocklist::default()));
        let _ = std::fs::remove_file(&self.path_a);
        let _ = std::fs::remove_file(&self.path_b);
        let _ = self.enforcer.cleanup();
    }
}

pub fn run_w3() {
    println!("Starting W3 Isolation test");
    let exe = env::current_exe().unwrap();
    let client_a = exe.with_file_name("w3_a.exe");
    let client_b = exe.with_file_name("w3_b.exe");
    std::fs::copy(&exe, &client_a).unwrap();
    std::fs::copy(&exe, &client_b).unwrap();

    let enforcer = WindowsEnforcer {
        current: Blocklist::default(),
    };

    let _cleanup = W3Cleanup {
        enforcer: WindowsEnforcer {
            current: Blocklist::default(),
        },
        path_a: client_a.clone(),
        path_b: client_b.clone(),
    };

    let mut wanted = Blocklist::default();
    wanted.paths.push(client_a.to_string_lossy().to_string());

    let plan = enforcer.plan(&wanted);
    enforcer.apply(&plan).unwrap();

    // Test A (blocked)
    let output_a = Command::new(&client_a)
        .arg("curl")
        .arg("https://example.com")
        .output()
        .unwrap();
    assert!(
        !output_a.status.success(),
        "W3 Failed: Client A was not blocked"
    );

    // Test B (allowed)
    let output_b = Command::new(&client_b)
        .arg("curl")
        .arg("https://example.com")
        .output()
        .unwrap();
    assert!(
        output_b.status.success(),
        "W3 Failed: Client B was blocked incorrectly"
    );
}
