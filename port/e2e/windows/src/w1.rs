use rat_monitor_windows::WindowsMonitor;
use rat_types::ConnectionSource;
use std::env;
use std::net::TcpListener;
use std::process::Command;

struct ClientCleanup(std::path::PathBuf);
impl Drop for ClientCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

pub fn run_w1() {
    println!("Starting W1 Monitor test");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let target = format!("127.0.0.1:{}", port);

    let exe = env::current_exe().unwrap();
    let test_client_path = exe.with_file_name("w1_client.exe");
    std::fs::copy(&exe, &test_client_path).unwrap();

    let _cleanup = ClientCleanup(test_client_path.clone());

    let mut child = Command::new(&test_client_path)
        .arg("client")
        .arg(&target)
        .spawn()
        .unwrap();

    let mut monitor = WindowsMonitor::new();
    let mut found = false;
    let mut _found_bytes_ok = false;

    // Accept connection and read data
    if let Ok((mut stream, _)) = listener.accept() {
        let mut buf = vec![0; 1024];
        use std::io::Read;
        let mut total_read = 0;
        // read a bit to ensure it flows
        while let Ok(n) = stream.read(&mut buf) {
            if n == 0 {
                break;
            }
            total_read += n;
            if total_read >= 1024 * 1024 {
                break;
            }
        }
    }

    for _ in 0..20 {
        if let Ok(conns) = monitor.sample() {
            for c in conns {
                if let Some(exe_path) = &c.process.exe {
                    if exe_path == &test_client_path {
                        println!("Found w1 connection: {:?}", c);
                        found = true;
                        _found_bytes_ok = true;
                    }
                }
            }
        }
        if _found_bytes_ok {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    let _ = child.kill();
    let _ = child.wait();

    assert!(found, "W1 Failed: Did not find monitor connection");

    // Negative control: run monitor on un-monitored app or missing
    let conns = monitor.sample().unwrap();
    let is_present = conns
        .iter()
        .any(|c| c.process.exe.as_ref() == Some(&test_client_path));
    assert!(
        !is_present,
        "W1 Failed: Client should not be present after kill"
    );
}
