mod common;
mod ipc;
mod w1;
mod w2;
mod w3;
mod w4;
mod w5;
mod w6;

use common::{Report, Status};
use std::panic::{self, AssertUnwindSafe};

fn run_one(id: &'static str, f: fn(&mut Report)) -> i32 {
    let mut r = Report::new(id);
    let res = panic::catch_unwind(AssertUnwindSafe(|| f(&mut r)));
    if let Err(p) = res {
        let msg = p
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "non-string panic".into());
        r.add(Status::FailHarness, "harness-panic", msg);
    }
    r.finish()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("all");
    match mode {
        // Helper mode: connect, send 1 MiB, hold the connection open.
        "client" => {
            let target = args[2].clone();
            let hold_ms: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(500);
            if let Ok(mut stream) = std::net::TcpStream::connect(&target) {
                use std::io::Write;
                let data = vec![0u8; 1024 * 1024];
                let _ = stream.write_all(&data);
                let _ = stream.flush();
                std::thread::sleep(std::time::Duration::from_millis(hold_ms));
            }
        }
        // Helper mode: HTTPS GET; exit 0 on success, 1 on failure.
        "curl" => {
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(8))
                .build()
                .unwrap();
            let ok = client.get(&args[2]).send().is_ok();
            std::process::exit(if ok { 0 } else { 1 });
        }
        "w1" => std::process::exit(run_one("W1", w1::run)),
        "w2" => std::process::exit(run_one("W2", w2::run)),
        "w3" => std::process::exit(run_one("W3", w3::run)),
        "w4" => std::process::exit(run_one("W4", w4::run)),
        "w5" => std::process::exit(run_one("W5", w5::run)),
        "w6" => std::process::exit(run_one("W6", w6::run)),
        "all" => {
            let mut worst = 0;
            for (id, f) in [
                ("W1", w1::run as fn(&mut Report)),
                ("W2", w2::run),
                ("W3", w3::run),
                ("W4", w4::run),
                ("W5", w5::run),
                ("W6", w6::run),
            ] {
                worst = worst.max(run_one(id, f));
            }
            std::process::exit(worst);
        }
        other => {
            eprintln!("unknown mode {other}");
            std::process::exit(64);
        }
    }
}
