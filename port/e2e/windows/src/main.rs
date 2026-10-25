mod w1;
mod w2;
mod w3;
mod w4;
mod w5;
mod w6;

use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};

static HAS_FAILURE: AtomicBool = AtomicBool::new(false);

fn run_test(name: &str, test: fn()) {
    println!("--- Running test {} ---", name);
    let result = panic::catch_unwind(|| {
        test();
    });
    if let Err(_) = result {
        println!("Test {} FAILED", name);
        HAS_FAILURE.store(true, Ordering::SeqCst);
    } else {
        println!("Test {} PASSED", name);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "client" {
        let target = args[2].clone();
        if let Ok(mut stream) = std::net::TcpStream::connect(&target) {
            use std::io::Write;
            let data = vec![0u8; 1024 * 1024];
            let _ = stream.write_all(&data);
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        return;
    } else if args.len() > 1 && args[1] == "curl" {
        let target = args[2].clone();
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .unwrap();
        let res = client.get(&target).send();
        if res.is_err() {
            std::process::exit(1);
        } else {
            std::process::exit(0);
        }
    }

    println!("Running tests...");
    run_test("w1", w1::run_w1);
    run_test("w2", w2::run_w2);
    run_test("w3", w3::run_w3);
    run_test("w4", w4::run_w4);
    run_test("w5", w5::run_w5);
    run_test("w6", w6::run_w6);

    if HAS_FAILURE.load(Ordering::SeqCst) {
        std::process::exit(101);
    }
}
