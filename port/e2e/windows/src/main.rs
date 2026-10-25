mod w1;
mod w2;
mod w3;
mod w4;
mod w5;
mod w6;

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
    w1::run_w1();
    w2::run_w2();
    w3::run_w3();
    w4::run_w4();
    w5::run_w5();
    w6::run_w6();
}
