use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <host> <port> [loop]", args[0]);
        std::process::exit(1);
    }
    let host = &args[1];
    let port = &args[2];

    if let Ok(mut stream) = TcpStream::connect(format!("{}:{}", host, port)) {
        if args.len() > 3 && args[3] == "loop" {
            // Keep alive
            loop {
                std::thread::sleep(Duration::from_millis(100));
            }
        } else {
            let mut stdin = std::io::stdin();
            let _ = std::io::copy(&mut stdin, &mut stream);
        }
    } else {
        std::process::exit(1);
    }
}
