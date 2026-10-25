//! Tiny TCP client/server used by the Linux e2e harness. The harness copies this
//! binary to unique paths so each copy is a distinct "application".
//!
//! test-client connect HOST PORT [--bind LPORT] [--send BYTES] [--wait-go] [--hold MS]
//!   prints `LOCAL <port>` after connect; with --wait-go it then waits for one
//!   line on stdin before sending; prints `SENT <n>` after sending, then holds
//!   the connection open for MS milliseconds (default 600000) and exits 0.
//!   On connect failure prints `ERR errno=<n> <text>` and exits 2.
//! test-client serve HOST PORT
//!   prints `LISTENING <port>`, then accepts forever and discards what it reads.
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::os::fd::FromRawFd;
use std::time::Duration;

fn connect_raw(host: Ipv4Addr, port: u16, bind_port: u16) -> Result<TcpStream, std::io::Error> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Owns the fd from here on, so every error path closes it.
        let stream = TcpStream::from_raw_fd(fd);

        let one: libc::c_int = 1;
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // A dropped SYN must not hang for minutes: cap the connect at 3 s.
        let tv = libc::timeval {
            tv_sec: 3,
            tv_usec: 0,
        };
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }

        if bind_port != 0 {
            let local = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: bind_port.to_be(),
                sin_addr: libc::in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            };
            if libc::bind(
                fd,
                &local as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }

        let remote = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(host.octets()),
            },
            sin_zero: [0; 8],
        };
        if libc::connect(
            fd,
            &remote as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(stream)
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("usage: test-client connect|serve HOST PORT [options]");
        std::process::exit(64);
    }
    let host: Ipv4Addr = match args[2].parse() {
        Ok(h) => h,
        Err(_) => {
            eprintln!("bad host {}", args[2]);
            std::process::exit(64);
        }
    };
    let port: u16 = match args[3].parse() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("bad port {}", args[3]);
            std::process::exit(64);
        }
    };

    match args[1].as_str() {
        "connect" => {
            let bind_port: u16 = flag(&args, "--bind")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let send: usize = flag(&args, "--send")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let hold_ms: u64 = flag(&args, "--hold")
                .and_then(|v| v.parse().ok())
                .unwrap_or(600_000);

            let mut stream = match connect_raw(host, port, bind_port) {
                Ok(s) => s,
                Err(e) => {
                    println!("ERR errno={} {}", e.raw_os_error().unwrap_or(-1), e);
                    std::process::exit(2);
                }
            };
            let local = stream.local_addr().map(|a| a.port()).unwrap_or(0);
            println!("LOCAL {}", local);
            let _ = std::io::stdout().flush();

            if args.iter().any(|a| a == "--wait-go") {
                let mut line = String::new();
                let _ = std::io::stdin().read_line(&mut line);
            }

            if send > 0 {
                let chunk = vec![0x5au8; 64 * 1024];
                let mut left = send;
                while left > 0 {
                    let n = left.min(chunk.len());
                    if let Err(e) = stream.write_all(&chunk[..n]) {
                        println!("ERR send {}", e);
                        std::process::exit(3);
                    }
                    left -= n;
                }
                println!("SENT {}", send);
                let _ = std::io::stdout().flush();
            }
            std::thread::sleep(Duration::from_millis(hold_ms));
        }
        "serve" => {
            let listener = match TcpListener::bind((host, port)) {
                Ok(l) => l,
                Err(e) => {
                    println!("ERR bind {}", e);
                    std::process::exit(2);
                }
            };
            println!(
                "LISTENING {}",
                listener.local_addr().map(|a| a.port()).unwrap_or(port)
            );
            let _ = std::io::stdout().flush();
            for conn in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut conn = conn;
                    let mut buf = vec![0u8; 64 * 1024];
                    while let Ok(n) = conn.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                    }
                });
            }
        }
        other => {
            eprintln!("unknown mode {}", other);
            std::process::exit(64);
        }
    }
}
