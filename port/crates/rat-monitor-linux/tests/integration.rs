use rat_monitor_linux::LinuxMonitor;
use rat_types::{ConnectionSource, Protocol};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

#[test]
fn test_live_tcp_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local_addr = listener.local_addr().unwrap();

    // Accept connection in a separate thread
    let server_thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        use std::io::Write;
        stream.write_all(b"hello").unwrap();
        // Keep it open for a bit
        thread::sleep(Duration::from_secs(2));
    });

    // Client connection
    let client = TcpStream::connect(local_addr).unwrap();

    // Give OS time to update /proc and netlink
    thread::sleep(Duration::from_millis(500));

    let mut monitor = LinuxMonitor::default();
    let connections = monitor.sample().unwrap();

    let client_addr = client.local_addr().unwrap();

    // Look for client connection
    let client_conn = connections.iter().find(|c| {
        c.protocol == Protocol::Tcp && c.local == client_addr && c.remote == Some(local_addr)
    });

    assert!(
        client_conn.is_some(),
        "Client connection not found in monitor sample"
    );

    let client_conn = client_conn.unwrap();
    assert_eq!(client_conn.process.pid, std::process::id());
    // Name should likely match the test executable
    assert!(!client_conn.process.name.is_empty());
    assert!(client_conn.process.exe.is_some());

    server_thread.join().unwrap();
}
