
#[test]
fn test_budget_parse_port() {
    let start = std::time::Instant::now();
    for _ in 0..2000 {
        rat_monitor_windows::parse_port(13056);
    }
    let elapsed = start.elapsed();
    assert!(elapsed.as_millis() < 50, "budget exceeded: {:?}", elapsed);
}

#[test]
fn test_budget_extract_process_name() {
    let path = std::path::Path::new(r"C:\Program Files\App\app.exe");
    let start = std::time::Instant::now();
    for _ in 0..2000 {
        rat_monitor_windows::extract_process_name_from_path(Some(path));
    }
    let elapsed = start.elapsed();
    assert!(elapsed.as_millis() < 50, "budget exceeded: {:?}", elapsed);
}

#[test]
fn test_budget_check_is_vpn() {
    let start = std::time::Instant::now();
    for _ in 0..2000 {
        rat_monitor_windows::check_is_vpn_interface_type(53, "Wintun Userspace Tunnel");
    }
    let elapsed = start.elapsed();
    assert!(elapsed.as_millis() < 50, "budget exceeded: {:?}", elapsed);
}
