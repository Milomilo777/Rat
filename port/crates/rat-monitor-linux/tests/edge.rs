use rat_monitor_linux::LinuxMonitor;
use rat_types::ConnectionSource;

#[test]
fn test_mock_root_missing_files() {
    let mut monitor =
        LinuxMonitor::new(std::path::PathBuf::from("/nonexistent/path/for/tests/proc"));
    let connections = monitor.sample().unwrap();
    assert!(connections.is_empty());
}
