#[cfg(target_os = "windows")]
use std::path::PathBuf;

#[cfg(target_os = "windows")]
#[test]
fn test_windows_long_paths() {
    let long_path_str = "\\\\?\\C:\\very\\long\\path\\that\\exceeds\\260\\characters\\"
        .to_string()
        .repeat(10);
    let path = PathBuf::from(&long_path_str);
    assert_eq!(path.to_string_lossy(), long_path_str);
}

#[cfg(target_os = "windows")]
#[test]
fn test_windows_utf16_paths() {
    // Rust natively supports UTF-16 inside PathBuf through OsString
    let path = PathBuf::from("C:\\テスト\\こんにちは.exe");
    assert!(path.to_string_lossy().contains("テスト"));
}

#[cfg(target_os = "windows")]
#[test]
fn test_windows_unc_paths() {
    let path = PathBuf::from("\\\\server\\share\\file.txt");
    assert_eq!(path.to_string_lossy(), "\\\\server\\share\\file.txt");
}
