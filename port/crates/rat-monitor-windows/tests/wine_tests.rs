#[cfg(test)]
mod wine_tests {
    use rat_monitor_windows::extract_process_name_from_path;
    use std::fs::File;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    #[test]
    fn test_backslash_and_unc_paths() {
        let unc_path = PathBuf::from(r"\\server\share\folder\app.exe");
        assert_eq!(extract_process_name_from_path(Some(&unc_path)), "app.exe");

        let backslash_path = PathBuf::from(r"C:\Program Files\App\app.exe");
        assert_eq!(
            extract_process_name_from_path(Some(&backslash_path)),
            "app.exe"
        );
    }

    #[test]
    fn test_drive_letter_case() {
        let path1 = PathBuf::from(r"c:\folder\app.exe");
        assert_eq!(extract_process_name_from_path(Some(&path1)), "app.exe");

        let path2 = PathBuf::from(r"C:\folder\app.exe");
        assert_eq!(extract_process_name_from_path(Some(&path2)), "app.exe");
    }

    #[test]
    fn test_long_paths() {
        let mut long_path_str = r"C:\".to_string();
        for _ in 0..30 {
            long_path_str.push_str("very_long_folder_name_that_takes_up_space\\");
        }
        long_path_str.push_str("app.exe");
        let long_path = PathBuf::from(long_path_str);

        assert_eq!(extract_process_name_from_path(Some(&long_path)), "app.exe");
    }

    #[test]
    fn test_utf16_non_ascii_names() {
        let path1 = PathBuf::from(r"C:\برنامه\تست.exe");
        assert_eq!(extract_process_name_from_path(Some(&path1)), "تست.exe");

        let path2 = PathBuf::from(r"C:\测试\应用.exe");
        assert_eq!(extract_process_name_from_path(Some(&path2)), "应用.exe");
    }

    #[test]
    fn test_crlf_line_endings() {
        let path1 = PathBuf::from("C:\\folder\\app.exe\r\n");
        assert_eq!(extract_process_name_from_path(Some(&path1)), "app.exe\r\n");
    }

    #[test]
    fn test_file_locking() {
        // Just verify basic behavior here since we can't reliably test Windows file locking on Wine/Linux
        assert_eq!(
            extract_process_name_from_path(Some(Path::new(r"C:\locked_file.exe"))),
            "locked_file.exe"
        );
    }
}
