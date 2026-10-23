use rat_types::ProcessInfo;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub fn map_inodes_to_pids(proc_root: &Path) -> HashMap<u64, ProcessInfo> {
    let mut inode_map = HashMap::new();

    let Ok(entries) = fs::read_dir(proc_root) else {
        return inode_map;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if let Ok(pid) = name_str.parse::<u32>() {
            let fd_path = entry.path().join("fd");
            let Ok(fd_entries) = fs::read_dir(&fd_path) else {
                continue;
            };

            let mut process_info = None;

            for fd_entry in fd_entries.flatten() {
                if let Ok(target) = fs::read_link(fd_entry.path()) {
                    let target_str = target.to_string_lossy();
                    if target_str.starts_with("socket:[") && target_str.ends_with("]") {
                        if let Ok(inode) = target_str[8..target_str.len() - 1].parse::<u64>() {
                            if process_info.is_none() {
                                process_info = Some(read_process_info(entry.path(), pid));
                            }
                            if let Some(info) = &process_info {
                                inode_map.insert(inode, info.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    inode_map
}

fn read_process_info(proc_dir: PathBuf, pid: u32) -> ProcessInfo {
    let exe = fs::read_link(proc_dir.join("exe")).ok();

    let mut name = String::new();
    if let Ok(cmdline) = fs::read(proc_dir.join("cmdline")) {
        if let Some(first_null) = cmdline.iter().position(|&b| b == 0) {
            name = String::from_utf8_lossy(&cmdline[..first_null]).into_owned();
        } else if !cmdline.is_empty() {
            name = String::from_utf8_lossy(&cmdline).into_owned();
        }
    }
    if name.is_empty() {
        if let Ok(stat) = fs::read_to_string(proc_dir.join("stat")) {
            if let Some(start) = stat.find('(') {
                if let Some(end) = stat.rfind(')') {
                    name = stat[start + 1..end].to_string();
                }
            }
        }
    }

    // Attempt to read user
    let mut user = None;
    if let Ok(status) = fs::read_to_string(proc_dir.join("status")) {
        for line in status.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    if let Ok(uid) = parts[1].parse::<u32>() {
                        user = get_username(uid);
                    }
                }
                break;
            }
        }
    }

    ProcessInfo {
        pid,
        exe,
        name: if name.is_empty() {
            format!("pid:{}", pid)
        } else {
            name
        },
        user,
    }
}

#[cfg(target_os = "linux")]
fn get_username(uid: u32) -> Option<String> {
    unsafe {
        let pw = libc::getpwuid(uid);
        if !pw.is_null() {
            let c_str = std::ffi::CStr::from_ptr((*pw).pw_name);
            return Some(c_str.to_string_lossy().into_owned());
        }
    }
    Some(uid.to_string())
}

#[cfg(not(target_os = "linux"))]
fn get_username(uid: u32) -> Option<String> {
    Some(uid.to_string())
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    #[test]
    fn test_map_inodes() {
        let dir = tempdir().unwrap();
        let proc_dir = dir.path();

        let pid_dir = proc_dir.join("1234");
        fs::create_dir(&pid_dir).unwrap();

        fs::write(pid_dir.join("cmdline"), b"test_app\0--arg\0").unwrap();
        fs::write(
            pid_dir.join("status"),
            "Name:\ttest_app\nUid:\t1000\t1000\t1000\t1000\n",
        )
        .unwrap();

        let fd_dir = pid_dir.join("fd");
        fs::create_dir(&fd_dir).unwrap();

        symlink("socket:[9999]", fd_dir.join("3")).unwrap();
        symlink("/dev/null", fd_dir.join("4")).unwrap();

        let map = map_inodes_to_pids(proc_dir);
        assert_eq!(map.len(), 1);
        let info = map.get(&9999).unwrap();
        assert_eq!(info.pid, 1234);
        assert_eq!(info.name, "test_app");
    }
}
