use rat_types::ProcessInfo;
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;

pub fn map_inodes_to_pids(proc_root: &Path) -> HashMap<u64, u32> {
    let mut inode_to_pid = HashMap::new();

    let entries = match fs::read_dir(proc_root) {
        Ok(e) => e,
        Err(_) => return inode_to_pid,
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let name_str = file_name.to_string_lossy();

        if let Ok(pid) = name_str.parse::<u32>() {
            let fd_dir = entry.path().join("fd");

            if let Ok(fd_entries) = fs::read_dir(&fd_dir) {
                for fd_entry in fd_entries.flatten() {
                    if let Ok(target) = fs::read_link(fd_entry.path()) {
                        let target_str = target.to_string_lossy();
                        if target_str.starts_with("socket:[") && target_str.ends_with(']') {
                            let inode_str = &target_str[8..target_str.len() - 1];
                            if let Ok(inode) = inode_str.parse::<u64>() {
                                // prefork servers share one
                                // socket inode across processes; keep the
                                // lowest pid so the mapping is deterministic
                                // regardless of readdir order.
                                match inode_to_pid.entry(inode) {
                                    std::collections::hash_map::Entry::Vacant(v) => {
                                        v.insert(pid);
                                    }
                                    std::collections::hash_map::Entry::Occupied(mut o) => {
                                        if pid < *o.get() {
                                            o.insert(pid);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    inode_to_pid
}

pub fn get_process_info(proc_root: &Path, pid: u32) -> Option<ProcessInfo> {
    let pid_dir = proc_root.join(pid.to_string());

    let exe = fs::read_link(pid_dir.join("exe")).ok();

    let name = fs::read_to_string(pid_dir.join("comm"))
        .unwrap_or_default()
        .trim()
        .to_string();

    if name.is_empty() {
        return None;
    }

    let mut uid = None;
    if let Ok(mut status_file) = fs::File::open(pid_dir.join("status")) {
        let mut status = String::new();
        if status_file.read_to_string(&mut status).is_ok() {
            for line in status.lines() {
                if line.starts_with("Uid:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() > 1 {
                        if let Ok(uid_val) = parts[1].parse::<u32>() {
                            uid = Some(uid_val);
                        }
                    }
                    break;
                }
            }
        }
    }

    let user = uid.map(get_user_name);

    Some(ProcessInfo {
        pid,
        exe,
        name,
        user,
    })
}

fn get_user_name(uid: u32) -> String {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
            let mut pwd_ptr = std::ptr::null_mut();
            // c_char is u8 on aarch64 (and i8 on x86) - an
            // i8 buffer does not compile there; use u8 and cast.
            let mut buf = vec![0u8; 1024];
            let ret = libc::getpwuid_r(
                uid,
                pwd.as_mut_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut pwd_ptr,
            );
            if ret == 0 && !pwd_ptr.is_null() {
                let pw = pwd.assume_init();
                if let Ok(c_str) = std::ffi::CStr::from_ptr(pw.pw_name).to_str() {
                    return c_str.to_string();
                }
            }
        }
    }

    uid.to_string()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn test_shared_inode_maps_to_lowest_pid() {
        // prefork servers expose the same socket inode via
        // several processes' fd dirs; the mapping must be deterministic.
        let root = tempfile::tempdir().unwrap();
        for pid in [200u32, 100] {
            let fd_dir = root.path().join(pid.to_string()).join("fd");
            std::fs::create_dir_all(&fd_dir).unwrap();
            std::os::unix::fs::symlink("socket:[42]", fd_dir.join("3")).unwrap();
        }
        let map = map_inodes_to_pids(root.path());
        assert_eq!(map.get(&42), Some(&100));
    }
}
