pub mod diag;
pub mod pid;
pub mod proc;
pub mod route;

use rat_types::{Connection, ConnectionSource};
use std::fs;
use std::io;
use std::path::PathBuf;

pub struct LinuxMonitor {
    proc_root: PathBuf,
    pub skipped: usize,
}

impl Default for LinuxMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxMonitor {
    pub fn new() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            skipped: 0,
        }
    }

    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: root.into(),
            skipped: 0,
        }
    }
}

impl ConnectionSource for LinuxMonitor {
    fn sample(&mut self) -> io::Result<Vec<Connection>> {
        let mut connections = Vec::new();

        let process_map = pid::map_inodes_to_pids(&self.proc_root);

        let mut sockets = Vec::new();
        for (file, is_tcp) in [
            ("net/tcp", true),
            ("net/tcp6", true),
            ("net/udp", false),
            ("net/udp6", false),
        ] {
            let path = self.proc_root.join(file);
            if let Ok(content) = fs::read_to_string(&path) {
                let mut parsed = proc::parse_proc_net(&content, is_tcp);
                sockets.append(&mut parsed);
            }
        }

        let counters = diag::get_socket_counters();

        for sock in sockets {
            if let Some(process) = process_map.get(&sock.inode) {
                let c = counters.get(&sock.inode);
                connections.push(Connection {
                    process: process.clone(),
                    protocol: sock.protocol,
                    local: sock.local,
                    remote: sock.remote,
                    listening: sock.listening,
                    bytes_in: c.and_then(|c| c.bytes_in),
                    bytes_out: c.and_then(|c| c.bytes_out),
                });
            } else {
                self.skipped += 1;
            }
        }

        Ok(connections)
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    #[test]
    fn test_monitor_mock() {
        let dir = tempdir().unwrap();
        let proc_dir = dir.path();

        let net_dir = proc_dir.join("net");
        fs::create_dir(&net_dir).unwrap();

        fs::write(net_dir.join("tcp"), "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1267 1 0000000000000000 100 0 0 10 0\n").unwrap();

        let pid_dir = proc_dir.join("1234");
        fs::create_dir(&pid_dir).unwrap();
        fs::write(pid_dir.join("cmdline"), b"test_app\0--arg\0").unwrap();

        let fd_dir = pid_dir.join("fd");
        fs::create_dir(&fd_dir).unwrap();
        symlink("socket:[1267]", fd_dir.join("3")).unwrap();

        let mut monitor = LinuxMonitor::with_root(proc_dir);
        let conns = monitor.sample().unwrap();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].process.pid, 1234);
        assert_eq!(conns[0].process.name, "test_app");
        assert_eq!(conns[0].local.port(), 22);
    }
}
