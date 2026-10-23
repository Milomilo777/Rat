pub mod diag;
pub mod pid;
pub mod proc;
pub mod route;

use rat_types::{Connection, ConnectionSource, ProcessInfo, Protocol};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

pub struct LinuxMonitor {
    proc_root: PathBuf,
    pub vanished_count: u64,
}

impl Default for LinuxMonitor {
    fn default() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            vanished_count: 0,
        }
    }
}

impl LinuxMonitor {
    pub fn new(proc_root: PathBuf) -> Self {
        Self { proc_root, vanished_count: 0 }
    }
}

impl ConnectionSource for LinuxMonitor {
    fn sample(&mut self) -> std::io::Result<Vec<Connection>> {
        let mut connections = Vec::new();
        let mut vanished = 0;

        let tcp4 = fs::read_to_string(self.proc_root.join("net/tcp")).unwrap_or_default();
        let tcp6 = fs::read_to_string(self.proc_root.join("net/tcp6")).unwrap_or_default();
        let udp4 = fs::read_to_string(self.proc_root.join("net/udp")).unwrap_or_default();
        let udp6 = fs::read_to_string(self.proc_root.join("net/udp6")).unwrap_or_default();

        let mut entries = proc::parse_proc_net(&tcp4, Protocol::Tcp);
        entries.append(&mut proc::parse_proc_net(&tcp6, Protocol::Tcp));
        let mut udp_entries = proc::parse_proc_net(&udp4, Protocol::Udp);
        udp_entries.append(&mut proc::parse_proc_net(&udp6, Protocol::Udp));

        let inode_to_pid = pid::map_inodes_to_pids(&self.proc_root);

        let mut process_cache: HashMap<u32, ProcessInfo> = HashMap::new();

        #[cfg(target_os = "linux")]
        let counters = diag::get_socket_counters();

        #[cfg(not(target_os = "linux"))]
        let counters: HashMap<u64, diag::SocketCounters> = HashMap::new();

        let mut build_connections = |entries: Vec<proc::ProcNetEntry>, protocol: Protocol, vanished: &mut u64| {
            for entry in entries {
                if let Some(&pid) = inode_to_pid.get(&entry.inode) {
                    use std::collections::hash_map::Entry;
                    if let Entry::Vacant(e) = process_cache.entry(pid) {
                        if let Some(info) = pid::get_process_info(&self.proc_root, pid) {
                            e.insert(info);
                        } else {
                            *vanished += 1;
                            continue;
                        }
                    }

                    if let Some(process) = process_cache.get(&pid).cloned() {
                        let is_listening = protocol == Protocol::Tcp && entry.state == 10;

                        let (bytes_in, bytes_out) = if protocol == Protocol::Tcp {
                            if let Some(c) = counters.get(&entry.inode) {
                                (c.bytes_in, c.bytes_out)
                            } else {
                                (None, None)
                            }
                        } else {
                            (None, None)
                        };

                        connections.push(Connection {
                            process,
                            protocol,
                            local: entry.local,
                            remote: entry.remote,
                            listening: is_listening,
                            bytes_in,
                            bytes_out,
                        });
                    } else {
                        *vanished += 1;
                    }
                }
            }
        };

        build_connections(entries, Protocol::Tcp, &mut vanished);
        build_connections(udp_entries, Protocol::Udp, &mut vanished);

        self.vanished_count = vanished;
        Ok(connections)
    }
}
