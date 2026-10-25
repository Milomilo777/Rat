//! Shared data types for the Rat port. Feature lanes never edit this file.
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    // Aliases accept Swift's lowercase raw values ("tcp"/"udp") on decode;
    // the serialized spelling stays unchanged.
    #[serde(alias = "tcp")]
    Tcp,
    #[serde(alias = "udp")]
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub exe: Option<PathBuf>,
    pub name: String,
    pub user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    pub process: ProcessInfo,
    pub protocol: Protocol,
    pub local: SocketAddr,
    /// None for listening sockets and unconnected UDP.
    pub remote: Option<SocketAddr>,
    pub listening: bool,
    pub bytes_in: Option<u64>,
    pub bytes_out: Option<u64>,
    /// M5 (update-09): true when the connection leaves through a VPN
    /// interface (v1.2.0 "mark connections through a VPN"). serde-defaulted
    /// so pre-field JSON still decodes.
    #[serde(default)]
    pub via_vpn: bool,
}

pub trait ConnectionSource {
    fn sample(&mut self) -> std::io::Result<Vec<Connection>>;
}
