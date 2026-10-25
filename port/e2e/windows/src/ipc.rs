//! Minimal IPC protocol v1 client for `\\.\pipe\rat` (see rat-daemon msg.rs /
//! ipc.rs): newline-delimited JSON, first message must be Hello.
use rat_daemon::msg::{ClientMessage, ServerMessage, PROTOCOL_VERSION};
use std::io;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

pub const PIPE: &str = r"\\.\pipe\rat";

pub enum Recv {
    Line(String),
    Eof,
    Timeout,
    Err(String),
}

pub struct Ipc {
    rt: tokio::runtime::Runtime,
    rd: ReadHalf<NamedPipeClient>,
    wr: WriteHalf<NamedPipeClient>,
    buf: Vec<u8>,
}

impl Ipc {
    /// Opens the pipe, retrying while it is missing or busy (bounded).
    pub fn connect(timeout: Duration) -> io::Result<Ipc> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let start = Instant::now();
        loop {
            let res = rt.block_on(async { ClientOptions::new().open(PIPE) });
            match res {
                Ok(c) => {
                    let (rd, wr) = rt.block_on(async { tokio::io::split(c) });
                    return Ok(Ipc {
                        rt,
                        rd,
                        wr,
                        buf: Vec::new(),
                    });
                }
                Err(e) => {
                    // 231 = ERROR_PIPE_BUSY, NotFound = not created yet.
                    let retry = e.raw_os_error() == Some(231) || e.kind() == io::ErrorKind::NotFound;
                    if !retry || start.elapsed() >= timeout {
                        return Err(e);
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }

    /// Writes the raw bytes followed by a newline.
    pub fn send_raw(&mut self, line: &[u8]) -> io::Result<()> {
        let wr = &mut self.wr;
        self.rt.block_on(async {
            wr.write_all(line).await?;
            wr.write_all(b"\n").await?;
            wr.flush().await
        })
    }

    pub fn send(&mut self, msg: &ClientMessage) -> io::Result<()> {
        let s = msg.to_string().map_err(|e| io::Error::other(e.to_string()))?;
        self.send_raw(s.as_bytes())
    }

    pub fn hello(&mut self) -> io::Result<()> {
        self.send(&ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
        })
    }

    /// Next line from the daemon. The partial-line buffer lives in `self`, so
    /// a timeout loses nothing.
    pub fn recv(&mut self, timeout: Duration) -> Recv {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=pos).collect();
                return Recv::Line(String::from_utf8_lossy(&line).trim_end().to_string());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Recv::Timeout;
            }
            let mut chunk = vec![0u8; 65536];
            let rd = &mut self.rd;
            let res = self
                .rt
                .block_on(async { tokio::time::timeout(left, rd.read(&mut chunk)).await });
            match res {
                Err(_) => return Recv::Timeout,
                Ok(Ok(0)) => return Recv::Eof,
                Ok(Ok(n)) => self.buf.extend_from_slice(&chunk[..n]),
                Ok(Err(e)) => {
                    // A server that closes its end may surface as BrokenPipe
                    // (109) rather than a clean EOF.
                    if e.kind() == io::ErrorKind::BrokenPipe || e.raw_os_error() == Some(109) {
                        return Recv::Eof;
                    }
                    return Recv::Err(e.to_string());
                }
            }
        }
    }

    pub fn recv_msg(&mut self, timeout: Duration) -> Result<ServerMessage, Recv> {
        match self.recv(timeout) {
            Recv::Line(l) => ServerMessage::from_json_str(&l).map_err(|_| Recv::Line(l)),
            other => Err(other),
        }
    }
}
