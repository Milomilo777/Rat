# rat-daemon

## Purpose
`rat-daemon` is the privileged background daemon component of the Rat network monitor port. It interfaces with OS-level primitives to capture network connections (via `ConnectionSource`) and pushes `Snapshot` messages over a local IPC channel (Unix Domain Socket on Linux, Named Pipe on Windows) to unprivileged user-interface clients.

## Public API

The crate exposes its internals for integration, but is primarily meant to be run as a standalone binary or service.
The main components are:
* `rat_daemon::msg::Message`: The versioned IPC JSON lines message format.
* `rat_daemon::core::run_core_loop`: Polling loop that triggers `ConnectionSource` samples every 1.5 seconds.
* `rat_daemon::ipc::start_ipc_server`: Asynchronous IPC listener handling Framed JSON Line serialization.

### Example usage (Client side receiving Snapshot)

```rust
use rat_daemon::msg::Message;
use tokio::net::UnixStream;
use tokio_util::codec::{FramedRead, LinesCodec};
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stream = UnixStream::connect("/run/rat/rat.sock").await?;
    let mut framed = FramedRead::new(stream, LinesCodec::new_with_max_length(10 * 1024 * 1024));

    if let Some(Ok(line)) = framed.next().await {
        let msg: Message = serde_json::from_str(&line)?;
        if let Message::Snapshot { connections } = msg {
            println!("Received {} connections", connections.len());
        }
    }
    Ok(())
}
```

## Platform Notes
* **Linux**:
  * Needs root to initially write to `/run/rat/rat.sock`, or `/run/rat/` directory must be writable by the user running the daemon.
  * The socket file is created with `0o660` permissions.
  * Stops gracefully on `SIGTERM` and `SIGINT`, cleaning up the socket file.
* **Windows**:
  * Runs as a Windows Service by default. Service mode requires administrative privileges to install.
  * Creates a named pipe `\\.\pipe\rat` with Security Descriptor `D:(A;;GA;;;IU)(A;;GA;;;BA)`, meaning only Interactive Users (IU) and Built-in Administrators (BA) are allowed to access it.

## Known Limits
* The current `ConnectionSource` integration in the binary provides a dummy empty implementation for testing purposes, as the actual connection sampler (like libproc/nettop) is part of a different lane.
* IPC currently drops clients that lag too much instead of buffering infinitely.
* Malformed JSON messages are rejected with an `Error` response but won't cause the server to crash.
* Does not handle pf or enforcer duties, this is deferred to `rat-enforcerd` (upstream macOS).
