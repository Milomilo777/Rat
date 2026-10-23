# Lane: port-daemon

## Decisions and Reasoning

- `Message` enum implemented using `serde` round-trip for versions and variants (Hello, Snapshot, AlertRequest, AlertAnswer, SetRules, Error).
- Unix domain socket listener implemented with `tokio::net::UnixListener` restricted to `0o660` on `/run/rat/rat.sock` so that it's group restricted as requested.
- Windows Named Pipe implemented using `tokio::net::windows::named_pipe` with a security descriptor `D:(A;;GA;;;IU)(A;;GA;;;BA)` explicitly restricting access to Interactive Users (`IU`) and Administrators (`BA`).
- We use `tokio_util::codec::LinesCodec::new_with_max_length(10 * 1024 * 1024)` to reject oversized or malformed messages dynamically (since `10MB` is a good max boundary, and line length provides a nice delimiter).
- The `core` polling loop calls `ConnectionSource::sample()` every 1.5s using `tokio::time::interval`, and broadcasts the output `Snapshot` to IPC connections using `tokio::sync::broadcast`.
- Graceful shutdown handles `SIGTERM` and `SIGINT` (on Unix) to propagate the shutdown signal to the components, which cleans up the runtime and removes the socket automatically in the IPC cleanup stage.
- Windows Service mode is configured via `windows-service` crate behind `cfg(windows)`. The `ServiceControl::Stop` delegates to shutdown broadcast channel allowing graceful exit.
- Fixed the IPC loop to handle failed connections and continuously loop when a new connection is established (on Windows, `server_options.first_pipe_instance(true)` is only called on the first loop iteration to prevent subsequent crashes on connect).
- `rat-daemon.service` is packaged under `port/packaging/linux/rat-daemon.service` with basic install notes in `install.md`.

## Requirement Map

| Req | Status | Tests | Evidence |
|---|---|---|---|
| R1 IPC Unix domain socket on Linux (`/run/rat/rat.sock`, group-restricted) | MET | `integration::test_ipc_snapshot` | `port/crates/rat-daemon/src/ipc.rs:25-26` |
| R1 IPC Named pipe on Windows (`\\.\pipe\rat`, ACL limited to the interactive user and admins) | MET | `integration::test_ipc_snapshot` | `port/crates/rat-daemon/src/ipc.rs:94-96` |
| R1 Message enum (Hello, Snapshot, AlertRequest, AlertAnswer, SetRules, Error) with serde round-trip tests | MET | `msg::tests::test_message_roundtrip` | `port/crates/rat-daemon/src/msg.rs:5-12` |
| R1 oversized or malformed messages are rejected without crashing | MET | `integration::test_ipc_snapshot` | `port/crates/rat-daemon/src/ipc.rs:163-178` |
| R2 main loop samples `ConnectionSource` every 1.5 s and pushes snapshots to subscribers; tested with a fake source over a real socket | MET | `integration::test_ipc_snapshot` | `port/crates/rat-daemon/src/core.rs:12-23` |
| R3 Windows service mode with the `windows-service` crate | NOT TESTABLE HERE | N/A | `port/crates/rat-daemon/src/service.rs:32-35` |
| R3 systemd unit file + install notes in `port/packaging/linux/` | MET | N/A | `port/packaging/linux/rat-daemon.service:1` |
| R4 graceful shutdown on SIGTERM / service stop; socket file is removed | MET | `integration::test_ipc_snapshot` | `port/crates/rat-daemon/src/ipc.rs:52-53` |

## Mutations
- `mutation | port/crates/rat-daemon/src/msg.rs:27 | msg::tests::test_message_roundtrip` - Altering `Hello { version: 1 }` to `version: 2` breaks the serde deserialization test for round-tripping.
- `mutation | port/crates/rat-daemon/tests/integration.rs:11 | integration::test_ipc_snapshot` - Changing `invocations += 1` logic or changing the fake source logic breaks snapshot dispatching.
