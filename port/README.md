# Rat for Windows and Linux (port)

This directory holds the Windows and Linux version of Rat. It has two parts:

- **`rat-daemon`** - a privileged background process (a Windows service running as `LocalSystem`, or a systemd
  service running as root). It watches network connections, matches them against saved rules and enforces
  blocks with the system firewall (Windows Defender Firewall through `netsh`, Linux through `nftables`).
- **Desktop app** (`app/`) - a Tauri application that shows connections and rules.

The macOS app lives in the repository root and is not part of this directory.

## Status

This is the first release of the port. The daemon, the rule store and the firewall enforcement are tested on real
Windows and Linux runners in GitHub Actions. Read [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) before relying on it.

TODO (to be confirmed with the app wiring in this pull request): the app talks to the daemon over IPC; on Windows
run the app elevated.

## Build

Requirements: Rust (stable toolchain). For the app also Node.js and npm.

Daemon (run from `port/`):

```bash
cargo build --release -p rat-daemon
```

The binary is `target/release/rat-daemon` (`rat-daemon.exe` on Windows).

App (run from `port/app/`):

```bash
npm ci
npx tauri build
```

## Install

- Windows: [packaging/windows/install.md](packaging/windows/install.md)
- Linux: [packaging/linux/install.md](packaging/linux/install.md)

## Tests

From `port/`:

```bash
cargo test --workspace
```

The real-OS end-to-end suites (`e2e/windows`, `e2e/linux`) change the firewall, so they run in GitHub Actions
(`port-e2e-windows.yml`, `port-e2e-linux.yml`) and not as part of `cargo test`.

## Documentation

Crate documentation is in [docs/](docs/). Known limits and open problems: [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).
