# Known issues (Windows/Linux port, first release)

This is the first release of the Windows and Linux port. The items below are known and planned for later
versions. Severity is our own estimate. Reports and fixes are welcome.

## Enforcement (`rat-enforcer`)
- **Outbound only for app rules (medium).** Per-program rules block outbound traffic; inbound connections to a
  listening blocked app are only blocked when a local-port rule covers them (port rules block both directions).
- **Apps that change their executable (medium).** Rules match one executable path. Electron/Chromium helper
  executables, packaged (Store/UWP) apps and auto-updaters that install into versioned folders (`app-1.2.3\`) are
  not followed; after an update the block may stop applying. A renamed or copied executable is not blocked.
- **Short gap on re-add (low).** Re-adding a rule deletes the old one first, so there is a brief window without a
  block while netsh runs.
- **No timeouts on netsh / PowerShell / nft child processes (medium).** A hung tool stalls the daemon's pipeline
  and, at startup, the read-back before the IPC server starts.
- **Long paths (low).** Rule names embed the full path (`Rat:path:<path>`); very long paths may exceed netsh's
  name limit.
- **Ownership marker (low).** Cleanup removes every rule whose display name starts with `Rat:path:` /
  `Rat:port:`; rules are not tagged with a firewall group yet.
- **Shared-host list (medium).** Only `svchost.exe` is treated as a shared system host; other shared hosts
  (`dllhost.exe`, `RuntimeBroker.exe`, ...) are not refused.
- **`cleanup()` keeps in-memory state (low).** After `cleanup()` the enforcer's `current` set still lists the
  removed rules until the next reconcile.
- **Silent disable (medium).** If Windows Defender Firewall is off, a profile is disabled, a third-party firewall
  replaced it, or group policy ignores local rules, rules are added but have no effect; the daemon does not
  report this yet.
- **Port blocks outlive the socket (medium).** A local port blocked for a denied app stays blocked until the next
  tick; a new allowed app that reuses the same ephemeral port can be blocked meanwhile (also seen on Linux, E2E L4).

## Daemon and IPC (`rat-daemon`)
- **IPC access (medium, Windows).** The named pipe admits only elevated administrators and SYSTEM, so the desktop
  app must run elevated.
- **No installer or uninstaller (medium).** The service is installed by hand (see the install guides). Rules and
  firewall entries outlive the service unless `rat-daemon --cleanup` is run before removing it.
- **UNC paths (medium).** A rule path like `\\host\share\app.exe` is canonicalised by the SYSTEM service, which
  contacts that host.
- **Back pressure (medium).** The command channel is unbounded and each `SetRules` runs a full enforce; a client can
  queue a lot of work.
- **Pipe start-up (low).** If another process already owns `\\.\pipe\rat`, the daemon exits; there is no retry, and
  the GUI does not verify the server's identity.
- **Slow clients (low).** A client that never reads its replies can hold one of the four client slots.
- **Alerts (low).** A GUI that connects after an alert became active does not receive that alert; an alert that is
  re-queued with the same key may not be broadcast again.
- **First tick (low).** If the first connection sample fails, static rules are enforced only after a later
  successful sample or a GUI command.
- **Read-back order (low).** Paths read back from existing firewall rules at startup are not sorted/deduplicated.
- **Untested hardening.** Task-death exit + backoff and reply-then-close on oversized messages are implemented but
  have no test that fails when they are removed; the Unix peer check relies on platform tests.

## Monitoring (`rat-monitor-*`)
- **Linux byte counters (low).** Per-connection byte counts on Linux come from the kernel's `sock_diag` and
  cover TCP only; UDP connections show no byte counts.
- **Linux blocks by local port (medium).** Linux enforcement works on local ports, not on programs, and reacts
  after each connection sample (every 1.5 s), so a new connection can get through briefly.
- **Shared sockets and PID reuse (low).** A socket shared by several processes is attributed to the lowest PID;
  PID reuse and sockets without an inode are not handled yet.
- **Windows process user (low).** The user of a process is not filled in on Windows yet.

## Desktop app (`port/app`)
- Differences from the macOS app: the sidebar groups by service instead of by app; the inspector shows all
  connections instead of the selected one; port 53 shows the IANA name `domain` instead of `DNS`; the world map
  is empty with the demo data.
- Debug builds open a console window next to the app (release builds do not). Debug builds also lack the
  administrator manifest, so on Windows run them from an elevated terminal to reach the daemon.
- The app reads the current rules from the daemon's rules file (the protocol has no "get rules" message yet) and
  sends the whole list back with SetRules; temporary rules (once / until quit) are not in that file and are
  dropped when the app changes the rules.
- The rule form takes a full program path; a bare name such as `firefox` does not match.
- The app's connection to a real daemon is covered by unit tests against an in-memory daemon, not yet by the
  real-OS end-to-end suites; the browser-based accessibility (axe) checks were not re-run for the new rule form
  and banner.

## Testing
- Real-OS end-to-end tests run in GitHub Actions: on Windows scenarios W1-W6 pass, on Linux scenarios L1-L6 pass,
  and the macOS app tests pass.
- There is no end-to-end test with a program path that contains spaces (for example `C:\Program Files\...`).
- Re-applying the protected access list to an existing rules directory is not covered by an automated test.
- A crash during a rules save can leave a stray, randomly named `.tmp` file next to `rules.json`; it is not
  cleaned up automatically.
