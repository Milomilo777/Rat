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
- **Rules directory permissions (high, Windows).** The daemon does not create or lock down
  `C:\ProgramData\rat`; the installer must create it with an Administrators/SYSTEM-only ACL.
- **UNC paths (medium).** A rule path like `\\host\share\app.exe` is canonicalised by the SYSTEM service, which
  contacts that host.
- **Back pressure (medium).** The command channel is unbounded and each `SetRules` runs a full enforce; a client can
  queue a lot of work.
- **Pipe start-up (low).** If another process already owns `\\.\pipe\rat`, the daemon exits; there is no retry, and
  the GUI does not verify the server's identity.
- **Slow clients (low).** A client that never reads its replies can hold one of the four client slots.
- **Linux socket group (low).** The socket is not `chgrp`'d to a `rat` group; only root and the daemon user can
  connect.
- **Alerts (low).** A GUI that connects after an alert became active does not receive that alert; an alert that is
  re-queued with the same key may not be broadcast again.
- **First tick (low).** If the first connection sample fails, static rules are enforced only after a later
  successful sample or a GUI command.
- **Read-back order (low).** Paths read back from existing firewall rules at startup are not sorted/deduplicated.
- **Untested hardening.** Task-death exit + backoff and reply-then-close on oversized messages are implemented but
  have no test that fails when they are removed; the Unix peer check relies on platform tests.

## Monitoring (`rat-monitor-*`)
- **Linux byte counters (medium).** Per-connection byte counts on Linux are incomplete (E2E L1).
- **Shared sockets and PID reuse (low).** A socket shared by several processes is attributed to the lowest PID;
  PID reuse and sockets without an inode are not handled yet.
- **Windows process user (low).** The user of a process is not filled in on Windows yet.

## Desktop app (`port/app`)
- Differences from the macOS app: the sidebar groups by service instead of by app; the inspector shows all
  connections instead of the selected one; port 53 shows the IANA name `domain` instead of `DNS`; the world map
  is empty with the demo data.
- Debug builds open a console window next to the app (release builds do not).

## Testing
- Real-OS end-to-end tests run in GitHub Actions on separate branches and are still being completed: on Linux
  three of six scenarios pass (the client-connection-limit scenario may be a harness issue); on Windows four of six
  pass and the named-pipe and IPC scenarios do not yet speak the current protocol.
