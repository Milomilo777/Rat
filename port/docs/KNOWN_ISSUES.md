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
- **Firewall tool time limit (low).** netsh, PowerShell and nft are killed after 30 seconds. On Windows the kill
  does not reach processes the tool itself started, and a failed netsh add or delete reports no tool output.
- **Long paths (low).** Rule names embed the full path (`Rat:path:<path>`); very long paths may exceed netsh's
  name limit.
- **Ownership marker (low).** Cleanup removes every rule whose display name starts with `Rat:path:` /
  `Rat:port:`; rules are not tagged with a firewall group yet.
- **Shared-host list (low).** Whole-program blocks are refused for a fixed list of Windows hosts that work for
  many apps (`svchost.exe`, `dllhost.exe`, `RuntimeBroker.exe`, `taskhostw.exe`, `backgroundTaskHost.exe`,
  `sihost.exe`, `conhost.exe`, `rundll32.exe`, `WmiPrvSE.exe`); other such hosts are not on the list yet.
- **`cleanup()` keeps in-memory state (low).** After `cleanup()` the enforcer's `current` set still lists the
  removed rules until the next reconcile.
- **Silent disable (medium).** If Windows Defender Firewall is off, a profile is disabled, a third-party firewall
  replaced it, or group policy ignores local rules, rules are added but have no effect; the daemon does not
  report this yet.
- **Port blocks outlive the socket (medium).** A local port blocked for a denied app stays blocked until the next
  tick; a new allowed app that reuses the same ephemeral port can be blocked meanwhile (also seen on Linux, E2E L4).

## Daemon and IPC (`rat-daemon`)
- **Rule edits replace the whole list (medium).** The app reads the rules with `GetRules`, changes the list and
  sends it back with `SetRules`; a rule the daemon creates in between (for example from an alert answer) can be
  overwritten. Incremental add/remove messages would fix this.
- **IPC access (medium, Windows).** The named pipe admits only elevated administrators and SYSTEM, so the desktop
  app must run elevated.
- **No installer or uninstaller (medium).** The service is installed by hand (see the install guides). Rules and
  firewall entries outlive the service unless `rat-daemon --cleanup` is run before removing it.
- **Network and verbatim paths (low).** Rule paths on a network share (`\\host\share\app.exe`) and paths that
  start with `\\?\` or `\\.\` are refused; programs on a network share cannot be blocked by path.
- **Busy daemon (low).** At most 16 client commands wait for the daemon; queued `SetRules` lists are merged into
  the newest one. When the queue is full the client gets an Error reply and the command (also an alert answer)
  is dropped; the desktop app does not retry it yet.
- **Pipe identity (low).** The GUI does not verify that the process behind the pipe is the Rat service; a process
  that creates the pipe before the service starts could answer the GUI. (The daemon retries for 3 s when the pipe
  is still owned by a previous instance, then exits with an error.)
- **First tick (low).** If the first connection sample fails, static rules are enforced only after a later
  successful sample or a GUI command.
- **Read-back order (low).** Paths read back from existing firewall rules at startup are not sorted/deduplicated.
- **Untested hardening (low).** The pause after a failed accept is tested on its own helper, not on a real accept
  error (none can be provoked); the Unix peer check relies on platform tests.

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
- The app gets the current rules from the daemon (`GetRules`) and sends the whole list back with SetRules, so it
  never reads the rules file itself. The IPC line limit for one client message is 64 KiB (65536 bytes): a rule
  update larger than that (a few hundred rules) is refused by the app with "too many rules for one update:
  N bytes, limit 65536" and nothing is sent. The limit was not raised on purpose; a chunked update is not built.
- The app waits for the write of a rule change or an alert answer to the daemon, not for the daemon to apply it.
  A closed alert window is reopened with the next snapshot until the alert is answered.
- The rule form takes a full program path; a bare name such as `firefox` does not match.
- The alert window can re-render while the pointer is over it, so a click may land on an alert that was just
  replaced (low). The daemon rejects an answer for an alert that no longer exists, so no wrong rule is created.
- A rule's `approved` and `enabled` flags are not shown in the app (low); the app keeps their values when it sends
  the rules back.
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
