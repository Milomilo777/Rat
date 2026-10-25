# Installing Rat Daemon on Windows

There is no installer yet. The daemon is installed by hand as a Windows service. Use an elevated
(Administrator) PowerShell for every step. Run the build from `port/`.

## Install

1. Build:
   ```powershell
   cargo build --release -p rat-daemon
   ```

2. Copy the binary to a folder that standard users cannot write to:
   ```powershell
   New-Item -ItemType Directory -Force "C:\Program Files\Rat"
   Copy-Item target\release\rat-daemon.exe "C:\Program Files\Rat\rat-daemon.exe"
   ```
   The service runs as `LocalSystem`. If a user could replace the executable, that user would get SYSTEM rights.
   `C:\Program Files` is writable only by administrators by default.

3. Create the service. The `binPath` value must be quoted, because the path contains a space. Without quotes
   Windows may try to run `C:\Program.exe` first (the "unquoted service path" privilege escalation). Note the
   space after each `=`; `sc.exe` requires it.
   ```powershell
   sc.exe create RatDaemon binPath= "\"C:\Program Files\Rat\rat-daemon.exe\"" start= auto obj= LocalSystem
   ```

4. Start it:
   ```powershell
   sc.exe start RatDaemon
   ```
   Stop it with `sc.exe stop RatDaemon`. Check it with `sc.exe query RatDaemon`.

The Windows end-to-end suite (`port/e2e/windows`) uses the same service name, `RatDaemon`.

## Where data lives

- Rules: `C:\ProgramData\rat\rules.json`. The daemon creates the folder at start-up with a protected access list
  (SYSTEM and Administrators only). If the folder already exists and is not owned by SYSTEM or Administrators,
  or is a junction, the daemon does not use it: it starts with no saved rules and rules are not saved. If the
  existing folder is owned by SYSTEM or Administrators, the daemon re-applies the same protected access list to it.
- IPC endpoint: the named pipe `\\.\pipe\rat`. Only elevated administrators and SYSTEM may connect, so the desktop
  app must run elevated.
- Firewall rules created by the daemon have display names starting with `Rat:path:` (per program) or
  `Rat:port:` (local port).

## Uninstall

1. Stop the service:
   ```powershell
   sc.exe stop RatDaemon
   ```
2. Remove every firewall rule the daemon created:
   ```powershell
   & "C:\Program Files\Rat\rat-daemon.exe" --cleanup
   ```
3. Delete the service:
   ```powershell
   sc.exe delete RatDaemon
   ```
4. Optionally delete `C:\Program Files\Rat` and `C:\ProgramData\rat` (the saved rules).

If you delete the service without step 2, the `Rat:` firewall rules stay in place and keep blocking. You can still
run `rat-daemon.exe --cleanup` afterwards.
