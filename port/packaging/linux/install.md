# Installing Rat Daemon on Linux

1. Build the daemon:
   ```bash
   cargo build --release -p rat-daemon
   ```

2. Copy the binary to your path:
   ```bash
   sudo cp target/release/rat-daemon /usr/local/bin/
   ```

3. Install the systemd service:
   ```bash
   sudo cp port/packaging/linux/rat-daemon.service /etc/systemd/system/
   ```

4. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now rat-daemon.service
   ```
