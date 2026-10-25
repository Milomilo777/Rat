# Installing Rat Daemon on Linux

There is no package yet. Run every command from the `port/` directory of the repository.

1. Build:
   ```bash
   cargo build --release -p rat-daemon
   ```

2. Install the binary:
   ```bash
   sudo install -m 0755 target/release/rat-daemon /usr/local/bin/rat-daemon
   ```

3. Create the `rat` group. Members of this group may talk to the daemon; root always may.
   ```bash
   sudo groupadd --system rat
   sudo usermod -aG rat <user>
   ```
   The user must log in again for the new group to apply.

4. Create the rules directory. The daemon saves its rules in `/etc/rat/rules.json`. The unit file in this
   directory does not create `/etc/rat`, so create it yourself (mode 0750, owner root, group rat):
   ```bash
   sudo install -d -m 0750 -o root -g rat /etc/rat
   ```
   If this directory is missing the daemon still runs, but it cannot save rules.

5. Install the systemd unit:
   ```bash
   sudo cp packaging/linux/rat-daemon.service /etc/systemd/system/
   ```

6. Enable and start:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now rat-daemon.service
   ```

The unit creates `/run/rat` (mode 0750) with systemd's `RuntimeDirectory=`. The daemon listens on the Unix socket
`/run/rat/rat.sock` (mode 0660) and accepts root, its own user and members of the `rat` group. The group name can
be changed with the `RAT_IPC_GROUP` environment variable.

## Uninstall

```bash
sudo systemctl disable --now rat-daemon.service
sudo /usr/local/bin/rat-daemon --cleanup
sudo rm /etc/systemd/system/rat-daemon.service /usr/local/bin/rat-daemon
sudo systemctl daemon-reload
```

`rat-daemon --cleanup` removes the firewall table the daemon created. You can do the same by hand with
`sudo nft delete table inet rat`. The saved rules in `/etc/rat` are not removed; delete that directory yourself if
you want them gone.
