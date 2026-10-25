#!/usr/bin/env python3
"""Real-OS end-to-end tests of the Rat Linux port (requirements L1-L6).

Runs as root on a disposable CI VM. Every system command is checked, every wait
has a timeout, every check prints what it saw. A requirement ends as:
  PASS          every product check held
  FAIL-PRODUCT  a product check failed (the check text + evidence lines say which)
  FAIL-HARNESS  setup or a control check failed: the result says nothing about the product
  NOT RUN       a prerequisite was missing (reason given)
Usage: e2e.py run | e2e.py ipc-probe   (ipc-probe is run as other users)
"""
import grp
import json
import os
import random
import re
import select
import shutil
import socket
import subprocess
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = "/opt/rat-e2e"
OUT = os.environ.get("E2E_OUT", "/tmp/rat-e2e-out")
BIN = os.environ.get("E2E_BIN_DIR", os.path.join(HERE, "target", "release"))
DAEMON_BIN = os.environ.get("E2E_DAEMON_BIN", "")
UNIT_SRC = os.path.normpath(os.path.join(HERE, "..", "..", "packaging", "linux", "rat-daemon.service"))
SOCK = "/run/rat/rat.sock"
NS = "ratsrv"
HOST_IP = "203.0.113.1"
SRV_IP = "203.0.113.9"
MIB = 1024 * 1024
TIMEOUT_ERRNOS = {11, 110, 115}  # EAGAIN / ETIMEDOUT / EINPROGRESS: a dropped SYN
TICK = 1.5  # daemon sampling interval (docs/rat-daemon.md)

LOG = None


def log(msg):
    line = "%s %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    if LOG:
        LOG.write(line + "\n")
        LOG.flush()


class Harness(Exception):
    """Setup problem or failed control: says nothing about the product."""


class NotRun(Exception):
    pass


class Req:
    def __init__(self, rid, title):
        self.id, self.title = rid, title
        self.checks = []
        self.status = "?"
        self.reason = ""

    def _add(self, kind, name, ok, detail):
        self.checks.append({"kind": kind, "name": name, "ok": bool(ok), "detail": detail})
        log("[%s] %s %s: %s -- %s" % (self.id, kind.upper(), "PASS" if ok else "FAIL", name, detail))

    def check(self, name, ok, detail=""):
        self._add("check", name, ok, detail)
        return ok

    def info(self, name, detail):
        self._add("info", name, True, detail)

    def control(self, name, ok, detail=""):
        self._add("control", name, ok, detail)
        if not ok:
            raise Harness("control failed: %s (%s)" % (name, detail))


# ---------------------------------------------------------------- commands

def sh(cmd, check=True, timeout=30, env=None, quiet=False, cwd=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd)
    except subprocess.TimeoutExpired:
        raise Harness("timeout after %ss: %s" % (timeout, " ".join(cmd)))
    except FileNotFoundError as e:
        raise Harness("command not found: %s (%s)" % (cmd[0], e))
    msg = "$ %s -> rc=%d" % (" ".join(cmd), r.returncode)
    if not quiet:
        if r.stdout.strip():
            msg += "\n    stdout: " + r.stdout.strip()[:500].replace("\n", "\n    ")
        if r.stderr.strip():
            msg += "\n    stderr: " + r.stderr.strip()[:500].replace("\n", "\n    ")
    log(msg)
    if check and r.returncode != 0:
        raise Harness("command failed rc=%d: %s: %s" % (r.returncode, " ".join(cmd), r.stderr.strip()[:300]))
    return r


PROCS = []


def spawn(cmd):
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, bufsize=0)
    PROCS.append(p)
    return p


def read_line(p, timeout):
    end = time.time() + timeout
    buf = b""
    fd = p.stdout.fileno()
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], max(0.0, end - time.time()))
        if not r:
            break
        ch = os.read(fd, 1)
        if not ch:
            break
        if ch == b"\n":
            return buf.decode(errors="replace")
        buf += ch
    return None


def stop_proc(p):
    # Only Popen objects this script started.
    if p.poll() is None:
        p.kill()
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def stop_all_procs():
    for p in PROCS:
        stop_proc(p)
    PROCS.clear()


def wait_until(pred, timeout, interval=0.25):
    end = time.time() + timeout
    while True:
        v = pred()
        if v:
            return v
        if time.time() >= end:
            return None
        time.sleep(interval)


def free_port(lo, hi):
    for _ in range(200):
        p = random.randint(lo, hi)
        s = socket.socket()
        try:
            s.bind(("0.0.0.0", p))
            return p
        except OSError:
            pass
        finally:
            s.close()
    raise Harness("no free port in %d-%d" % (lo, hi))


# ---------------------------------------------------------------- fixtures

def test_client_bin():
    p = os.path.join(BIN, "test-client")
    if not os.path.isfile(p):
        raise Harness("missing helper binary %s" % p)
    return p


def make_app(name):
    """A distinct executable at a unique path (copy of the test client)."""
    os.makedirs(WORK, mode=0o755, exist_ok=True)
    dst = os.path.join(WORK, name)
    shutil.copy2(test_client_bin(), dst)
    os.chmod(dst, 0o755)
    return os.path.realpath(dst)


class Client:
    def __init__(self, exe, host, port, bind=0, send=0, hold=600000, wait_go=False):
        cmd = [exe, "connect", host, str(port), "--hold", str(hold)]
        if bind:
            cmd += ["--bind", str(bind)]
        if send:
            cmd += ["--send", str(send)]
        if wait_go:
            cmd += ["--wait-go"]
        self.exe = exe
        self.p = spawn(cmd)
        self.local = None
        self.err = None
        self.errno = None
        line = read_line(self.p, 8)
        if line and line.startswith("LOCAL "):
            self.local = int(line.split()[1])
        else:
            self.err = line if line else "no output rc=%s" % self.p.poll()
            m = re.search(r"errno=(\d+)", self.err or "")
            self.errno = int(m.group(1)) if m else None

    @property
    def connected(self):
        return self.local is not None

    def desc(self):
        return "connected local=%s pid=%d" % (self.local, self.p.pid) if self.connected else "NOT connected: %s" % self.err

    def go(self):
        self.p.stdin.write(b"GO\n")
        self.p.stdin.flush()

    def stop(self):
        stop_proc(self.p)


def start_server(ns=False):
    ip = SRV_IP if ns else "127.0.0.1"
    port = free_port(30000, 32000)
    cmd = [test_client_bin(), "serve", ip, str(port)]
    if ns:
        cmd = ["ip", "netns", "exec", NS] + cmd
    p = spawn(cmd)
    line = read_line(p, 8)
    if not (line and line.startswith("LISTENING")):
        raise Harness("server did not start: %r" % line)
    return port


def probe():
    r = subprocess.run([os.path.join(BIN, "monitor-probe")], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise Harness("monitor-probe rc=%d: %s" % (r.returncode, r.stderr.strip()[:300]))
    return json.loads(r.stdout)


def port_of(addr):
    return int(addr.rsplit(":", 1)[1])


def find_conn(conns, pid=None, local=None):
    for c in conns:
        if pid is not None and c["process"]["pid"] != pid:
            continue
        if local is not None and port_of(c["local"]) != local:
            continue
        return c
    return None


def nft_json_table():
    r = sh(["nft", "-j", "list", "table", "inet", "rat"], check=False, quiet=True)
    return json.loads(r.stdout) if r.returncode == 0 else None


def rat_ports():
    t = nft_json_table()
    if t is None:
        return None
    ports = set()
    for item in t["nftables"]:
        s = item.get("set")
        if s and s.get("name") == "rat_ports":
            for e in s.get("elem", []):
                if isinstance(e, int):
                    ports.add(e)
    return ports


def other_tables():
    """Every table except `inet rat`, with packet counters normalised."""
    out = sh(["nft", "list", "tables"], quiet=True).stdout
    snap = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[0] != "table":
            continue
        if parts[1] == "inet" and parts[2] == "rat":
            continue
        txt = sh(["nft", "list", "table", parts[1], parts[2]], quiet=True).stdout
        snap["%s %s" % (parts[1], parts[2])] = re.sub(r"packets \d+ bytes \d+", "packets N bytes N", txt)
    return snap


def ss_field(args, field, ns=False):
    cmd = ["ss", "-tinH"] + args
    if ns:
        cmd = ["ip", "netns", "exec", NS] + cmd
    r = sh(cmd, check=False, quiet=True)
    if r.returncode != 0:
        return None, r.stderr.strip()
    m = re.search(field + r":(\d+)", r.stdout)
    return (int(m.group(1)) if m else 0), r.stdout.strip().replace("\n", " | ")[:300]


class Net:
    """veth pair + namespace holding a non-loopback 'remote' (documentation range)."""
    up = False

    def setup(self):
        sh(["ip", "netns", "add", NS])
        self.up = True
        sh(["ip", "link", "add", "rat-h", "type", "veth", "peer", "name", "rat-s"])
        sh(["ip", "link", "set", "rat-s", "netns", NS])
        sh(["ip", "addr", "add", HOST_IP + "/24", "dev", "rat-h"])
        sh(["ip", "link", "set", "rat-h", "up"])
        sh(["ip", "netns", "exec", NS, "ip", "addr", "add", SRV_IP + "/24", "dev", "rat-s"])
        sh(["ip", "netns", "exec", NS, "ip", "link", "set", "rat-s", "up"])
        sh(["ip", "netns", "exec", NS, "ip", "link", "set", "lo", "up"])
        sh(["ping", "-c", "1", "-W", "3", SRV_IP])

    def teardown(self):
        if self.up:
            sh(["ip", "netns", "del", NS], check=False)
            sh(["ip", "link", "del", "rat-h"], check=False, quiet=True)
            self.up = False


class Ipc:
    EOF = object()

    def __init__(self):
        self.s = socket.socket(socket.AF_UNIX)
        self.s.settimeout(5)
        self.s.connect(SOCK)
        self.buf = b""

    def send(self, obj):
        data = obj if isinstance(obj, bytes) else (json.dumps(obj) + "\n").encode()
        self.s.sendall(data)

    def recv_line(self, timeout):
        end = time.time() + timeout
        while b"\n" not in self.buf:
            left = end - time.time()
            if left <= 0:
                return None
            r, _, _ = select.select([self.s], [], [], left)
            if not r:
                return None
            try:
                d = self.s.recv(1 << 20)
            except ConnectionResetError:
                return Ipc.EOF
            if not d:
                return Ipc.EOF
            self.buf += d
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode(errors="replace")

    def wait_for(self, pred, timeout):
        end = time.time() + timeout
        while time.time() < end:
            line = self.recv_line(max(0.1, end - time.time()))
            if line is None or line is Ipc.EOF:
                return line
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if pred(msg):
                return msg
        return None

    def hello(self):
        self.send({"Hello": {"protocol_version": 1}})
        m = self.wait_for(lambda m: "HelloAck" in m or "Error" in m, 5)
        return isinstance(m, dict) and "HelloAck" in m

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def rule_deny(path):
    return {"verdict": "deny", "processPath": path, "lifetime": "untilQuit"}


def set_rules(ipc, rules):
    ipc.send({"SetRules": {"rules": rules}})


class Daemon:
    installed = False
    running = False

    def install(self):
        if not DAEMON_BIN or not os.path.isfile(DAEMON_BIN):
            raise Harness("E2E_DAEMON_BIN not set or missing: %r" % DAEMON_BIN)
        sh(["groupadd", "-f", "rat"])
        sh(["install", "-m", "0755", DAEMON_BIN, "/usr/local/bin/rat-daemon"])
        sh(["install", "-m", "0644", UNIT_SRC, "/etc/systemd/system/rat-daemon.service"])
        os.makedirs("/etc/rat", exist_ok=True)  # the installer's job (docs/rat-daemon.md)
        sh(["systemctl", "daemon-reload"])
        self.installed = True

    def journal(self):
        r = sh(["journalctl", "-u", "rat-daemon", "--no-pager", "-n", "40", "-o", "cat"], check=False, quiet=True)
        log("journal rat-daemon:\n    " + r.stdout.strip().replace("\n", "\n    "))
        return r.stdout

    def start(self):
        r = sh(["systemctl", "start", "rat-daemon"], check=False, timeout=40)

        def ready():
            if not os.path.exists(SOCK):
                return False
            try:
                ipc = Ipc()
            except OSError:
                return False
            try:
                return ipc.hello()
            finally:
                ipc.close()

        ok = bool(wait_until(ready, 15))
        self.running = ok
        if not ok:
            log("daemon not ready (start rc=%d)" % r.returncode)
            sh(["systemctl", "status", "rat-daemon", "--no-pager"], check=False)
            self.journal()
        return ok

    def main_pid(self):
        r = sh(["systemctl", "show", "-p", "MainPID", "--value", "rat-daemon"], check=False, quiet=True)
        try:
            return int(r.stdout.strip())
        except ValueError:
            return 0

    def remove(self):
        if self.installed:
            sh(["systemctl", "stop", "rat-daemon"], check=False, timeout=40)
            sh(["systemctl", "reset-failed", "rat-daemon"], check=False, quiet=True)
            shutil.rmtree("/etc/systemd/system/rat-daemon.service.d", ignore_errors=True)
            for f in ("/etc/systemd/system/rat-daemon.service", "/usr/local/bin/rat-daemon"):
                if os.path.exists(f):
                    os.remove(f)
            sh(["systemctl", "daemon-reload"], check=False)
            self.installed = False
            self.running = False


def reset_rules():
    """Drop all rules and wait for the deny set to empty (isolation between tests)."""
    if not os.path.exists(SOCK):
        return
    try:
        ipc = Ipc()
        if ipc.hello():
            set_rules(ipc, [])
            wait_until(lambda: not rat_ports(), 10)
        ipc.close()
    except OSError:
        pass


# ---------------------------------------------------------------- L1

def l1(R):
    server = start_server()
    app = make_app("l1_client")
    c = Client(app, "127.0.0.1", server, send=MIB)
    R.control("client connected", c.connected, c.desc())
    sent = read_line(c.p, 10)
    R.control("client sent 1 MiB", bool(sent and sent.startswith("SENT")), repr(sent))

    found = None
    best = None
    end = time.time() + 12
    while time.time() < end:
        conn = find_conn(probe(), pid=c.p.pid, local=c.local)
        if conn:
            found = conn
            best = conn.get("bytes_out")
            if best is not None and best >= MIB:
                break
        time.sleep(0.3)
    R.check("sample() lists the client connection (pid + local port)", found is not None,
            "pid=%d local=%d -> %s" % (c.p.pid, c.local, json.dumps(found)[:300] if found else "absent"))
    if found:
        R.check("executable path is the client's unique path", found["process"]["exe"] == app,
                "exe=%r expected=%r" % (found["process"]["exe"], app))
        R.check("remote is the server", found["remote"] == "127.0.0.1:%d" % server, "remote=%r" % found["remote"])
        ok = best is not None and best >= MIB
        kernel, raw = ss_field(["state", "established", "( sport = :%d )" % c.local], "bytes_acked")
        detail = "monitor bytes_out=%r (needs >= %d); kernel ss bytes_acked=%r [%s]" % (best, MIB, kernel, raw)
        if not ok and (kernel is None or kernel < MIB):
            raise Harness("kernel itself shows < 1 MiB, harness did not send it: " + detail)
        R.check("byte counter >= 1 MiB after sending 1 MiB", ok, detail)

    # negative control: a connection that sent nothing must not look like 1 MiB
    idle = Client(app, "127.0.0.1", server)
    R.control("idle client connected", idle.connected, idle.desc())
    time.sleep(1)
    conn = find_conn(probe(), pid=idle.p.pid, local=idle.local)
    bo = conn.get("bytes_out") if conn else None
    R.control("idle connection does not report >= 1 MiB", conn is not None and (bo is None or bo < MIB),
              "idle bytes_out=%r" % bo)


# ---------------------------------------------------------------- L2

def l2(R):
    ctl = os.path.join(BIN, "enforcer-ctl")
    R.control("no inet rat table before", nft_json_table() is None, "table absent at start")
    before = other_tables()
    R.info("tables present before", ", ".join(sorted(before)) or "(none)")
    app = make_app("l2_client")
    servers = [start_server() for _ in range(4)]
    F = free_port(20000, 29000)
    G = free_port(20000, 29000)
    while G == F:
        G = free_port(20000, 29000)

    # negative control: dry run enforces nothing
    env = dict(os.environ, RAT_DRY_RUN="1")
    r = sh([ctl, "apply", str(F)], check=False, env=env)
    R.control("dry-run apply exits 0 and creates no table", r.returncode == 0 and nft_json_table() is None,
              "rc=%d" % r.returncode)
    c0 = Client(app, "127.0.0.1", servers[0], bind=F, hold=500)
    R.control("under dry run, port %d still connects" % F, c0.connected, c0.desc())

    r = sh([ctl, "apply", str(F)], check=False)
    if not R.check("Enforcer::apply exit code 0", r.returncode == 0, "rc=%d %s" % (r.returncode, r.stderr.strip()[:200])):
        return
    t = nft_json_table()
    if not R.check("table inet rat exists after apply", t is not None, "nft -j list table inet rat"):
        return
    ports = rat_ports()
    R.check("set rat_ports holds exactly the denied port", ports == {F}, "ports=%s wanted={%d}" % (sorted(ports), F))
    chains = {i["chain"]["name"] for i in t["nftables"] if "chain" in i}
    rules = [i for i in t["nftables"] if "rule" in i]
    R.check("chains drop_out and drop_in with 4 drop rules",
            {"drop_out", "drop_in"} <= chains and len(rules) == 4 and all('"drop"' in json.dumps(x) for x in rules),
            "chains=%s rules=%d" % (sorted(chains), len(rules)))

    blocked = Client(app, "127.0.0.1", servers[1], bind=F, hold=500)
    R.check("traffic from the denied port is dropped (SYN timeout)",
            not blocked.connected and blocked.errno in TIMEOUT_ERRNOS, blocked.desc())
    other = Client(app, "127.0.0.1", servers[2], bind=G, hold=500)
    R.check("traffic from another fixed port still flows", other.connected, "port %d: %s" % (G, other.desc()))
    eph = Client(app, "127.0.0.1", servers[3], hold=500)
    R.check("traffic from an ephemeral port still flows", eph.connected, eph.desc())

    r = sh([ctl, "cleanup"], check=False)
    R.check("cleanup() exit code 0", r.returncode == 0, "rc=%d %s" % (r.returncode, r.stderr.strip()[:200]))
    R.check("table inet rat removed by cleanup", nft_json_table() is None, "nft list table inet rat fails")
    after = other_tables()
    diff = [k for k in set(before) | set(after) if before.get(k) != after.get(k)]
    R.check("every other table is unchanged (counters normalised)", not diff, "changed tables: %s" % (diff or "none"))


# ---------------------------------------------------------------- L3

def srv_received(server_port, client_port):
    v, raw = ss_field(["state", "established", "( sport = :%d and dport = :%d )" % (server_port, client_port)],
                      "bytes_received", ns=True)
    if v is None or not raw:
        raise Harness("server socket for client port %d not found: %s" % (client_port, raw))
    return v, raw


def l3(R, d):
    server = start_server(ns=True)
    a, b = make_app("app_a"), make_app("app_b")
    ca = Client(a, SRV_IP, server, send=MIB, wait_go=True)
    cb = Client(b, SRV_IP, server, send=MIB, wait_go=True)
    R.control("app A reaches the remote", ca.connected, ca.desc())
    R.control("app B reaches the remote", cb.connected, cb.desc())
    ipc = Ipc()
    R.control("IPC handshake", ipc.hello(), "HelloAck")
    set_rules(ipc, [rule_deny(a)])
    got = wait_until(lambda: ca.local in (rat_ports() or set()), 12)
    R.check("deny A: A's local port appears in the nft set", bool(got),
            "A port=%d B port=%d set=%s" % (ca.local, cb.local, sorted(rat_ports() or [])))
    time.sleep(2 * TICK + 0.5)
    ports = rat_ports() or set()
    R.check("B's local port is not in the nft set", cb.local not in ports, "set=%s" % sorted(ports))
    ca.go()
    cb.go()
    time.sleep(4)
    ra, rawa = srv_received(server, ca.local)
    rb, rawb = srv_received(server, cb.local)
    R.check("A's data is dropped (server received < 64 KiB of 1 MiB)", ra < 65536, "A: %d bytes [%s]" % (ra, rawa))
    R.check("B's data flows (server received >= 1 MiB)", rb >= MIB, "B: %d bytes [%s]" % (rb, rawb))
    ipc.close()


# ---------------------------------------------------------------- L4

def l4(R, d):
    # Part 1: attribution of 100 short-lived processes while a sampler runs.
    server = start_server()
    app = make_app("l4_short")
    results = []
    seen = {}
    clients = []
    import threading
    stop = threading.Event()
    errors = []

    def sampler():
        while not stop.is_set():
            try:
                for c in probe():
                    if c["remote"] and port_of(c["remote"]) == server:
                        seen[(c["process"]["pid"], port_of(c["local"]))] = c["process"]["exe"]
            except Exception as e:  # recorded, checked below
                errors.append(str(e))
                return

    th = threading.Thread(target=sampler)
    th.start()
    for _ in range(100):
        clients.append(Client(app, "127.0.0.1", server, hold=700))
        time.sleep(0.03)
    time.sleep(1.2)
    stop.set()
    th.join(timeout=30)
    R.control("sampler ran without error", not errors, "; ".join(errors) or "ok")
    made = [c for c in clients if c.connected]
    R.control("all 100 short clients connected", len(made) == 100, "%d/100 connected" % len(made))
    hits = sum(1 for c in made if seen.get((c.p.pid, c.local)) == app)
    wrong = [(k, v) for k, v in seen.items() if v != app]
    R.check("attribution hit rate >= 95% with the right executable", hits >= 95,
            "hit rate %d/100; wrong exe: %s" % (hits, wrong[:3] or "none"))

    # Part 2: port reuse, through the daemon (needs a non-loopback remote).
    if not d.running:
        raise NotRun("daemon not running; port-reuse part needs it")
    srv_a, srv_b = start_server(ns=True), start_server(ns=True)
    a, b = make_app("l4_denied"), make_app("l4_allowed")
    ipc = Ipc()
    R.control("IPC handshake", ipc.hello(), "HelloAck")
    set_rules(ipc, [rule_deny(a)])
    time.sleep(0.5)
    a1 = Client(a, SRV_IP, srv_a)
    R.control("denied app connected", a1.connected, a1.desc())
    pa = a1.local
    R.control("daemon blocks the denied app's port", bool(wait_until(lambda: pa in (rat_ports() or set()), 12)),
              "port %d" % pa)
    stop_proc(a1.p)
    # immediate reuse by an allowed app: the documented window
    b1 = Client(b, SRV_IP, srv_b, bind=pa, hold=500)
    still = pa in (rat_ports() or set())
    R.check("allowed app reusing the freed port right away is not blocked", b1.connected,
            "%s; port still in nft set at that moment: %s" % (b1.desc(), still))
    gone = wait_until(lambda: pa not in (rat_ports() or set()), 10)
    R.check("freed port leaves the nft set within 10 s (<= ~6 ticks)", bool(gone),
            "set=%s" % sorted(rat_ports() or []))
    srv_c = start_server(ns=True)
    b2 = Client(b, SRV_IP, srv_c, bind=pa, hold=500)
    R.check("after the set was rebuilt the allowed app on the same port connects", b2.connected, b2.desc())
    ipc.close()


# ---------------------------------------------------------------- L5

USERS = ["ratout", "ratsup", "ratpri"]


def ipc_probe_main():
    out = {"connect": None, "hello_ack": False}
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(4)
    try:
        s.connect(SOCK)
        out["connect"] = "ok"
        s.sendall(b'{"Hello":{"protocol_version":1}}\n')
        data = b""
        try:
            while b"\n" not in data:
                d = s.recv(65536)
                if not d:
                    break
                data += d
        except socket.timeout:
            pass
        out["hello_ack"] = b"HelloAck" in data
        out["reply"] = data[:120].decode(errors="replace")
    except PermissionError:
        out["connect"] = "EACCES"
    except OSError as e:
        out["connect"] = "error: %r" % (e,)
    print(json.dumps(out))


def run_as(user):
    r = sh(["runuser", "-u", user, "--", "python3", os.path.join(WORK, "e2e.py"), "ipc-probe"],
           check=False, cwd="/", timeout=30)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise Harness("ipc-probe as %s gave no JSON: rc=%d %s" % (user, r.returncode, r.stderr.strip()[:200]))


def l5(R, d):
    if not d.running:
        raise_status = "daemon did not start with the shipped unit (see journal in the log)"
        R.check("systemd unit starts the daemon and the socket answers Hello", False, raise_status)
        return
    R.check("systemd unit starts the daemon and the socket answers Hello", True,
            "MainPID=%d" % d.main_pid())
    st = os.stat(SOCK)
    group = grp.getgrgid(st.st_gid).gr_name
    R.check("socket mode is 0660", (st.st_mode & 0o777) == 0o660, "mode=%o" % (st.st_mode & 0o777))
    R.check("socket group is rat", group == "rat", "group=%s" % group)

    shutil.copy2(os.path.join(HERE, "e2e.py"), os.path.join(WORK, "e2e.py"))
    os.chmod(os.path.join(WORK, "e2e.py"), 0o755)
    sh(["useradd", "-M", "-N", "-s", "/usr/sbin/nologin", "ratout"])
    sh(["useradd", "-M", "-N", "-s", "/usr/sbin/nologin", "-G", "rat", "ratsup"])
    sh(["useradd", "-M", "-g", "rat", "-s", "/usr/sbin/nologin", "ratpri"])
    out = run_as("ratout")
    R.check("user not in group rat cannot connect (EACCES)", out["connect"] == "EACCES", json.dumps(out))
    out = run_as("ratpri")
    R.check("user with primary group rat connects and gets HelloAck", out["connect"] == "ok" and out["hello_ack"],
            json.dumps(out))
    out = run_as("ratsup")
    R.check("user with SUPPLEMENTARY group rat connects and gets HelloAck (usermod -aG rat)",
            out["connect"] == "ok" and out["hello_ack"], json.dumps(out))

    # client limit (4) and oversized line (64 KiB)
    held = []
    try:
        for i in range(4):
            c = Ipc()
            R.control("client %d handshake" % (i + 1), c.hello(), "HelloAck")
            held.append(c)
        fifth = Ipc()
        fifth.send({"Hello": {"protocol_version": 1}})
        m = fifth.wait_for(lambda m: "HelloAck" in m, 4)
        R.check("5th concurrent client is refused (no HelloAck, connection dropped)",
                not (isinstance(m, dict) and "HelloAck" in m), "5th client got: %r" % (m if m is not Ipc.EOF else "EOF"))
        fifth.close()
        held.pop().close()
        ok = None
        for _ in range(8):
            retry = Ipc()
            if retry.hello():
                ok = True
                retry.close()
                break
            retry.close()
            time.sleep(0.5)
        R.control("after one slot is freed a new client is served", bool(ok), "slot released")
    finally:
        for c in held:
            c.close()

    big = Ipc()
    R.control("handshake before oversized line", big.hello(), "HelloAck")
    try:
        big.send(b"A" * 70000 + b"\n")
    except OSError:
        pass
    closed = False
    end = time.time() + 6
    while time.time() < end:
        line = big.recv_line(max(0.1, end - time.time()))
        if line is Ipc.EOF:
            closed = True
            break
    R.check("line > 64 KiB closes the connection", closed, "EOF seen: %s" % closed)
    big.close()
    sane = Ipc()
    R.control("daemon still serves after the oversized line", sane.hello(), "HelloAck")
    sane.close()

    # SIGKILL: phase 1 without restart proves ExecStopPost removes the table.
    server = start_server(ns=True)
    app = make_app("l5_victim")
    c = Client(app, SRV_IP, server)
    R.control("victim connected", c.connected, c.desc())
    ipc = Ipc()
    R.control("handshake", ipc.hello(), "HelloAck")
    set_rules(ipc, [rule_deny(app)])
    R.control("daemon created the deny rule in nft", bool(wait_until(lambda: c.local in (rat_ports() or set()), 12)),
              "port %d in set" % c.local)
    ipc.close()
    dropin = "/etc/systemd/system/rat-daemon.service.d"
    os.makedirs(dropin, exist_ok=True)
    with open(dropin + "/e2e.conf", "w") as f:
        f.write("[Service]\nRestart=no\n")
    sh(["systemctl", "daemon-reload"])
    sh(["systemctl", "restart", "rat-daemon"], timeout=40)
    R.control("daemon back up with Restart=no", d.start(), "ready")
    ipc = Ipc()
    ipc.hello()
    set_rules(ipc, [rule_deny(app)])
    R.control("deny rule enforced again", bool(wait_until(lambda: c.local in (rat_ports() or set()), 12)),
              "port %d" % c.local)
    ipc.close()
    sh(["systemctl", "kill", "-s", "KILL", "rat-daemon"])
    dead = wait_until(lambda: sh(["systemctl", "is-active", "rat-daemon"], check=False, quiet=True).stdout.strip() != "active", 10)
    R.control("daemon died on SIGKILL", bool(dead), "is-active != active")
    gone = wait_until(lambda: nft_json_table() is None, 8)
    R.check("kill -9 leaves no `inet rat` table (ExecStopPost ran)", bool(gone),
            "table present after kill: %s" % (not gone))
    # phase 2: restart policy
    shutil.rmtree(dropin, ignore_errors=True)
    sh(["systemctl", "daemon-reload"])
    sh(["systemctl", "reset-failed", "rat-daemon"], check=False)
    R.control("daemon started again with the shipped Restart policy", d.start(), "ready")
    pid1 = d.main_pid()
    ipc = Ipc()
    ipc.hello()
    set_rules(ipc, [rule_deny(app)])
    wait_until(lambda: c.local in (rat_ports() or set()), 12)
    ipc.close()
    sh(["systemctl", "kill", "-s", "KILL", "rat-daemon"])

    def restarted():
        p = d.main_pid()
        return p not in (0, pid1) and sh(["systemctl", "is-active", "rat-daemon"], check=False, quiet=True).stdout.strip() == "active"

    ok = wait_until(restarted, 20)
    R.check("systemd restarts the daemon after SIGKILL (new MainPID)", bool(ok), "old=%d new=%d" % (pid1, d.main_pid()))
    ready = wait_until(lambda: os.path.exists(SOCK) and Ipc().hello(), 10)
    R.check("restarted daemon answers Hello", bool(ready), "HelloAck")
    time.sleep(2 * TICK + 0.5)
    stale = c.local in (rat_ports() or set())
    R.check("restarted daemon does not re-apply the dead daemon's session rule", not stale,
            "victim port %d in set: %s" % (c.local, stale))


# ---------------------------------------------------------------- L6

def l6(R, d):
    if not d.running:
        raise NotRun("daemon not running")
    ipc = Ipc()
    R.check("Hello answered with HelloAck", ipc.hello(), "HelloAck")
    server = start_server(ns=True)
    lo_server = start_server()
    app = make_app("l6_remote")
    lo_app = make_app("l6_loopback")
    c = Client(app, SRV_IP, server)
    lc = Client(lo_app, "127.0.0.1", lo_server)
    R.control("remote client connected", c.connected, c.desc())
    R.control("loopback client connected", lc.connected, lc.desc())

    def has_client(m):
        if "Snapshot" not in m:
            return False
        return find_conn(m["Snapshot"]["connections"], pid=c.p.pid, local=c.local) is not None

    snap = ipc.wait_for(has_client, 10)
    R.check("Snapshot contains the real client connection (pid + port)", isinstance(snap, dict),
            "waited for pid=%d local=%d" % (c.p.pid, c.local))
    if isinstance(snap, dict):
        conn = find_conn(snap["Snapshot"]["connections"], pid=c.p.pid, local=c.local)
        R.check("Snapshot attributes the right executable", conn["process"]["exe"] == app,
                "exe=%r" % conn["process"]["exe"])
        R.info("Snapshot size", "%d connections in the first matching snapshot" % len(snap["Snapshot"]["connections"]))

    set_rules(ipc, [rule_deny(app), rule_deny(lo_app)])
    R.check("SetRules deny changes the nft table (remote client's port added)",
            bool(wait_until(lambda: c.local in (rat_ports() or set()), 12)),
            "port %d; set=%s" % (c.local, sorted(rat_ports() or [])))
    time.sleep(2 * TICK)
    ports = rat_ports() or set()
    R.info("loopback-only client under a deny rule",
           "port %d in set: %s (ledger never judges loopback/private remotes, rat-ledger/src/ingest.rs is_local)"
           % (lc.local, lc.local in ports))
    set_rules(ipc, [])
    R.check("SetRules [] removes the port from the nft set again",
            bool(wait_until(lambda: c.local not in (rat_ports() or set()), 10)),
            "set=%s" % sorted(rat_ports() or []))
    ipc.close()


# ---------------------------------------------------------------- driver

def run_req(results, rid, title, fn, *args):
    R = Req(rid, title)
    log("=== %s %s" % (rid, title))
    try:
        fn(R, *args)
        bad = [c for c in R.checks if c["kind"] == "check" and not c["ok"]]
        R.status = "FAIL-PRODUCT" if bad else "PASS"
    except NotRun as e:
        R.status, R.reason = "NOT RUN", str(e)
    except Harness as e:
        R.status, R.reason = "FAIL-HARNESS", str(e)
    except Exception as e:
        R.status, R.reason = "FAIL-HARNESS", "unexpected %r\n%s" % (e, traceback.format_exc())
    finally:
        stop_all_procs()
        reset_rules()
    log("=== %s -> %s %s" % (rid, R.status, R.reason))
    results.append(R)


def main():
    global LOG
    if os.geteuid() != 0:
        print("must run as root")
        return 2
    os.makedirs(OUT, exist_ok=True)
    LOG = open(os.path.join(OUT, "e2e-run.log"), "w")
    log("kernel: " + os.uname().release)
    sh(["nft", "--version"])
    results = []
    net, d = Net(), Daemon()
    try:
        net.setup()
        run_req(results, "L1", "Monitor attribution", l1)
        run_req(results, "L2", "Enforcer real rules", l2)
        d.install()
        d.start()
        if d.running:
            run_req(results, "L3", "Per-app isolation", l3, d)
        else:
            r = Req("L3", "Per-app isolation")
            r.status, r.reason = "NOT RUN", "daemon did not start (see L5)"
            results.append(r)
        run_req(results, "L4", "Short-lived processes and port reuse", l4, d)
        run_req(results, "L5", "Daemon lifecycle and IPC security", l5, d)
        run_req(results, "L6", "GUI-to-daemon wiring", l6, d)
    except Harness as e:
        log("FATAL setup error: %s" % e)
        for rid in ("L1", "L2", "L3", "L4", "L5", "L6"):
            if not any(x.id == rid for x in results):
                r = Req(rid, "")
                r.status, r.reason = "FAIL-HARNESS", "setup failed: %s" % e
                results.append(r)
    finally:
        stop_all_procs()
        reset_rules()
        d.remove()
        for u in USERS:
            sh(["userdel", u], check=False, quiet=True)
        sh(["groupdel", "rat"], check=False, quiet=True)
        net.teardown()
        shutil.rmtree(WORK, ignore_errors=True)
        shutil.rmtree("/etc/rat", ignore_errors=True)
    left = sh(["nft", "list", "tables"], check=False, quiet=True).stdout
    leftovers = "table inet rat" in left
    log("leftover `inet rat` table after teardown: %s" % leftovers)

    log("======== SUMMARY ========")
    for r in sorted(results, key=lambda x: x.id):
        log("%s  %-13s %s %s" % (r.id, r.status, r.title, r.reason.splitlines()[0] if r.reason else ""))
        for c in r.checks:
            if c["kind"] == "check" and not c["ok"]:
                log("      FAILED CHECK: %s -- %s" % (c["name"], c["detail"]))
    with open(os.path.join(OUT, "e2e-results.json"), "w") as f:
        json.dump([{"id": r.id, "title": r.title, "status": r.status, "reason": r.reason, "checks": r.checks}
                   for r in results], f, indent=1)
    LOG.close()
    return 0 if all(r.status == "PASS" for r in results) and not leftovers else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "ipc-probe":
        ipc_probe_main()
    else:
        sys.exit(main())
