#!/usr/bin/env python3
# Created by Sunny Chase (https://github.com/sunnychase) in collaboration with Claude (Anthropic) · Lion Studio - Container Port Dash
"""Lion Studio - Container Port Dash -- every listening port on one Linux machine, what each one is, who owns it, the traffic on it and
where the data goes; ON / OFF switches for your own systemd --user services and a Kill that asks for your login password.

What it reads (no root needed): `ss -tuaneiH` (every socket with the cgroup that owns it -- exact for root services and
containers too -- and, for TCP, the bytes sent and received on each connection), `ss -E` (the kernel reports every socket as it
closes, with its final byte counts: short connections between two samples are recorded too), /proc (your own processes),
the Docker socket (container names; stop) and your user D-Bus (systemd --user services; start / stop / disable).

Viewing is open to whoever can reach the page. A switch needs the panel token (DATA/token); Kill needs the login password of
PORTS_LOGIN, checked by the machine's own SSH server (PAM) on PORTS_SSH -- never stored, never logged. Kill acts only on your
own services and programs and on Docker containers (stopped, auto-restart off, never deleted); system services are view only.

Env: PORTS_BIND (0.0.0.0) PORTS_PORT (8660) PORTS_DATA (/data) PORTS_LOGIN (the account Kill checks; empty = Kill off)
     PORTS_SSH (127.0.0.1:22) PORTS_DOCKER_SOCK (/var/run/docker.sock) PORTS_PASSWD (/host/passwd: the host's user names)
     PORTS_SAMPLE_S (2) PORTS_UPLOAD_ALERT_MB (100: data sent to the internet by one program in an hour that raises an alert)
     PORTS_LOG_DAYS (30: days of connection log kept) PORTS_LOG_LOCAL (1 = log connections inside this machine too)
     PORTS_LAN (extra networks counted as LAN, comma separated CIDRs) PORTS_DEMO (1 = made-up data, for screenshots)
"""
import hmac
import http.client
import ipaddress
import json
import os
import math
import re
import signal
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

try:
    import paramiko
except ImportError:                                   # Kill stays off without it
    paramiko = None

BIND = os.environ.get("PORTS_BIND", "0.0.0.0")
PORT = int(os.environ.get("PORTS_PORT", "8660"))
DATA = os.environ.get("PORTS_DATA", "/data")
LOGIN = os.environ.get("PORTS_LOGIN", "")
SSH_AT = os.environ.get("PORTS_SSH", "127.0.0.1:22")
DOCKER_SOCK = os.environ.get("PORTS_DOCKER_SOCK", "/var/run/docker.sock")
PASSWD = os.environ.get("PORTS_PASSWD", "/host/passwd")
SAMPLE_S = max(1.0, float(os.environ.get("PORTS_SAMPLE_S", "2")))
LOG_DAYS = int(os.environ.get("PORTS_LOG_DAYS", "30"))
LOG_LOCAL = os.environ.get("PORTS_LOG_LOCAL") == "1"
UPLOAD_ALERT = float(os.environ.get("PORTS_UPLOAD_ALERT_MB", "100")) * 1e6
EXTRA_LAN = [ipaddress.ip_network(n.strip(), strict=False) for n in os.environ.get("PORTS_LAN", "").split(",") if n.strip()]
DEMO = os.environ.get("PORTS_DEMO") == "1"
ME = os.getuid()
SEEN = os.path.join(DATA, "seen_units.json")
KILLED = os.path.join(DATA, "killed_units.json")
TRAFFIC = os.path.join(DATA, "traffic.json")
AUDIT = os.path.join(DATA, "audit.log")
LOGDIR = os.path.join(DATA, "connlog")
UNIT_RE = re.compile(r"^[A-Za-z0-9@._:\\-]{1,200}\.service$")
_lock = threading.Lock()

# ----------------------------------------------------------------------------- what things are
KNOWN_PORTS = {
    22: "SSH: remote login and file copy (ssh, scp, sftp)", 53: "DNS: the local name resolver (turns names into addresses)",
    67: "DHCP server", 68: "DHCP: gets this machine's address from the router", 80: "HTTP web server",
    111: "rpcbind: helper for NFS file sharing", 123: "NTP: keeps the clock right", 139: "Samba: Windows file sharing",
    443: "HTTPS web server", 445: "Samba: Windows file sharing", 631: "CUPS: the printing service and its web page",
    1716: "KDE Connect / GSConnect: phone link", 1900: "SSDP / UPnP: finds media devices on the LAN",
    2049: "NFS: network file sharing", 2375: "Docker API without encryption (anyone who reaches it controls Docker)",
    2376: "Docker API (TLS)", 3000: "web app (Grafana, Node apps and others use it)", 3306: "MySQL / MariaDB database",
    3389: "RDP: remote desktop", 3702: "WS-Discovery: finds devices on the LAN", 5353: "mDNS / Avahi: finds printers and devices on the LAN (.local names)",
    5355: "LLMNR: local name lookup", 5432: "PostgreSQL database", 5900: "VNC: remote desktop", 6006: "TensorBoard",
    6379: "Redis database", 8080: "web app (a common second HTTP port)", 8888: "Jupyter notebook", 9090: "Prometheus / web console",
    11000: "NVIDIA DGX Dashboard: the system status page", 11434: "Ollama: model server", 20241: "cloudflared: the Cloudflare Tunnel's status page",
    27017: "MongoDB database",
}
KNOWN_UNITS = {
    "ssh": "SSH: remote login (OpenSSH server)", "sshd": "SSH: remote login (OpenSSH server)",
    "systemd-resolved": "DNS: the local name resolver", "avahi-daemon": "mDNS / Avahi: finds printers and devices on the LAN (.local names)",
    "cloudflared": "Cloudflare Tunnel: an outbound tunnel that publishes chosen local web pages through Cloudflare",
    "NetworkManager": "network manager: gets this machine's address from the router (DHCP)", "systemd-networkd": "network manager (systemd-networkd)",
    "cups": "CUPS: printing", "cups-browsed": "finds network printers", "snap.cups.cupsd": "CUPS: printing (snap)",
    "snap.cups.cups-browsed": "finds network printers (snap)", "dgx-dashboard": "NVIDIA DGX Dashboard: the system status page",
    "dgx-dashboard-admin": "NVIDIA DGX Dashboard: its admin helper", "docker": "Docker: forwards a published container port (docker-proxy)",
    "containerd": "container runtime", "systemd-timesyncd": "NTP: keeps the clock right", "chrony": "NTP: keeps the clock right",
    "chronyd": "NTP: keeps the clock right", "gnome-remote-desktop": "GNOME Remote Desktop (RDP / VNC)",
    "snapd": "snap store: checks for and downloads snap updates", "fwupd": "firmware updates (checks the LVFS service)",
    "ModemManager": "mobile-broadband modem manager", "ollama": "Ollama: model server", "lldpd": "LLDP: tells network switches what this machine is",
    "rpcbind": "rpcbind: helper for NFS", "nfs-server": "NFS: network file sharing", "smbd": "Samba: Windows file sharing",
    "nmbd": "Samba: Windows names", "tailscaled": "Tailscale VPN", "packagekit": "software updates", "unattended-upgrades": "automatic security updates",
    "gdm": "the login screen", "colord": "colour profiles", "geoclue": "location service", "rsyslog": "system log",
    "wpa_supplicant": "Wi-Fi login", "systemd-journald": "system log", "rtkit-daemon": "real-time scheduling helper",
}
REMOTE_PORTS = {443: "HTTPS", 80: "HTTP", 53: "DNS", 853: "DNS over TLS", 22: "SSH", 123: "NTP", 7844: "Cloudflare Tunnel",
                993: "IMAP mail", 465: "SMTP mail", 587: "SMTP mail", 25: "SMTP mail", 3478: "STUN", 51820: "WireGuard",
                41641: "Tailscale", 8443: "HTTPS", 6881: "BitTorrent", 5228: "Google push", 5223: "Apple push", 1883: "MQTT", 8883: "MQTT TLS"}


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, obj):
    try:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(obj, f, indent=1)
        os.replace(tmp, path)
    except OSError:
        pass


def token():
    try:
        return open(os.path.join(DATA, "token")).read().strip()
    except OSError:
        return ""


_users = {"t": 0, "m": {}}


def user_name(uid):
    if DEMO:
        return {0: "root", 992: "systemd-resolve", 116: "avahi", 117: "dgx-dashboard", 1000: "you"}.get(uid, f"uid {uid}")
    if time.time() - _users["t"] > 300:
        m = {}
        for path in (PASSWD, "/etc/passwd"):
            try:
                for ln in open(path):
                    p = ln.split(":")
                    if len(p) > 2 and p[2].isdigit():
                        m.setdefault(int(p[2]), p[0])
            except OSError:
                pass
        _users.update(t=time.time(), m=m)
    return _users["m"].get(uid, f"uid {uid}")


# ----------------------------------------------------------------------------- sockets (ss)
def _ep(s):
    host, _, port = s.rpartition(":")
    host = host.strip("[]").split("%")[0]
    if host.startswith("::ffff:") and "." in host:
        host = host[7:]
    try:
        return host, int(port)
    except ValueError:
        return host, 0


def parse_ss(text):
    """`ss -tuaneiH` -> one record per socket: proto, state, ip, port, rip, rport, uid, ino, cgroup, sent, recv (TCP only)"""
    recs, cur = [], None
    for ln in text.splitlines():
        if not ln.strip():
            continue
        if ln[0] in " \t":
            if cur is not None:
                for k, f in (("sent", r"\bbytes_sent:(\d+)"), ("recv", r"\bbytes_received:(\d+)")):
                    m = re.search(f, ln)
                    if m:
                        cur[k] = int(m.group(1))
            continue
        p = ln.split()
        if len(p) < 6 or p[0] not in ("tcp", "udp"):
            cur = None
            continue
        rest = " ".join(p[6:])
        uid, ino, cg = re.search(r"\buid:(\d+)", rest), re.search(r"\bino:(\d+)", rest), re.search(r"\bcgroup:(\S+)", rest)
        sk = re.search(r"\bsk:([0-9a-f]+)", rest)
        (ip, port), (rip, rport) = _ep(p[4]), _ep(p[5])
        cur = {"proto": p[0], "state": p[1], "ip": ip, "port": port, "rip": rip, "rport": rport, "uid": int(uid.group(1)) if uid else 0,
               "ino": ino.group(1) if ino else "", "cgroup": cg.group(1) if cg else "", "sk": sk.group(1) if sk else "", "sent": None, "recv": None}
        recs.append(cur)
    return recs


def owner_of(cg):
    """the cgroup a socket belongs to -> what owns it"""
    m = re.search(r"/docker-([0-9a-f]{64})\.scope", cg)
    if m:
        return {"kind": "container", "id": m.group(1)}
    m = re.search(r"/user@(\d+)\.service/(?:.*/)?([^/]+\.service)$", cg)
    if m:
        return {"kind": "unit" if int(m.group(1)) == ME else "other", "unit": m.group(2), "uid": int(m.group(1))}
    m = re.search(r"/user-(\d+)\.slice/(?:.*/)?([^/]+\.scope)$", cg)
    if m:
        return {"kind": "process" if int(m.group(1)) == ME else "other", "unit": m.group(2), "uid": int(m.group(1))}
    m = re.search(r"^/system\.slice/(?:.*/)?([^/]+\.(?:service|socket|scope))$", cg)
    if m:
        return {"kind": "proxy" if m.group(1) == "docker.service" else "system", "unit": m.group(1)}
    return {"kind": "other", "unit": cg.rsplit("/", 1)[-1] if cg else ""}


def fd_owners():
    """socket inode -> pid, for the processes this account may look into"""
    m = {}
    if DEMO:
        return m
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        d = f"/proc/{pid}/fd"
        try:
            for fd in os.listdir(d):
                try:
                    t = os.readlink(f"{d}/{fd}")
                except OSError:
                    continue
                if t.startswith("socket:["):
                    m.setdefault(t[8:-1], pid)
        except OSError:
            continue
    return m


def proc_info(pid):
    def rd(p):
        try:
            return open(p, "rb").read()
        except OSError:
            return b""
    comm = rd(f"/proc/{pid}/comm").decode(errors="replace").strip()
    cmd = rd(f"/proc/{pid}/cmdline").replace(b"\0", b" ").decode(errors="replace").strip()
    return {"pid": pid, "process": comm, "cmd": re.sub(r"/home/[^/ ]+", "~", cmd)[:200]}


# ----------------------------------------------------------------------------- Docker (unix socket, standard library)
class _UConn(http.client.HTTPConnection):
    def __init__(self, path, timeout=15):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def docker(method, path, body=None, timeout=15):
    if DEMO:
        return DEMO_STATE.docker(method, path, body)
    if not os.path.exists(DOCKER_SOCK):
        return 0, None
    c = _UConn(DOCKER_SOCK, timeout)
    try:
        c.request(method, path, body=json.dumps(body) if body is not None else None,
                  headers={"Content-Type": "application/json"} if body is not None else {})
        r = c.getresponse()
        raw = r.read()
        try:
            return r.status, json.loads(raw) if raw else None
        except ValueError:
            return r.status, raw.decode(errors="replace")
    except OSError as e:
        return 0, str(e)
    finally:
        c.close()


_cont = {"t": 0, "m": {}}


def containers():
    """running containers: id -> name, image, restart policy, published ports"""
    if time.time() - _cont["t"] < 15:
        return _cont["m"]
    st, lst = docker("GET", "/containers/json")
    m = {}
    for c in lst if st == 200 and isinstance(lst, list) else []:
        m[c["Id"]] = {"id": c["Id"], "name": (c.get("Names") or ["/?"])[0].lstrip("/"), "image": c.get("Image", ""),
                      "published": sorted({(p["PublicPort"], p.get("Type", "tcp")) for p in c.get("Ports") or [] if p.get("PublicPort")}),
                      "net": (c.get("HostConfig") or {}).get("NetworkMode", "")}
    _cont.update(t=time.time(), m=m)
    return m


# ----------------------------------------------------------------------------- systemd --user (busctl over the user D-Bus)
def busctl(*args, timeout=60):
    if DEMO:
        return DEMO_STATE.busctl(*args)
    return subprocess.run(["busctl", "--user", "--json=short", *args], capture_output=True, text=True, timeout=timeout)


def _mgr(method, sig, *args, timeout=90):
    return busctl("call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", method, sig, *args,
                  timeout=timeout)


_ust = {}


def unit_state(units, fresh=False):
    st = {}
    for u in units:
        c = _ust.get(u)
        if c and not fresh and time.time() - c[0] < 20:
            st[u] = c[1]
            continue
        r = _mgr("LoadUnit", "s", u, timeout=15)
        try:
            path = json.loads(r.stdout)["data"][0]
            g = busctl("get-property", "org.freedesktop.systemd1", path, "org.freedesktop.systemd1.Unit", "ActiveState", "SubState",
                       "Description", "Transient", "UnitFileState", timeout=15)
            v = [json.loads(x)["data"] for x in g.stdout.splitlines() if x.strip()]
            st[u] = {"ActiveState": v[0], "SubState": v[1], "Description": v[2], "Transient": bool(v[3]), "UnitFileState": v[4]}
        except (ValueError, KeyError, IndexError, TypeError):
            st[u] = {"ActiveState": "unknown", "SubState": "", "Description": "", "Transient": False, "UnitFileState": ""}
        _ust[u] = (time.time(), st[u])
    return st


# ----------------------------------------------------------------------------- where a peer is
_own = {"t": 0, "ips": set(), "nets": []}
LAN_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
                                              "fc00::/7", "fe80::/10")]


def own_addrs():
    if time.time() - _own["t"] < 60:
        return _own
    ips, nets = set(), []
    if DEMO:
        ips = {"192.0.2.10"}
    else:
        try:
            for i in json.loads(subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, timeout=10).stdout or "[]"):
                for a in i.get("addr_info", []):
                    ips.add(a["local"])
                    if i.get("ifname", "").startswith(("docker", "br-", "veth", "virbr", "cni", "podman")):
                        nets.append(ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}", strict=False))
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            pass
    _own.update(t=time.time(), ips=ips, nets=nets)
    return _own


def where(ip):
    if ip in ("*", "0.0.0.0", "::", ""):
        return "any"
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "?"
    o = own_addrs()
    if a.is_loopback or ip in o["ips"]:
        return "this machine"
    if any(a in n for n in o["nets"]):
        return "container (this machine)"
    if any(a.version == n.version and a in n for n in LAN_NETS + EXTRA_LAN):
        return "LAN"
    if a.is_multicast:
        return "multicast (LAN)"
    return "internet"


def reach(ip):
    w = where(ip)
    if w == "this machine":
        return "this machine only"
    if w == "any":
        return "all interfaces (LAN)"
    return f"only {ip}"


# ----------------------------------------------------------------------------- traffic: sampled every SAMPLE_S, kept in DATA/traffic.json
def dest_group(ip):
    """destinations are 'new' per network (/24, /48), so a service that changes address inside its network is not new each time"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    return str(ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 48}", strict=False))


class Traffic:
    def __init__(self):
        d = load_json(TRAFFIC, {})
        self.lock = threading.Lock()
        self.prev = {}                                # socket cookie -> (sent, recv) at the last sample
        self.cookie = {}                              # socket cookie -> owner, direction, last seen (owners of sockets that close later)
        self.recs, self.conns, self.t = [], [], 0.0
        self.first = True
        self.started = d.get("started") or time.time()
        self.dest = d.get("dest", {})                 # "owner|ip" -> totals, first / last seen
        self.known = d.get("known", {})               # "owner|network" -> first seen (the NEW flag)
        self.listen_seen = d.get("listen_seen", {})   # "proto/port" -> first seen
        self.hours = d.get("hours", {})               # hour -> owner -> [sent internet, recv internet, sent LAN, recv LAN]
        self.alerts = d.get("alerts", [])
        self.names = d.get("names", {})
        self.minute = {}                              # owner -> {minute: bytes sent to the internet}  (the upload alert)
        self.alerted = {}
        self.learn_until = d.get("learn_until") or time.time() + (5 if DEMO else 1800)   # the first 30 min learn what is normal: no NEW alerts
        self.saved = 0.0
        self.listen = []
        self.short = 0                                # connections that opened and closed between two samples (recorded at close)
        self._resolving = set()
        self._logday, self._logf = "", None

    # names: reverse DNS in the background (a lookup goes to this machine's resolver)
    def name(self, ip):
        n = self.names.get(ip)
        if n is None and ip not in self._resolving and len(self._resolving) < 32 and where(ip) in ("internet", "LAN"):
            self._resolving.add(ip)
            threading.Thread(target=self._resolve, args=(ip,), daemon=True).start()
        return n or ""

    def _resolve(self, ip):
        try:
            n = DEMO_STATE.rdns(ip) if DEMO else socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            n = ""
        with self.lock:
            self.names[ip] = n
            if len(self.names) > 5000:
                for k in list(self.names)[:1000]:
                    self.names.pop(k, None)
        self._resolving.discard(ip)

    def alert(self, kind, text):
        self.alerts.append({"t": time.time(), "kind": kind, "text": text})
        self.alerts = self.alerts[-300:]

    # the connection log: one JSON line per event, one file per day, LOG_DAYS kept
    def log(self, rec):
        day = time.strftime("%Y-%m-%d")
        try:
            if day != self._logday:
                if self._logf:
                    self._logf.close()
                os.makedirs(LOGDIR, exist_ok=True)
                self._logf, self._logday = open(os.path.join(LOGDIR, day + ".jsonl"), "a", buffering=1), day
                cut = time.strftime("%Y-%m-%d", time.localtime(time.time() - LOG_DAYS * 86400))
                for f in os.listdir(LOGDIR):                    # the page's own log files past the retention, nothing else
                    if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.jsonl", f) and f[:10] < cut:
                        os.remove(os.path.join(LOGDIR, f))
            self._logf.write(json.dumps(rec, separators=(",", ":")) + "\n")
        except OSError:
            pass

    def _account(self, own, r, w, inbound, up, down, now):
        """add bytes to the 24 h / 7 day totals of one program and one other end; NEW destination alert"""
        dk = f'{own}|{r["rip"]}'
        e = self.dest.get(dk)
        if e is None:
            e = self.dest[dk] = {"owner": own, "ip": r["rip"], "where": w, "first": now, "last": now, "sent": 0, "recv": 0,
                                 "ports": [], "dir": "in" if inbound else "out", "lport": r["port"] if inbound else None, "closed": 0}
        e["last"] = now
        e["sent"] += up
        e["recv"] += down
        pp = r["port"] if inbound else r["rport"]
        if pp not in e["ports"] and len(e["ports"]) < 8:
            e["ports"].append(pp)
        g = f'{own}|{dest_group(r["rip"])}'
        if g not in self.known:
            self.known[g] = now
            if now > self.learn_until and w == "internet":
                nm = self.name(r["rip"])
                self.alert("new", f'NEW destination: {own} {"was reached from" if inbound else "connected to"} '
                                  f'{nm + " " if nm else ""}{r["rip"]} port {pp} ({w})')
        hb = self.hours.setdefault(str(int(now // 3600 * 3600)), {}).setdefault(own, [0, 0, 0, 0])
        j = 0 if w == "internet" else 2
        hb[j] += up
        hb[j + 1] += down
        if w == "internet" and up:
            mm = self.minute.setdefault(own, {})
            mm[int(now // 60)] = mm.get(int(now // 60), 0) + up
        return e

    def _is_conn(self, r):
        if r["proto"] == "tcp":
            return r["state"] != "LISTEN" and r["sent"] is not None
        return r["state"] == "ESTAB" and bool(r["rport"])

    def _inbound(self, r):
        return r["proto"] == "tcp" and any(p == r["port"] and (i in ("0.0.0.0", "::", "*") or i == r["ip"]) for i, p in self.listen)

    def sample(self, recs, label):
        now = time.time()
        dt = max(0.5, now - self.t) if self.t else SAMPLE_S
        conns, new_prev = [], {}
        with self.lock:
            self.listen = [(r["ip"], r["port"]) for r in recs if r["proto"] == "tcp" and r["state"] == "LISTEN"]
            for r in recs:
                if not self._is_conn(r):
                    continue
                inbound = self._inbound(r)
                k = r["sk"] or f'{r["proto"]}|{r["ip"]}|{r["port"]}|{r["rip"]}|{r["rport"]}|{r["ino"]}'
                w = where(r["rip"])
                own = label(r)
                up = down = 0
                if r["sent"] is not None:
                    pv = self.prev.get(k)
                    if pv is None:
                        up, down = (0, 0) if self.first else (r["sent"], r["recv"] or 0)
                    else:
                        up, down = max(0, r["sent"] - pv[0]), max(0, (r["recv"] or 0) - pv[1])
                    new_prev[k] = (r["sent"], r["recv"] or 0)
                if k not in self.cookie and (LOG_LOCAL or w in ("internet", "LAN")) and not self.first:
                    self.log({"t": round(now, 1), "ev": "open", "proto": r["proto"], "owner": own, "dir": "in" if inbound else "out",
                              "local": f'{r["ip"]}:{r["port"]}', "remote": f'{r["rip"]}:{r["rport"]}', "where": w,
                              "name": self.name(r["rip"]), "sent": r["sent"], "recv": r["recv"]})
                self.cookie[k] = (own, inbound, now, w)
                conns.append({**r, "key": k, "dir": "in" if inbound else "out", "where": w, "owner": own, "up_s": up / dt, "down_s": down / dt})
                if w in ("internet", "LAN"):
                    self._account(own, r, w, inbound, up, down, now)
            for own, mm in self.minute.items():                  # upload alert: one program, the last 60 minutes
                for m_ in [m_ for m_ in mm if m_ < int(now // 60) - 60]:
                    del mm[m_]
                tot = sum(mm.values())
                if tot > UPLOAD_ALERT and now - self.alerted.get(own, 0) > 3600:
                    self.alerted[own] = now
                    self.alert("upload", f"UPLOAD: {own} sent {tot / 1e6:.0f} MB to the internet in the last hour")
            for r in recs:                                       # a port newly open to the LAN
                if (r["proto"] == "tcp" and r["state"] == "LISTEN") or (r["proto"] == "udp" and r["state"] == "UNCONN" and not r["rport"]):
                    lk = f'{r["proto"]}/{r["port"]}'
                    if lk not in self.listen_seen:
                        self.listen_seen[lk] = now
                        if now > self.learn_until and reach(r["ip"]) != "this machine only" and not (r["proto"] == "udp" and r["port"] >= 32768):
                            self.alert("listen", f'NEW port open to the LAN: {r["port"]}/{r["proto"]} by {label(r)}')
            for h in [h for h in self.hours if float(h) < now - 7 * 86400]:
                del self.hours[h]
            if len(self.dest) > 4000:
                for k in sorted(self.dest, key=lambda k: self.dest[k]["last"])[:500]:
                    del self.dest[k]
            for k in [k for k, v in self.cookie.items() if v[2] < now - 120]:     # owners are kept 2 min after a socket's last sample
                del self.cookie[k]
            self.prev, self.recs, self.conns, self.t, self.first = new_prev, recs, conns, now, False
            if now - self.saved > 60:
                self.save()

    def closed(self, r):
        """the kernel says a socket closed (ss -E): its final counters; bytes since the last sample are added, the event logged"""
        if not r["rport"] or r["rip"] in ("*", "0.0.0.0", "::", ""):
            return
        w = where(r["rip"])
        if not LOG_LOCAL and w not in ("internet", "LAN"):
            return
        now = time.time()
        with self.lock:
            k = r["sk"]
            c = self.cookie.pop(k, None)
            short = c is None
            own = c[0] if c else "unknown (closed between two samples)"
            inbound = c[1] if c else self._inbound(r)
            pv = self.prev.pop(k, None)
            up = down = 0
            if r["sent"] is not None:
                up, down = (max(0, r["sent"] - pv[0]), max(0, (r["recv"] or 0) - pv[1])) if pv else (r["sent"], r["recv"] or 0)
            if short:
                self.short += 1
            if w in ("internet", "LAN"):
                e = self._account(own, r, w, inbound, up, down, now)
                e["closed"] = e.get("closed", 0) + 1
            self.log({"t": round(now, 1), "ev": "close", "proto": r["proto"], "owner": own, "dir": "in" if inbound else "out",
                      "local": f'{r["ip"]}:{r["port"]}', "remote": f'{r["rip"]}:{r["rport"]}', "where": w, "name": self.name(r["rip"]),
                      "sent": r["sent"], "recv": r["recv"], "short": short})

    def save(self):
        self.saved = time.time()
        save_json(TRAFFIC, {"started": self.started, "learn_until": self.learn_until, "dest": self.dest, "known": self.known,
                            "listen_seen": self.listen_seen, "hours": self.hours, "alerts": self.alerts, "names": self.names})


def events():
    """`ss -E`: one record per socket as the kernel destroys it (no owner in the event: the sampler's memory names it)"""
    while True:
        try:
            if DEMO:
                for r in DEMO_STATE.events():
                    TR.closed(r)
                time.sleep(3)
                continue
            p = subprocess.Popen(["ss", "-E", "-tuaneiH"], stdout=subprocess.PIPE, text=True, bufsize=1)
            pend = None
            for ln in p.stdout:
                if ln[:1] in (" ", "\t"):
                    if pend is not None:
                        rr = parse_ss(pend + "\n" + ln)
                        if rr:
                            TR.closed(rr[0])
                    pend = None
                    continue
                if pend is not None:                         # a record without an info line (UDP)
                    rr = parse_ss(pend)
                    if rr:
                        TR.closed(rr[0])
                pend = ln.rstrip("\n")
            p.wait()
        except Exception as e:
            TR.alert("error", f"close events stopped: {type(e).__name__}: {e}"[:200])
        time.sleep(5)


def read_log(q="", scope="internet", limit=300):
    """the newest connection-log records (today, then the days before), filtered"""
    out = []
    try:
        days = sorted((f for f in os.listdir(LOGDIR) if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.jsonl", f)), reverse=True)
    except OSError:
        return out
    q = q.lower()
    for f in days[:LOG_DAYS]:
        try:
            with open(os.path.join(LOGDIR, f), "rb") as fh:
                fh.seek(0, 2)
                size = fh.tell()
                fh.seek(max(0, size - 4_000_000))
                lines = fh.read().decode(errors="replace").splitlines()
        except OSError:
            continue
        for ln in reversed(lines):
            try:
                r = json.loads(ln)
            except ValueError:
                continue
            if scope == "internet" and r.get("where") != "internet":
                continue
            if q and q not in ln.lower():
                continue
            out.append(r)
            if len(out) >= limit:
                return out
    return out


TR = None


def run_ss():
    if DEMO:
        return DEMO_STATE.ss()
    return subprocess.run(["ss", "-tuaneiH"], capture_output=True, text=True, timeout=30).stdout


def owner_label(r):
    """one short name for whoever owns a socket: a container, a service or a program"""
    o = owner_of(r["cgroup"])
    if o["kind"] == "container":
        return "container " + containers().get(o["id"], {}).get("name", o["id"][:12])
    if o["kind"] == "proxy" and r.get("port"):
        for c in containers().values():
            if (r["port"], "tcp" if r["proto"] == "tcp" else "udp") in c["published"]:
                return "container " + c["name"]
    return o.get("unit") or user_name(r["uid"])


def sampler():
    while True:
        try:
            TR.sample(parse_ss(run_ss()), owner_label)
        except Exception as e:                                   # keep sampling; the page shows the last good sample
            TR.alert("error", f"sampling failed: {type(e).__name__}: {e}"[:200])
        time.sleep(SAMPLE_S)


# ----------------------------------------------------------------------------- the ports
def self_container():
    for r in TR.recs:
        if r["proto"] == "tcp" and r["state"] == "LISTEN" and r["port"] == PORT:
            o = owner_of(r["cgroup"])
            return o.get("id", "")
    return ""


def ports():
    notes = load_json(os.path.join(DATA, "descriptions.json"), {})
    own = fd_owners()
    conts = containers()
    me_c = self_container()
    with TR.lock:
        recs, conns = list(TR.recs), list(TR.conns)
    rows, seen = [], set()
    for r in recs:
        if not ((r["proto"] == "tcp" and r["state"] == "LISTEN") or (r["proto"] == "udp" and r["state"] == "UNCONN" and not r["rport"])):
            continue
        k = (r["proto"], r["ip"], r["port"])
        if k in seen or (r["proto"] == "udp" and r["port"] == 0):
            continue
        seen.add(k)
        o = owner_of(r["cgroup"])
        row = {"key": f'{r["proto"]}|{r["ip"]}|{r["port"]}', "proto": r["proto"], "ip": r["ip"], "port": r["port"], "reach": reach(r["ip"]),
               "uid": r["uid"], "user": user_name(r["uid"]), "kind": o["kind"], "unit": o.get("unit", ""), "container": None,
               "pid": "", "process": "", "cmd": "", "cg": r["cgroup"], "ips": [r["ip"]]}
        if o["kind"] == "container":
            row["container"] = conts.get(o["id"], {"id": o["id"], "name": o["id"][:12], "image": ""})
        elif o["kind"] == "proxy":
            hit = [c for c in conts.values() if (r["port"], r["proto"]) in c["published"]]
            if hit:
                row.update(kind="container", container=hit[0], via="published by Docker (docker-proxy)")
        pid = own.get(r["ino"])
        if pid:
            row.update(proc_info(pid))
        if row["container"] and row["container"]["id"] == me_c or str(row.get("pid")) == str(os.getpid()):
            row["kind"] = "self"
        if row["container"] and row["user"].startswith("uid "):
            row["user"] += " (an account inside the container)"
        twin = next((x for x in rows if x["proto"] == row["proto"] and x["port"] == row["port"] and x["cg"] == row["cg"]), None)
        if twin:                                                  # the same service on IPv4 and IPv6: one row
            twin["ips"].append(row["ip"])
            if row["reach"] == "all interfaces (LAN)" or (twin["reach"] == "this machine only" and row["reach"] != twin["reach"]):
                twin["reach"] = row["reach"]
            continue
        rows.append(row)
    # traffic per port
    for row in rows:
        cs = [c for c in conns if c["dir"] == "in" and c["port"] == row["port"] and c["proto"] == row["proto"]]
        row["conns"] = len(cs)
        row["in_s"] = sum(c["down_s"] for c in cs)
        row["out_s"] = sum(c["up_s"] for c in cs)
        peers = {}
        for c in cs:
            p = peers.setdefault(c["rip"], {"ip": c["rip"], "where": c["where"], "conns": 0, "in_s": 0.0, "out_s": 0.0})
            p["conns"] += 1
            p["in_s"] += c["down_s"]
            p["out_s"] += c["up_s"]
        for p in peers.values():
            p["name"] = TR.name(p["ip"]) if p["where"] in ("internet", "LAN") else ""
        row["peers"] = sorted(peers.values(), key=lambda p: -(p["out_s"] + p["in_s"]))[:20]
    units = unit_state(sorted({r["unit"] for r in rows if r["kind"] == "unit"}))
    for row in rows:
        row["description"] = describe(row, notes, units)
        row["killable"], row["kill_note"] = killable(row)
    rows.sort(key=lambda r: (r["port"], r["proto"], r["ip"]))
    return rows


def describe(row, notes, units):
    for k in (f'{row["port"]}/{row["proto"]}', str(row["port"])):
        if notes.get(k):
            return notes[k]
    c = row.get("container")
    if c:
        return notes.get(f'container:{c["name"]}') or f'Docker container {c["name"]}' + (f' ({c["image"]})' if c.get("image") else "")
    u = row.get("unit", "")
    if row["kind"] == "unit":
        return notes.get(u) or units.get(u, {}).get("Description") or u
    stem = re.sub(r"\.(service|socket|scope)$", "", u)
    if row["kind"] == "self":
        return "this page (Container Port Dash)"
    if KNOWN_UNITS.get(stem):
        return KNOWN_UNITS[stem]
    if KNOWN_PORTS.get(row["port"]):
        return KNOWN_PORTS[row["port"]]
    if row["proto"] == "udp" and row["port"] >= 32768:
        return f"temporary port {stem or row['user']} opened for its own use (the number changes on restart)"
    return notes.get(u) or (f"{row['process']}" if row.get("process") else stem)


def killable(row):
    k = row["kind"]
    if k == "self":
        return False, "this page: stop it with docker stop"
    if k == "container":
        return True, ""
    if k == "unit":
        return True, ""
    if k == "process" and row.get("pid"):
        return True, ""
    return False, f'owned by {row["user"]}{" (" + row["unit"] + ")" if row.get("unit") else ""}: a system service, view only'


def kill_plan(row, rows):
    """what Kill will do, in plain words (the page shows it before asking for the password)"""
    if row["kind"] == "container":
        c = row["container"]
        others = sorted({f'{r["port"]}/{r["proto"]}' for r in rows if r.get("container") and r["container"]["id"] == c["id"]})
        return {"action": "container", "target": c["name"], "id": c["id"],
                "steps": [f'stop Docker container {c["name"]}' + (f' ({c["image"]})' if c.get("image") else ""),
                          "turn its automatic restart off, so it stays stopped after a reboot",
                          f'its ports go down: {", ".join(others)}',
                          f'nothing is deleted: the container and its data are kept; "docker start {c["name"]}" brings it back']}
    if row["kind"] == "unit":
        u = row["unit"]
        st = unit_state([u], fresh=True).get(u, {})
        others = sorted({f'{r["port"]}/{r["proto"]}' for r in rows if r["kind"] == "unit" and r["unit"] == u})
        if st.get("Transient"):
            return {"action": "unit", "target": u, "transient": True, "ports": [r["port"] for r in rows if r["kind"] == "unit" and r["unit"] == u],
                    "steps": [f"stop the temporary service {u}", f'its ports go down: {", ".join(others)}',
                              "a temporary service is deleted when it stops: it cannot be switched back on from this page"]}
        return {"action": "unit", "target": u, "transient": False, "ports": [r["port"] for r in rows if r["kind"] == "unit" and r["unit"] == u],
                "steps": [f"stop the service {u}", "disable it, so it stays off after a reboot",
                          f'its ports go down: {", ".join(others)}',
                          "nothing is deleted: switching it back ON under Your services starts and enables it again"]}
    if row["kind"] == "process":
        return {"action": "process", "target": f'{row["process"]} (PID {row["pid"]})', "pid": row["pid"],
                "steps": [f'end the program {row["process"]} (PID {row["pid"]}): ask it to close, force it after 5 s',
                          f'port {row["port"]}/{row["proto"]} goes down', "it is not a service: nothing restarts it, nothing is deleted"]}
    return None


# ----------------------------------------------------------------------------- the password (the machine's own SSH server checks it: PAM)
_fails = {"by": {}, "all": []}


def locked(client):
    now = time.time()
    by = [t for t in _fails["by"].get(client, []) if t > now - 900]
    al = [t for t in _fails["all"] if t > now - 900]
    _fails["by"][client], _fails["all"] = by, al
    if len(by) >= 5 or len(al) >= 15:
        return int((min(by if len(by) >= 5 else al) + 900 - now) // 60) + 1
    return 0


def password_ok(pw):
    if DEMO:
        return pw == "demo"
    if not (LOGIN and paramiko):
        raise RuntimeError("Kill is off: PORTS_LOGIN is not set or paramiko is missing")
    host, _, port = SSH_AT.rpartition(":")
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())      # this machine's own SSH server on loopback
    try:
        cli.connect(host or "127.0.0.1", port=int(port or 22), username=LOGIN, password=pw, look_for_keys=False, allow_agent=False,
                    timeout=8, auth_timeout=12, banner_timeout=12)
        return True
    except paramiko.AuthenticationException:
        return False
    except (paramiko.SSHException, OSError) as e:
        raise RuntimeError(f"the SSH server could not check the password: {type(e).__name__}") from None
    finally:
        cli.close()


def audit(client, action, target, result):
    try:
        with open(AUDIT, "a") as f:
            f.write(json.dumps({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "from": client, "action": action, "target": target,
                                "result": result}) + "\n")
    except OSError:
        pass


def do_kill(plan):
    a = plan["action"]
    if a == "container":
        st, b = docker("POST", f'/containers/{plan["id"]}/stop?t=10', timeout=40)
        if st not in (204, 304):
            return False, f"docker stop answered {st}: {str(b)[:200]}"
        st, b = docker("POST", f'/containers/{plan["id"]}/update', {"RestartPolicy": {"Name": "no"}})
        _cont["t"] = 0
        return (True, f'container {plan["target"]} stopped, automatic restart off') if st == 200 else \
            (True, f'container {plan["target"]} stopped; restart policy NOT changed ({st}): it may come back after a reboot')
    if a == "unit":
        u = plan["target"]
        if not plan.get("transient"):
            d = _mgr("DisableUnitFiles", "asb", "1", u, "false")
            if d.returncode == 0:
                _mgr("Reload", "", timeout=60)
                with _lock:
                    k = load_json(KILLED, [])
                    if u not in k:
                        save_json(KILLED, k + [u])
                    seen = load_json(SEEN, {})                    # it keeps its ON switch under Your services
                    seen[u] = sorted(set(seen.get(u, [])) | set(plan.get("ports") or []))
                    save_json(SEEN, seen)
        r = _mgr("StopUnit", "ss", u, "replace")
        for _ in range(30):
            st = unit_state([u], fresh=True).get(u, {})
            if st.get("ActiveState") in ("inactive", "failed", "unknown"):
                break
            time.sleep(1)
        return r.returncode == 0, f"{u}: {st.get('ActiveState')}" + ("" if plan.get("transient") else ", disabled") + \
            ("" if r.returncode == 0 else f" ({r.stderr.strip()[-200:]})")
    if a == "process":
        pid = int(plan["pid"])
        try:
            os.kill(pid, signal.SIGTERM)
            for _ in range(50):
                time.sleep(0.1)
                os.kill(pid, 0)
            os.kill(pid, signal.SIGKILL)
            return True, f'{plan["target"]} forced to close after 5 s'
        except ProcessLookupError:
            return True, f'{plan["target"]} closed'
        except PermissionError:
            return False, f'{plan["target"]}: not allowed (another account)'
    return False, "nothing to do"


# ----------------------------------------------------------------------------- switches (your systemd --user services)
def services(rows):
    with _lock:
        seen = load_json(SEEN, {})
        for r in rows:
            if r["kind"] == "unit" and UNIT_RE.match(r["unit"]):
                ps = seen.setdefault(r["unit"], [])
                if r["port"] not in ps:
                    seen[r["unit"]] = sorted(ps + [r["port"]])
        save_json(SEEN, seen)
    st = unit_state(sorted(seen))
    return [{"unit": u, "ports": p, "active": st.get(u, {}).get("ActiveState", "unknown"), "sub": st.get(u, {}).get("SubState", ""),
             "description": st.get(u, {}).get("Description", ""), "temporary": st.get(u, {}).get("Transient", False),
             "enabled": st.get(u, {}).get("UnitFileState", "")}
            for u, p in sorted(seen.items())]


def toggle(unit, on):
    with _lock:
        known = load_json(SEEN, {})
    if not UNIT_RE.match(unit or "") or unit not in known:
        return 400, {"error": "only a systemd --user service this page has seen holding a port can be switched"}
    if not on and unit_state([unit], fresh=True).get(unit, {}).get("Transient"):
        return 409, {"error": f"{unit} is a temporary (transient) unit: turning it off would delete it, so it cannot be switched here"}
    if on:                                                        # a service Kill disabled is enabled again
        with _lock:
            k = load_json(KILLED, [])
        if unit in k:
            _mgr("EnableUnitFiles", "asbb", "1", unit, "false", "false")
            _mgr("Reload", "", timeout=60)
            with _lock:
                save_json(KILLED, [x for x in load_json(KILLED, []) if x != unit])
    r = _mgr("StartUnit" if on else "StopUnit", "ss", unit, "replace")
    st = {}
    for _ in range(30):
        st = unit_state([unit], fresh=True).get(unit, {})
        if st.get("ActiveState") in (("active", "failed") if on else ("inactive", "failed")):
            break
        time.sleep(1)
    return (200 if r.returncode == 0 else 500), {"unit": unit, "requested": "on" if on else "off", "rc": r.returncode,
                                                 "active": st.get("ActiveState"), "error": r.stderr.strip()[-300:]}


# ----------------------------------------------------------------------------- the state the page shows
def state():
    rows = ports()
    now = time.time()
    with TR.lock:
        dest = [dict(e) for e in TR.dest.values()]
        conns = list(TR.conns)
        hours = {h: dict(v) for h, v in TR.hours.items() if float(h) > now - 86400}
        alerts = [a for a in TR.alerts if a["t"] > now - 7 * 86400][-60:]
        known, learn = dict(TR.known), TR.learn_until
    live = {}
    for c in conns:
        if c["where"] in ("internet", "LAN"):
            v = live.setdefault(f'{c["owner"]}|{c["rip"]}', [0, 0.0, 0.0])
            v[0] += 1
            v[1] += c["up_s"]
            v[2] += c["down_s"]
    for e in dest:
        v = live.get(f'{e["owner"]}|{e["ip"]}', [0, 0.0, 0.0])
        e.update(conns=v[0], up_s=v[1], down_s=v[2], name=TR.name(e["ip"]),
                 new=known.get(f'{e["owner"]}|{dest_group(e["ip"])}', 0) > max(learn, now - 86400) or
                 (e["first"] > max(learn, now - 86400)),
                 service=", ".join(REMOTE_PORTS.get(p, "") or str(p) for p in e["ports"][:3]) if e["dir"] == "out" else
                 f'into port {e.get("lport")}')
    dest = [e for e in dest if e["last"] > now - 86400 or e["conns"]]
    dest.sort(key=lambda e: (-(e["up_s"] > 0), -e["up_s"], -e["sent"]))
    day = {}
    for h, v in hours.items():
        for own, b in v.items():
            d = day.setdefault(own, [0, 0, 0, 0])
            for i in range(4):
                d[i] += b[i]
    udp_out = sorted({(c["owner"], c["rip"], c["rport"]) for c in conns if c["proto"] == "udp" and c["where"] == "internet"})
    return {"when": time.strftime("%Y-%m-%d %H:%M:%S"), "sample_s": SAMPLE_S, "started": TR.started, "learning": now < learn,
            "ports": rows, "services": services(rows), "dest": dest[:300],
            "day": sorted(([o] + v for o, v in day.items()), key=lambda x: -x[1]),
            "udp_out": [{"owner": o, "ip": i, "port": p, "name": TR.name(i)} for o, i, p in udp_out][:50],
            "alerts": alerts[::-1], "kill": bool(DEMO or (LOGIN and paramiko)), "demo": DEMO, "short": TR.short, "log_days": LOG_DAYS,
            "days": sorted((f[:10] for f in (os.listdir(LOGDIR) if os.path.isdir(LOGDIR) else []) if re.fullmatch(r"\d{4}-\d{2}-\d{2}\.jsonl", f)),
                           reverse=True)}


# ----------------------------------------------------------------------------- made-up data (PORTS_DEMO=1), for screenshots and tests
class Demo:
    """a made-up machine: documentation addresses only (192.0.2.x = the LAN, 198.51.100.x / 203.0.113.x = the internet)"""
    U = "/user.slice/user-1000.slice/user@1000.service/app.slice/"
    D = "/system.slice/docker-%s.scope"

    def __init__(self):
        self.t0 = time.time()
        self.cids = {n: (n.encode().hex() * 8)[:64] for n in ("chat-ui", "model-server", "notebook")}
        self.stopped, self.units_off = set(), set()
        self.socks = [  # proto, ip, port, uid, cgroup
            ("tcp", "0.0.0.0", 22, 0, "/system.slice/ssh.socket"),
            ("tcp", "127.0.0.53", 53, 992, "/system.slice/systemd-resolved.service"),
            ("udp", "127.0.0.53", 53, 992, "/system.slice/systemd-resolved.service"),
            ("tcp", "127.0.0.1", 631, 0, "/system.slice/cups.service"),
            ("tcp", "0.0.0.0", 3080, 0, self.D % self.cids["chat-ui"]),
            ("udp", "0.0.0.0", 5353, 116, "/system.slice/avahi-daemon.service"),
            ("tcp", "127.0.0.1", 8000, 1000, self.U + "drawing-api.service"),
            ("tcp", "127.0.0.1", 8010, 1000, self.U + "report-builder.service"),
            ("tcp", "0.0.0.0", 8099, 1000, self.U + "model-panel.service"),
            ("tcp", "127.0.0.1", 8089, 0, self.D % self.cids["model-server"]),
            ("tcp", "0.0.0.0", PORT, 1000, self.D % ("ab" * 32)),
            ("tcp", "127.0.0.1", 8888, 1000, self.D % self.cids["notebook"]),
            ("tcp", "127.0.0.1", 11000, 117, "/system.slice/dgx-dashboard.service"),
            ("udp", "*", 44420, 0, "/system.slice/cloudflared.service"),
        ]
        self.flows = [  # owner cgroup, local, lport, remote, rport, up B/s, down B/s, inbound
            (self.D % self.cids["chat-ui"], "192.0.2.10", 3080, "192.0.2.25", 51522, 9000, 1500, True),
            (self.D % self.cids["chat-ui"], "192.0.2.10", 3080, "192.0.2.31", 50110, 3000, 600, True),
            (self.U + "model-panel.service", "192.0.2.10", 8099, "192.0.2.25", 50900, 52000, 800, True),
            ("/system.slice/cloudflared.service", "192.0.2.10", 40112, "198.51.100.7", 7844, 2600, 4100, False),
            (self.D % self.cids["model-server"], "192.0.2.10", 40220, "203.0.113.45", 443, 900, 3_400_000, False),
            ("/system.slice/snapd.service", "192.0.2.10", 40330, "198.51.100.90", 443, 300, 52000, False),
            (self.U + "report-builder.service", "192.0.2.10", 40440, "203.0.113.200", 443, 410_000, 3000, False),
            (self.D % self.cids["chat-ui"], "127.0.0.1", 3080, "127.0.0.1", 41000, 20000, 4000, True),
        ]

    def ss(self):
        el = time.time() - self.t0
        out = []
        for proto, ip, port, uid, cg in self.socks:
            if self._down(cg):
                continue
            ep = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
            u = f" uid:{uid}" if uid else ""
            out.append(f"{proto} {'LISTEN' if proto == 'tcp' else 'UNCONN'} 0 4096 {ep} {'0.0.0.0:*' if proto == 'tcp' else '*:*'}{u} ino:{port}1 cgroup:{cg}")
        for i, (cg, lip, lp, rip, rp, up, down, inbound) in enumerate(self.flows):
            if self._down(cg):
                continue
            t = el + 0.9 * math.sin(el / 3 + i)               # smooth and always growing
            sent = up * t + (up * 3 * max(0, el - 14) if "report-builder" in cg else 0)   # the made-up 'unexpected upload'
            out.append(f"tcp ESTAB 0 0 {lip}:{lp} {rip}:{rp} uid:1000 ino:9{i}00 sk:d{i}0 cgroup:{cg}")
            out.append(f"\t cubic bytes_sent:{int(sent)} bytes_received:{int(down * t)}")
        out.append("udp ESTAB 0 0 192.0.2.10:51000 198.51.100.7:7844 ino:777 cgroup:/system.slice/cloudflared.service")
        return "\n".join(out)

    def _down(self, cg):
        return any(self.cids[n] in cg for n in self.stopped) or any(u in cg for u in self.units_off)

    def events(self):
        """made-up short connections: a lookup to a known host, now and then one to an unknown one"""
        n = int(time.time() - self.t0)
        out = [{"proto": "tcp", "state": "UNCONN", "ip": "192.0.2.10", "port": 41000 + n % 900, "rip": "198.51.100.90", "rport": 443, "uid": 0,
                "ino": "", "cgroup": "", "sk": f"e{n}", "sent": 820, "recv": 5400}]
        if n > 12 and n % 6 < 3:
            out.append({"proto": "tcp", "state": "UNCONN", "ip": "192.0.2.10", "port": 42000 + n % 900, "rip": "203.0.113.77", "rport": 8443,
                        "uid": 0, "ino": "", "cgroup": "", "sk": f"f{n}", "sent": 180_000, "recv": 900})
        return out

    def rdns(self, ip):
        return {"198.51.100.7": "region1.tunnel.example.net", "203.0.113.45": "cdn.models.example.org", "198.51.100.90": "api.snapcraft.example",
                "203.0.113.200": "upload.unknown-host.example", "203.0.113.77": "","192.0.2.25": "laptop.lan", "192.0.2.31": "phone.lan"}.get(ip, "")

    def docker(self, method, path, body):
        if path == "/containers/json":
            return 200, [{"Id": cid, "Names": ["/" + n], "Image": {"chat-ui": "example/chat-ui:1.4", "model-server": "example/llm-server:2.0",
                                                                    "notebook": "example/notebook:7"}[n], "Ports": [], "HostConfig": {"NetworkMode": "host"}}
                         for n, cid in self.cids.items() if n not in self.stopped]
        m = re.match(r"/containers/([0-9a-f]+)/(stop|update)", path)
        if m:
            for n, cid in self.cids.items():
                if cid == m.group(1) and m.group(2) == "stop":
                    self.stopped.add(n)
            return (204 if m.group(2) == "stop" else 200), None
        return 404, None

    def busctl(self, *a):
        class R:
            returncode, stderr, stdout = 0, "", ""
        r = R()
        if "LoadUnit" in a:
            r.stdout = json.dumps({"data": ["/u/" + a[-1]]})
        elif a[0] == "get-property":
            u = a[2][3:]
            off = u in self.units_off
            d = {"drawing-api.service": "Drawing API (made-up)", "report-builder.service": "Report builder (made-up)",
                 "model-panel.service": "Model panel web page (made-up)"}.get(u, u)
            r.stdout = "\n".join(json.dumps({"data": v}) for v in ("inactive" if off else "active", "dead" if off else "running", d, False,
                                                                    "disabled" if off else "enabled"))
        elif "StopUnit" in a:
            self.units_off.add(a[-2])
        elif "StartUnit" in a:
            self.units_off.discard(a[-2])
        return r


DEMO_STATE = Demo() if DEMO else None


# ----------------------------------------------------------------------------- the page
PAGE = r"""<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Container Port Dash</title><style>
:root{--bg:#0b0f17;--fg:#e2e8f0;--dim:#94a3b8;--bd:#1f2937;--card:#111827;--on:#22c55e;--off:#475569;--warn:#f59e0b;--bad:#ef4444;--link:#38b6ff}
@media (prefers-color-scheme: light){:root:not([data-theme=dark]){--bg:#f8fafc;--fg:#0f172a;--dim:#475569;--bd:#e2e8f0;--card:#fff;--off:#94a3b8;--link:#0369a1}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px system-ui,sans-serif;padding:16px;max-width:1500px;margin:auto}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:22px 0 6px}.dim{color:var(--dim)}a{color:var(--link)}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid var(--bd);padding:6px 8px;text-align:left;vertical-align:top}
th{color:var(--dim);font-weight:600;font-size:12px;white-space:nowrap}td.p{font:600 14px ui-monospace,monospace}.n{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.lan{color:var(--warn)}.loc{color:var(--on)}.net{color:var(--bad)}.cmd{font:12px ui-monospace,monospace;color:var(--dim);word-break:break-all}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--bd);border-radius:10px}
.sw{position:relative;display:inline-block;width:46px;height:24px;vertical-align:middle}.sw input{opacity:0;width:0;height:0}
.sl{position:absolute;inset:0;background:var(--off);border-radius:24px;cursor:pointer;transition:.2s}
.sl:before{content:"";position:absolute;height:18px;width:18px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s}
input:checked+.sl{background:var(--on)}input:checked+.sl:before{transform:translateX(22px)}input:disabled+.sl{opacity:.45;cursor:wait}
.tag{font-size:11px;color:var(--dim);border:1px solid var(--bd);border-radius:10px;padding:1px 7px;white-space:nowrap}
.new{color:#fff;background:var(--bad);border-color:var(--bad)}.kill{font:600 12px system-ui;color:var(--bad);background:none;border:1px solid var(--bad);border-radius:6px;padding:3px 10px;cursor:pointer}
.kill:hover{background:var(--bad);color:#fff}tr.x{cursor:pointer}tr.x:hover td{background:rgba(127,127,127,.06)}
.alerts{display:flex;flex-direction:column;gap:6px;margin:10px 0}.al{border-left:4px solid var(--warn);background:var(--card);padding:7px 10px;border-radius:6px}
.al.new,.al.upload{border-color:var(--bad)}.al .t{color:var(--dim);font-size:12px;margin-right:8px}
.up{color:var(--bad)}.dn{color:var(--on)}.bar{display:inline-block;height:6px;border-radius:3px;background:var(--bad);vertical-align:middle;margin-left:6px}
#dlg{position:fixed;inset:0;background:rgba(0,0,0,.55);display:none;align-items:center;justify-content:center;padding:16px;z-index:9}
#dlg .b{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:18px;max-width:520px;width:100%}
#dlg ul{padding-left:18px}#dlg input{width:100%;padding:9px;font-size:15px;border-radius:8px;border:1px solid var(--bd);background:var(--bg);color:var(--fg)}
.btns{display:flex;gap:8px;justify-content:flex-end;margin-top:12px}.btns button{padding:8px 16px;border-radius:8px;border:1px solid var(--bd);background:none;color:var(--fg);cursor:pointer;font-size:14px}
.btns .go{background:var(--bad);border-color:var(--bad);color:#fff}#msg{margin-top:8px;min-height:18px}
.seg button{border:1px solid var(--bd);background:none;color:var(--fg);padding:3px 10px;cursor:pointer;font-size:12px}.seg button.on{background:var(--link);color:#fff;border-color:var(--link)}
footer{margin:28px 0 8px;color:var(--dim);font-size:12px}
@media (max-width:700px){.hide-s{display:none}}
</style></head><body>
<h1>Container Port Dash</h1><div class=dim id=hdr>loading…</div><div id=msg></div>
<div class=alerts id=alerts></div>
<h2>Data leaving this machine <span class="dim seg" style="font-weight:400"><button id=fi class=on onclick="flt('internet')">internet</button><button id=fl onclick="flt('all')">internet + LAN</button></span></h2>
<div class=dim style="font-size:12px;margin-bottom:6px">Every program that sent or received data with another machine in the last 24 h. <span class=up>↑ sent</span> = data leaving this machine, <span class=dn>↓ received</span>. NEW = a destination network this program never used before.</div>
<div class=wrap><table id=dest></table></div>
<div id=udp class=dim style="font-size:12px;margin-top:6px"></div>
<h2>Connection log <span class=dim style="font-weight:400" id=lgh></span></h2>
<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:6px"><input id=lq placeholder="search: program, host, address, port" style="flex:1;min-width:200px;padding:6px 9px;border-radius:8px;border:1px solid var(--bd);background:var(--card);color:var(--fg)"><span id=lgd class=dim style="font-size:12px;align-self:center"></span></div>
<div class=wrap style="max-height:420px;overflow-y:auto"><table id=log></table></div>
<h2>Last 24 hours by program</h2><div class=wrap><table id=day></table></div>
<h2>Your services <span class=dim style="font-weight:400">(systemd --user: switch on / off with the panel token)</span></h2>
<div class=wrap><table id=svc></table></div>
<h2>Every listening port <span class=dim style="font-weight:400">(click a row for its connections)</span></h2>
<div class=wrap><table id=ports></table></div>
<footer>Lion Studio - Container Port Dash · <a href="https://github.com/sunnychase">Created by Sunny Chase</a> in collaboration with Claude (Anthropic) ·
TCP traffic comes from the kernel's per-connection byte counters every few seconds, and every connection is recorded when it
closes (a short one that opened and closed between two samples is logged with its bytes but without its program); UDP has no byte counters. A program running as root can hide from any tool on the same machine: confirm on the router.</footer>
<div id=dlg><div class=b><h3 id=dt style="margin:0 0 8px">Kill</h3><div id=dd></div>
<label class=dim for=pw id=pwl>Login password</label><input id=pw type=password autocomplete=current-password>
<div class=btns><button onclick="closeDlg()">Cancel</button><button class=go id=go onclick="doKill()">Kill</button></div><div id=dm style="margin-top:8px"></div></div></div>
<script>
const $=id=>document.getElementById(id),esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const B=n=>{n=+n||0;const u=["B","KB","MB","GB","TB"];let i=0;while(n>=1000&&i<4){n/=1000;i++}return (i?n.toFixed(n<10?1:0):n.toFixed(0))+" "+u[i]};
const R=n=>(+n||0)<1?"–":B(n)+"/s",ago=t=>{const s=Date.now()/1000-t;return s<90?"just now":s<5400?Math.round(s/60)+" min ago":s<129600?Math.round(s/3600)+" h ago":Math.round(s/86400)+" d ago"};
const W=w=>w=="internet"?"net":w=="LAN"?"lan":"loc";
let busy=false,open=new Set(),scope="internet",D=null,kkey=null;
function flt(s){scope=s;$("fi").classList.toggle("on",s=="internet");$("fl").classList.toggle("on",s!="internet");draw();loadLog()}
function tok(){let t="";try{t=localStorage.getItem("sptok")||""}catch(e){}if(!t){t=prompt("Panel token:")||"";try{localStorage.setItem("sptok",t)}catch(e){}}return t}
async function load(){if(busy)return;try{D=await (await fetch("/api/state",{cache:"no-store"})).json()}catch(e){$("hdr").textContent="no answer from the machine";return}draw()}
function draw(){const d=D;if(!d)return;
 $("lgh").innerHTML=`(every connection to another machine as it opens and closes, short ones too · kept ${d.log_days} days${d.short?` · ${d.short} short ones since start`:""})`;
 $("lgd").innerHTML=d.days.length?"download: "+d.days.slice(0,7).map(x=>`<a href="/api/log/${x}.jsonl" download>${x}</a>`).join(" · "):"";
 $("hdr").innerHTML=`${d.ports.length} listening ports · ${esc(d.when)} · samples every ${d.sample_s} s · counting since ${new Date(d.started*1000).toLocaleString()}${d.learning?" · <b>learning what is normal (first 30 min): no NEW alerts yet</b>":""}${d.demo?" · <b>DEMO: made-up data</b>":""} · <a href="/api/state">JSON</a>`;
 $("alerts").innerHTML=d.alerts.slice(0,6).map(a=>`<div class="al ${esc(a.kind)}"><span class=t>${ago(a.t)}</span>${esc(a.text)}</div>`).join("");
 const ds=d.dest.filter(e=>scope=="all"||e.where=="internet"),mx=Math.max(1,...ds.map(e=>e.up_s));
 $("dest").innerHTML=`<tr><th>Program / service</th><th>Other end</th><th>Where</th><th class=hide-s>What</th><th class=n>Now ↑ sent</th><th class=n>Now ↓ recv</th><th class=n>24 h ↑</th><th class=n>24 h ↓</th><th class="n hide-s">Conns</th><th class=hide-s>First seen</th></tr>`+
  (ds.length?ds.map(e=>`<tr><td><b>${esc(e.owner)}</b></td><td>${e.name?esc(e.name)+"<br>":""}<span class=cmd>${esc(e.ip)}</span></td><td class=${W(e.where)}>${esc(e.where)}</td><td class=hide-s>${esc(e.service)}${e.dir=="in"?' <span class=tag>they connected in</span>':""}</td>
  <td class="n up">${R(e.up_s)}${e.up_s>=1?`<span class=bar style="width:${Math.max(3,60*e.up_s/mx)}px"></span>`:""}</td><td class="n dn">${R(e.down_s)}</td><td class="n up">${B(e.sent)}</td><td class="n dn">${B(e.recv)}</td><td class="n hide-s">${e.conns||""}</td>
  <td class=hide-s>${e.new?'<span class="tag new">NEW</span> ':""}${ago(e.first)}</td></tr>`).join(""):`<tr><td colspan=10 class=dim>nothing yet</td></tr>`);
 $("udp").innerHTML=d.udp_out.length?"UDP to the internet (no byte counters for UDP): "+d.udp_out.map(u=>`${esc(u.owner)} → ${esc(u.name||u.ip)}:${u.port}`).join(" · "):"";
 $("day").innerHTML=`<tr><th>Program / service</th><th class=n>↑ to internet</th><th class=n>↓ from internet</th><th class=n>↑ to LAN</th><th class=n>↓ from LAN</th></tr>`+
  (d.day.length?d.day.map(r=>`<tr><td><b>${esc(r[0])}</b></td><td class="n up">${B(r[1])}</td><td class="n dn">${B(r[2])}</td><td class=n>${B(r[3])}</td><td class=n>${B(r[4])}</td></tr>`).join(""):`<tr><td colspan=5 class=dim>nothing yet</td></tr>`);
 $("svc").innerHTML=`<tr><th>On</th><th>Service</th><th>Ports</th><th>State</th><th class=hide-s>Description</th></tr>`+d.services.map(s=>{const on=s.active=="active";
  return `<tr><td>${s.temporary?`<span class=tag title="a temporary unit: turning it off would delete it">temporary</span>`:`<label class=sw><input type=checkbox ${on?"checked":""} data-u="${esc(s.unit)}" onchange="sw(this)"><span class=sl></span></label>`}</td><td><b>${esc(s.unit)}</b></td><td class=p>${esc(s.ports.join(", "))}</td><td>${esc(s.active)} <span class=dim>${esc(s.sub)}${s.enabled=="disabled"?" · disabled":""}</span></td><td class="dim hide-s">${esc(s.description)}</td></tr>`}).join("");
 $("ports").innerHTML=`<tr><th>Port</th><th>Reach</th><th>What it is</th><th class=hide-s>Owner</th><th class=n>Conns</th><th class=n>↓ in</th><th class=n>↑ out</th><th></th></tr>`+d.ports.map(r=>{
  const own=r.container?"container "+r.container.name:r.unit||r.process||r.user;const o=open.has(r.key);
  return `<tr class=x onclick="tg('${esc(r.key)}')"><td class=p>${r.port}<span class=dim style="font-weight:400">/${esc(r.proto)}</span></td><td class=${r.reach=="this machine only"?"loc":"lan"}>${esc(r.reach)}</td><td>${esc(r.description)}</td><td class=hide-s>${esc(own)}<br><span class=dim>${esc(r.user)}</span></td>
  <td class=n>${r.proto=="udp"?'<span class=dim title="no counters for UDP">–</span>':r.conns||""}</td><td class="n dn">${R(r.in_s)}</td><td class="n up">${R(r.out_s)}</td>
  <td>${r.killable&&d.kill?`<button class=kill onclick="event.stopPropagation();ask('${esc(r.key)}')">Kill</button>`:`<span class=tag title="${esc(r.kill_note)}">view only</span>`}</td></tr>`+
  (o?`<tr><td></td><td colspan=7><div class=cmd>${r.ips.map(esc).join(", ")} port ${r.port} · ${r.pid?"PID "+esc(r.pid)+" · "+esc(r.cmd):r.container?"container "+esc(r.container.name)+" · id "+esc(r.container.id.slice(0,12))+(r.container.image?" · image "+esc(r.container.image):""):esc(r.kill_note||r.unit||"")}${r.via?" · "+esc(r.via):""}</div>
  ${r.peers.length?`<table style="margin-top:6px"><tr><th>Connected from</th><th>Where</th><th class=n>Conns</th><th class=n>↓ in</th><th class=n>↑ out</th></tr>${r.peers.map(p=>`<tr><td>${esc(p.name||p.ip)}${p.name?` <span class=cmd>${esc(p.ip)}</span>`:""}</td><td class=${W(p.where)}>${esc(p.where)}</td><td class=n>${p.conns}</td><td class="n dn">${R(p.in_s)}</td><td class="n up">${R(p.out_s)}</td></tr>`).join("")}</table>`:`<div class=dim>no open connections</div>`}</td></tr>`:"")}).join("")}
let lq="",lt=0;
async function loadLog(){let j=[];try{j=await (await fetch(`/api/log?scope=${scope}&q=${encodeURIComponent(lq)}`,{cache:"no-store"})).json()}catch(e){}
 $("log").innerHTML=`<tr><th>Time</th><th></th><th>Program / service</th><th>Other end</th><th>Where</th><th class=n>↑ sent</th><th class=n>↓ recv</th><th class=hide-s>Local</th></tr>`+
  (j.length?j.map(r=>`<tr><td class=n>${new Date(r.t*1000).toLocaleString([], {month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"})}</td><td><span class=tag>${esc(r.ev)}${r.dir=="in"?" in":""}</span>${r.short?' <span class="tag new" title="opened and closed between two samples">short</span>':""}</td>
  <td><b>${esc(r.owner)}</b></td><td>${r.name?esc(r.name)+" ":""}<span class=cmd>${esc(r.remote)}</span></td><td class=${W(r.where)}>${esc(r.where)}</td><td class="n up">${r.sent==null?"–":B(r.sent)}</td><td class="n dn">${r.recv==null?"–":B(r.recv)}</td><td class="cmd hide-s">${esc(r.local)}</td></tr>`).join(""):`<tr><td colspan=8 class=dim>no connections recorded yet</td></tr>`)}
$("lq").addEventListener("input",e=>{lq=e.target.value;clearTimeout(lt);lt=setTimeout(loadLog,300)});
function tg(k){open.has(k)?open.delete(k):open.add(k);draw()}
async function ask(k){kkey=k;$("dm").textContent="";$("pw").value="";$("dd").innerHTML="loading…";$("dlg").style.display="flex";busy=true;
 let j;try{j=await (await fetch("/api/plan?key="+encodeURIComponent(k))).json()}catch(e){j={error:String(e)}}
 if(j.error){$("dd").innerHTML=`<p class=up>${esc(j.error)}</p>`;$("go").disabled=true;return}$("go").disabled=false;
 $("dt").textContent="Kill "+j.target;$("dd").innerHTML=`<p class=dim>${esc(j.description)}</p><ul>${j.steps.map(s=>`<li>${esc(s)}</li>`).join("")}</ul>`;
 $("pwl").textContent=`Login password of ${j.login}`;setTimeout(()=>$("pw").focus(),50)}
function closeDlg(){$("dlg").style.display="none";$("pw").value="";busy=false;load()}
async function doKill(){const pw=$("pw").value;if(!pw){$("dm").textContent="type the password";return}$("go").disabled=true;$("dm").textContent="checking the password…";
 let r,j={};try{r=await fetch("/api/kill",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({key:kkey,password:pw})});j=await r.json()}catch(e){j={error:String(e)}}
 $("pw").value="";$("go").disabled=false;
 if(r&&r.ok){$("dm").innerHTML=`<span class=dn>${esc(j.result)}</span>`;setTimeout(closeDlg,1400)}else $("dm").innerHTML=`<span class=up>${esc(j.error||"failed")}</span>`}
$("pw").addEventListener("keydown",e=>{if(e.key=="Enter")doKill();if(e.key=="Escape")closeDlg()});
async function sw(el){const u=el.dataset.u,on=el.checked;
 if(!on&&!confirm(`Turn OFF ${u}?\n\nIts ports stop answering until you switch it back on.`)){el.checked=true;return}
 const t=tok();if(!t){el.checked=!on;return}busy=true;el.disabled=true;$("msg").textContent=`${on?"starting":"stopping"} ${u}…`;
 let j={},r;try{r=await fetch("/api/toggle",{method:"POST",headers:{"X-Token":t,"Content-Type":"application/json"},body:JSON.stringify({unit:u,on})});j=await r.json()}catch(e){j={error:String(e)}}
 if(r&&r.status==403){try{localStorage.removeItem("sptok")}catch(e){}}
 $("msg").textContent=j.error&&(!r||!r.ok)?`⚠ ${u}: ${j.error}`:`${u}: ${j.active}`;busy=false;el.disabled=false;load()}
load();loadLog();setInterval(load,4000);setInterval(()=>{if(!busy)loadLog()},8000);
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, indent=1)
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(b)

    def _body(self):
        try:
            return json.loads(self.rfile.read(min(int(self.headers.get("Content-Length", "0")), 4096)) or b"{}")
        except ValueError:
            return None

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/state":
            self._send(200, state())
        elif u.path == "/api/plan":
            key = (parse_qs(u.query).get("key") or [""])[0]
            rows = ports()
            row = next((r for r in rows if r["key"] == key), None)
            if not row:
                return self._send(404, {"error": "that port is not open any more"})
            if not row["killable"]:
                return self._send(403, {"error": row["kill_note"]})
            p = kill_plan(row, rows)
            self._send(200, {**p, "description": row["description"], "login": LOGIN or "demo"})
        elif u.path == "/api/log":
            qs = parse_qs(u.query)
            self._send(200, read_log((qs.get("q") or [""])[0][:100], (qs.get("scope") or ["internet"])[0], 300))
        elif u.path.startswith("/api/log/") and re.fullmatch(r"/api/log/\d{4}-\d{2}-\d{2}\.jsonl", u.path):
            try:
                body = open(os.path.join(LOGDIR, u.path.rsplit("/", 1)[1])).read()
            except OSError:
                return self._send(404, {"error": "no log for that day"})
            self._send(200, body, "application/x-ndjson")
        elif u.path in ("/", "/index.html"):
            self._send(200, PAGE, "text/html; charset=utf-8")
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        client = self.client_address[0]
        if self.path == "/api/toggle":
            t = token()
            if not t or not hmac.compare_digest(self.headers.get("X-Token", ""), t):
                return self._send(403, {"error": "wrong or missing token"})
            b = self._body()
            if b is None:
                return self._send(400, {"error": "bad JSON"})
            code, res = toggle(str(b.get("unit", "")), bool(b.get("on")))
            audit(client, "switch " + ("on" if b.get("on") else "off"), str(b.get("unit", "")), res.get("active") or res.get("error"))
            return self._send(code, res)
        if self.path == "/api/kill":
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self._send(415, {"error": "JSON only"})
            b = self._body()
            if b is None:
                return self._send(400, {"error": "bad JSON"})
            with _lock:
                wait = locked(client)
            if wait:
                return self._send(429, {"error": f"too many wrong passwords: try again in {wait} min"})
            rows = ports()
            row = next((r for r in rows if r["key"] == str(b.get("key", ""))), None)
            if not row or not row["killable"]:
                return self._send(403, {"error": row["kill_note"] if row else "that port is not open any more"})
            plan = kill_plan(row, rows)
            try:
                ok = password_ok(str(b.get("password", "")))
            except RuntimeError as e:
                return self._send(503, {"error": str(e)})
            if not ok:
                with _lock:
                    _fails["by"].setdefault(client, []).append(time.time())
                    _fails["all"].append(time.time())
                audit(client, "kill", plan["target"], "wrong password")
                return self._send(403, {"error": "wrong password"})
            done, text = do_kill(plan)
            audit(client, "kill", plan["target"], text)
            try:
                TR.sample(parse_ss(run_ss()), owner_label)          # the page shows the port gone at once
            except Exception:
                pass
            return self._send(200 if done else 500, {"result" if done else "error": text})
        self._send(404, {"error": "not found"})

    def log_message(self, *a):
        pass


def main():
    global TR
    os.makedirs(DATA, exist_ok=True)
    TR = Traffic()
    TR.sample(parse_ss(run_ss()), owner_label)
    threading.Thread(target=sampler, daemon=True).start()
    threading.Thread(target=events, daemon=True).start()
    srv = ThreadingHTTPServer((BIND, PORT), H)
    cert, key = os.path.join(DATA, "tls", "cert.pem"), os.path.join(DATA, "tls", "key.pem")
    if os.path.exists(cert) and os.path.exists(key):                  # optional HTTPS: the password then never crosses the LAN in clear
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
