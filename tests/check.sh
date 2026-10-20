#!/bin/bash
# Created by Sunny Chase (https://github.com/sunnychase) in collaboration with Claude (Anthropic) · Lion Studio - Container Port Dash
# tests/check.sh -- syntax, the ss parser, the owner rules, and the page in demo mode (made-up data): state, the Kill plan, a system
# port refused, wrong passwords refused then locked out, the right one acting, the connection log; then the privacy grep.
set -u
cd "$(dirname "$0")/.."
fail=0
tmp=$(mktemp -d); trap 'kill $(cat "$tmp/pid" 2>/dev/null) 2>/dev/null; rm -rf "$tmp"' EXIT
echo "== syntax"
python3 -m py_compile app.py && bash -n run.sh && echo ok || fail=1

echo "== parser and owner rules"
python3 -W ignore - <<'PY' || fail=1
import os, sys
os.environ["PORTS_DATA"] = os.environ.get("TMPDIR", "/tmp")
sys.path.insert(0, ".")
import app
bad = []
def check(c, what):
    print(("ok   " if c else "FAIL ") + what); c or bad.append(what)
txt = """tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* ino:20181 sk:1 cgroup:/system.slice/ssh.socket <->
tcp LISTEN 0 5 [::1]:8530 [::]:* uid:1000 ino:5 sk:2 cgroup:/user.slice/user-1000.slice/user@1000.service/app.slice/web.service <->
udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* uid:992 ino:7 sk:3 cgroup:/system.slice/systemd-resolved.service <->
tcp ESTAB 0 0 [::ffff:192.0.2.10]:40112 198.51.100.7:443 uid:1000 ino:9 sk:4a cgroup:/system.slice/docker-""" + "ab" * 32 + """.scope <->
\t cubic wscale:7,7 bytes_sent:1234 bytes_acked:1235 bytes_received:98765 segs_out:4
"""
r = app.parse_ss(txt)
check(len(r) == 4, f"four sockets parsed ({len(r)})")
check((r[0]["ip"], r[0]["port"], r[0]["uid"]) == ("0.0.0.0", 22, 0), "IPv4 listener, root (no uid field)")
check((r[1]["ip"], r[1]["port"], r[1]["uid"]) == ("::1", 8530, 1000), "IPv6 listener in brackets")
check(r[2]["ip"] == "127.0.0.53", "interface suffix (%lo) dropped")
check((r[3]["ip"], r[3]["rip"], r[3]["sent"], r[3]["recv"], r[3]["sk"]) == ("192.0.2.10", "198.51.100.7", 1234, 98765, "4a"),
      "IPv4-mapped address, byte counters from the info line, socket cookie")
o = [app.owner_of(x["cgroup"]) for x in r]
check(o[0] == {"kind": "system", "unit": "ssh.socket"}, f"system socket unit ({o[0]})")
check(o[1]["kind"] == ("unit" if os.getuid() == 1000 else "other") and o[1]["unit"] == "web.service", f"user service ({o[1]})")
check(o[3] == {"kind": "container", "id": "ab" * 32}, "container by its cgroup")
check(app.owner_of("/system.slice/docker.service")["kind"] == "proxy", "docker-proxy (a published port)")
check(app.where("10.1.2.3") == "LAN" and app.where("8.8.8.8") == "internet" and app.where("127.0.0.1") == "this machine", "where a peer is")
check(app.killable({"kind": "system", "user": "root", "unit": "ssh.socket"})[0] is False, "a system service is view only")
print(f"{'all' if not bad else len(bad)} parser checks {'passed' if not bad else 'FAILED'}")
sys.exit(1 if bad else 0)
PY

echo "== the page in demo mode (made-up data)"
PORTS_DEMO=1 PORTS_DATA="$tmp" PORTS_PORT=18660 PORTS_BIND=127.0.0.1 PORTS_LAN=192.0.2.0/24 python3 -W ignore app.py > "$tmp/log" 2>&1 & echo $! > "$tmp/pid"
for i in $(seq 30); do curl -s -o /dev/null http://127.0.0.1:18660/api/state && break; sleep 0.5; done
sleep 25
python3 - <<'PY' || fail=1
import json, urllib.request, urllib.error
B = "http://127.0.0.1:18660"
bad = []
def check(c, what):
    print(("ok   " if c else "FAIL ") + what); c or bad.append(what)
def get(p):
    return json.load(urllib.request.urlopen(B + p))
def post(p, body):
    rq = urllib.request.Request(B + p, json.dumps(body).encode(), {"Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(rq); return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)
d = get("/api/state")
check(len(d["ports"]) >= 10 and any(r["kind"] == "self" for r in d["ports"]), f'{len(d["ports"])} ports, this page marked as itself')
check(all(r["description"] for r in d["ports"]), "every port has a description")
up = [e for e in d["dest"] if e["owner"] == "report-builder.service"]
check(up and up[0]["where"] == "internet" and up[0]["sent"] > 0, "data sent to the internet is counted per program")
check(any(a["kind"] == "new" for a in d["alerts"]), f'a NEW destination raised an alert ({[a["text"][:60] for a in d["alerts"]][:2]})')
check(d["short"] > 0 and any(r.get("short") for r in get("/api/log?scope=all")), "short connections are recorded in the log")
check(get("/api/log?q=snapcraft&scope=all") and all("snapcraft" in json.dumps(r) for r in get("/api/log?q=snapcraft&scope=all")), "log search")
ssh = next(r for r in d["ports"] if r["port"] == 22)
c, j = post("/api/kill", {"key": ssh["key"], "password": "demo"})
check(c == 403 and "view only" in j["error"], f"Kill on a system port is refused even with the right password ({c})")
rb = next(r for r in d["ports"] if r["port"] == 8010)
plan = get("/api/plan?key=" + urllib.request.quote(rb["key"]))
check(any("disable" in s for s in plan["steps"]), "the plan says what Kill will do")
codes = [post("/api/kill", {"key": rb["key"], "password": "wrong"})[0] for _ in range(6)]
check(codes[:5] == [403] * 5 and codes[5] == 429, f"wrong passwords refused, then locked out ({codes})")
print(f"{'all' if not bad else len(bad)} page checks {'passed' if not bad else 'FAILED'}")
raise SystemExit(1 if bad else 0)
PY
kill "$(cat "$tmp/pid")" 2>/dev/null; sleep 1
rm -f "$tmp/traffic.json"
PORTS_DEMO=1 PORTS_DATA="$tmp" PORTS_PORT=18661 PORTS_BIND=127.0.0.1 python3 -W ignore app.py > "$tmp/log2" 2>&1 & echo $! > "$tmp/pid"
for i in $(seq 30); do curl -s -o /dev/null http://127.0.0.1:18661/api/state && break; sleep 0.5; done
python3 - <<'PY' || fail=1
import json, urllib.request
B = "http://127.0.0.1:18661"
d = json.load(urllib.request.urlopen(B + "/api/state"))
k = next(r["key"] for r in d["ports"] if r["port"] == 8888)
rq = urllib.request.Request(B + "/api/kill", json.dumps({"key": k, "password": "demo"}).encode(), {"Content-Type": "application/json"})
r = json.load(urllib.request.urlopen(rq))
d2 = json.load(urllib.request.urlopen(B + "/api/state"))
ok = "stopped" in r.get("result", "") and not any(x["port"] == 8888 for x in d2["ports"])
print(("ok   " if ok else "FAIL ") + f"the right password stops the container and its port goes away ({r})")
raise SystemExit(0 if ok else 1)
PY
grep -q '"wrong password"' "$tmp/audit.log" && ! grep -q '"demo"' "$tmp/audit.log" && echo "ok   the audit log records attempts, never a password" || { echo "FAIL audit log"; fail=1; }

echo "== hygiene: home paths, private addresses, token-shaped strings, e-mail addresses"
hits=$( { git grep -I -n -E 'hf_[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|sk-[A-Za-z0-9]{32,}|AKIA[0-9A-Z]{16}' -- .
  git grep -I -n -E '(^|[^A-Za-z0-9_.-])/home/[a-z]|192\.168\.[0-9]|\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b|\b172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b' -- . ':!tests/check.sh' ':!app.py'
  git grep -I -n -E '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' -- . | grep -v -E 'noreply|example\.(com|org|net)|@v[0-9]|user@\$|user@[0-9]+\.service|user@\\d'
} 2>/dev/null | cut -c1-200)
[ -z "$hits" ] && echo clean || { echo "$hits"; fail=1; }
[ "$fail" = 0 ] && echo "ALL CHECKS PASSED" || echo "CHECKS FAILED"
exit "$fail"
