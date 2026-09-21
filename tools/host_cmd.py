#!/usr/bin/env python3
"""The LAN hosts (Alpine, one behind every router) over SSH (paramiko, lab / lab).
   host_cmd.py run HOST CMD        run a command on one host (HOST = name from lab.conf or an address)
   host_cmd.py matrix [--json] [host ...]   ping every host from every other host over their LANs / the tunnels; prints the matrix
                                            (exit 1 unless every pair answers)"""
import concurrent.futures, json, os, re, subprocess, sys, threading
from pathlib import Path
import paramiko

LAB_DIR = Path(__file__).resolve().parents[1]
USER, PASS = os.environ.get("HOST_USERNAME", "lab"), os.environ.get("HOST_PASSWORD", "lab")


def hosts():
    """name -> {mgmt_ip, lan_ip, router} from lab.conf (via lab.sh status, which resolves the LAN link)."""
    out = {}
    for line in subprocess.run([str(LAB_DIR / "lab.sh"), "status"], capture_output=True, text=True, check=True).stdout.splitlines():
        m = re.match(r"^(\S+)\s+host\s+\S+\s+(\S+)\s+\S+\s+(\S+) \(LAN of (\S+)\)", line)
        if m: out[m[1]] = {"mgmt_ip": m[2], "lan_ip": m[3], "router": m[4], "gateway": m[3].rsplit(".", 1)[0] + ".1"}   # the router's LAN port is .1 of the /24
    return out


_sessions, _session_lock = {}, threading.Lock()


def _client(host):
    """One SSH session per host, kept open between calls (the live mesh polls every few seconds); reopened when it dropped."""
    with _session_lock:
        c = _sessions.get(host)
        if c is not None and c.get_transport() is not None and c.get_transport().is_active(): return c
        c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(host, username=USER, password=PASS, timeout=20, look_for_keys=False, allow_agent=False, banner_timeout=30)
        _sessions[host] = c; return c


def run(host, cmd, timeout=60):
    c = _client(host)
    try:
        _, out, err = c.exec_command(cmd, timeout=timeout)
        rc = out.channel.recv_exit_status(); text = out.read().decode() + err.read().decode()
    except Exception:
        with _session_lock: _sessions.pop(host, None)
        raise
    return rc, text


INTERNET = os.environ.get("MESH_INTERNET_TARGET", "1.1.1.1")   # the extra column: every host must reach the internet through its headend's breakout
EXTRA = ("gateway", "internet")


def matrix(names=None, count=2):
    """Every host pings every other host's LAN address, its own router (the gateway) and the internet (1.1.1.1 through the breakout):
    results[src][dst] = {"ok", "ms" (average round trip), "loss"}; dst is a host name, "gateway" or "internet"."""
    inv = hosts(); names = names or sorted(inv, key=lambda n: (not n.startswith("host-") or "spoke" in n, n))
    def targets(src): return [(d, inv[d]["lan_ip"]) for d in names if d != src] + [("gateway", inv[src]["gateway"]), ("internet", INTERNET)]
    def row(src):
        # one SSH session per source: every destination pinged from there, sequentially; busybox prints "round-trip min/avg/max = a/b/c ms"
        cmd = " ; ".join(f"echo '{d}=' $(ping -c {count} -W 1 -q {ip} 2>/dev/null | grep -E 'packets transmitted|round-trip' | tr '\\n' ' ')" for d, ip in targets(src))
        try:
            out = run(inv[src]["mgmt_ip"], cmd, timeout=len(names) * count * 3 + 20)[1]; res = {}
            for line in out.splitlines():
                if "=" not in line: continue
                d, rest = line.split("=", 1); m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", rest); r = re.search(r"= [\d.]+/([\d.]+)/", rest)
                got = int(m.group(2)) if m else 0
                res[d.strip()] = {"ok": got > 0, "ms": round(float(r.group(1)), 2) if r else None, "loss": (int(m.group(1)) - got) if m else count}
            return src, {d: res.get(d, {"ok": False, "ms": None, "loss": count}) for d, _ in targets(src)}
        except Exception as e:  # noqa: BLE001
            return src, {d: {"ok": False, "ms": None, "loss": count, "error": f"ssh:{e.__class__.__name__}"} for d, _ in targets(src)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex: res = dict(ex.map(row, names))
    return {"hosts": {n: inv[n] for n in names}, "results": res, "count": count, "targets": {"gateway": "the host's own router (LAN .1)", "internet": INTERNET},
            "ok": all(v["ok"] for r in res.values() for v in r.values()),
            "pairs": sum(len(r) for r in res.values()), "failed": [(s, d) for s, r in res.items() for d, v in r.items() if not v["ok"]]}


if __name__ == "__main__":
    if sys.argv[1] == "run":
        inv = hosts(); host = inv[sys.argv[2]]["mgmt_ip"] if sys.argv[2] in inv else sys.argv[2]
        rc, text = run(host, " ".join(sys.argv[3:])); print(text, end=""); sys.exit(rc)
    elif sys.argv[1] == "matrix":
        as_json = "--json" in sys.argv; names = [a for a in sys.argv[2:] if a != "--json"] or None
        m = matrix(names)
        if as_json: print(json.dumps(m, indent=2)); sys.exit(0 if m["ok"] else 1)
        names = list(m["hosts"]); cols = names + list(EXTRA); w = max(len(n) for n in cols) + 2
        print(f"{'from \\ to':{w}s}" + "".join(f"{t:>{w}s}" for t in cols))
        for src in names:
            cell = lambda d: '·' if d == src else (f"{m['results'][src][d]['ms']} ms" if m['results'][src][d]['ok'] and m['results'][src][d]['ms'] is not None else ('ok' if m['results'][src][d]['ok'] else 'FAIL'))
            print(f"{src:{w}s}" + "".join(f"{cell(d):>{w}s}" for d in cols))
        print(f"\n{m['pairs'] - len(m['failed'])}/{m['pairs']} checks ok (host to host, host to its gateway, host to the internet {INTERNET})" + (f"; failed: {', '.join(f'{s}->{d}' for s, d in m['failed'])}" if m["failed"] else " — everything reachable"))
        sys.exit(0 if m["ok"] else 1)
    else: sys.exit(__doc__)
