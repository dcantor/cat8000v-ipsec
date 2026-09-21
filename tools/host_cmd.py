#!/usr/bin/env python3
"""The LAN hosts (Alpine, one behind every router) over SSH (paramiko, lab / lab).
   host_cmd.py run HOST CMD        run a command on one host (HOST = name from lab.conf or an address)
   host_cmd.py matrix [--json] [host ...]   ping every host from every other host over their LANs / the tunnels; prints the matrix
                                            (exit 1 unless every pair answers)"""
import concurrent.futures, json, os, re, subprocess, sys
from pathlib import Path
import paramiko

LAB_DIR = Path(__file__).resolve().parents[1]
USER, PASS = os.environ.get("HOST_USERNAME", "lab"), os.environ.get("HOST_PASSWORD", "lab")


def hosts():
    """name -> {mgmt_ip, lan_ip, router} from lab.conf (via lab.sh status, which resolves the LAN link)."""
    out = {}
    for line in subprocess.run([str(LAB_DIR / "lab.sh"), "status"], capture_output=True, text=True, check=True).stdout.splitlines():
        m = re.match(r"^(\S+)\s+host\s+\S+\s+(\S+)\s+\S+\s+(\S+) \(LAN of (\S+)\)", line)
        if m: out[m[1]] = {"mgmt_ip": m[2], "lan_ip": m[3], "router": m[4]}
    return out


def run(host, cmd, timeout=60):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, username=USER, password=PASS, timeout=20, look_for_keys=False, allow_agent=False)
    try:
        _, out, err = c.exec_command(cmd, timeout=timeout)
        rc = out.channel.recv_exit_status(); text = out.read().decode() + err.read().decode()
    finally: c.close()
    return rc, text


def matrix(names=None, count=2):
    inv = hosts(); names = names or sorted(inv, key=lambda n: (not n.startswith("host-") or "spoke" in n, n))
    def row(src):
        # one SSH session per source: every destination pinged from there, sequentially
        cmd = " ; ".join(f"ping -c {count} -W 2 -q {inv[d]['lan_ip']} >/dev/null 2>&1 && echo {d}=ok || echo {d}=FAIL" for d in names if d != src)
        try: return src, dict(x.split("=") for x in run(inv[src]["mgmt_ip"], cmd, timeout=len(names) * count * 4 + 20)[1].split())
        except Exception as e:  # noqa: BLE001
            return src, {d: f"ssh:{e.__class__.__name__}" for d in names if d != src}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex: res = dict(ex.map(row, names))
    return {"hosts": {n: inv[n] for n in names}, "results": res, "ok": all(v == "ok" for r in res.values() for v in r.values()),
            "pairs": sum(len(r) for r in res.values()), "failed": [(s, d) for s, r in res.items() for d, v in r.items() if v != "ok"]}


if __name__ == "__main__":
    if sys.argv[1] == "run":
        inv = hosts(); host = inv[sys.argv[2]]["mgmt_ip"] if sys.argv[2] in inv else sys.argv[2]
        rc, text = run(host, " ".join(sys.argv[3:])); print(text, end=""); sys.exit(rc)
    elif sys.argv[1] == "matrix":
        as_json = "--json" in sys.argv; names = [a for a in sys.argv[2:] if a != "--json"] or None
        m = matrix(names)
        if as_json: print(json.dumps(m, indent=2)); sys.exit(0 if m["ok"] else 1)
        names = list(m["hosts"]); w = max(len(n) for n in names) + 2
        print(f"{'from \\ to':{w}s}" + "".join(f"{t:>{w}s}" for t in names))
        for src in names:
            print(f"{src:{w}s}" + "".join(f"{'·' if d == src else ('ok' if m['results'][src].get(d) == 'ok' else 'FAIL'):>{w}s}" for d in names))
        print(f"\n{m['pairs'] - len(m['failed'])}/{m['pairs']} pairs reachable" + (f"; failed: {', '.join(f'{s}->{d}' for s, d in m['failed'])}" if m["failed"] else " — full mesh"))
        sys.exit(0 if m["ok"] else 1)
    else: sys.exit(__doc__)
