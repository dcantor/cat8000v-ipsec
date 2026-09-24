#!/usr/bin/env python3
"""Live state of the data-centre interconnect: the DCI's twice-NAT, the aggregates it routes, and the two DNS zones.

The rest of the lab is watched through the tunnels (inventory.py); the interconnect has none. What matters there is that the
static translations are all still on the box (2002 of them, generated from one `scale` block — 2000 would mean a chunk of a
CLI template went missing), that nothing is being dropped for want of a translation, that the three aggregates are in the
routing table (they are what the two sides exchange instead of the overlapping prefixes), and that each zone still answers
with as many records as the model says. The DNS fix-up itself is proven by a packet capture, whose verdict the test run
leaves behind as JSON — read here so the dashboard and the alerts can see it too.

Collected over SSH with the same credentials as the inventory, cached for `ttl` seconds, and skipped entirely when the DCI
is not running.
"""
import json
import re
import sys
import threading
import time
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "nautobot"))
import intent as intent_mod                                    # noqa: E402

VERDICT = LAB / "results" / "latest" / "captures" / "verdict.json"   # written by tools/dns_capture.py during the test run


def expected(I=None):
    """What the model says the interconnect should hold: the NAT router, its static translations, the aggregates, the zones."""
    I = I or intent_mod.load()
    nat_router, nat = next(((d["name"], d["nat"]) for d in I["devices"] if d.get("nat")), (None, None))
    if not nat: return None
    entries, overlaps = intent_mod.nat_scale(nat), nat.get("overlaps") or []
    zones = {}
    for d in I["devices"]:
        dns = d.get("dns")
        if not dns: continue
        records = {**(dns.get("hosts") or {}), **intent_mod.dns_scale(dns, nat)}
        zones[d["name"]] = {"domain": dns.get("domain"), "records": len(records), "mgmt_ip": d["mgmt_ip"]}
    return {"router": nat_router, "mgmt_ip": next(d["mgmt_ip"] for d in I["devices"] if d["name"] == nat_router),
            "statics": 2 * (len(entries) + len(overlaps)), "prefixes": len(entries) + len(overlaps),
            "aggregates": intent_mod.nat_scale_aggregates(nat) or {}, "zones": zones}


def _int(m, i=1):
    return int(m.group(i)) if m else None


def collect(creds=("admin", "admin"), I=None):
    """One SSH session to the DCI and one to each zone server; returns what they hold against what the model says."""
    from netmiko import ConnectHandler
    exp = expected(I)
    if not exp: return None
    out = {"router": exp["router"], "expected": exp, "generated": time.time(), "errors": {}}

    try:
        c = ConnectHandler(device_type="cisco_xe", host=exp["mgmt_ip"], username=creds[0], password=creds[1], fast_cli=False, conn_timeout=20)
        try:
            stats = c.send_command("show ip nat statistics", read_timeout=120)
            out["translations"] = _int(re.search(r"Total active translations:\s+(\d+)", stats))
            out["statics"] = _int(re.search(r"\((\d+) static", stats))
            out["dynamic"] = _int(re.search(r"static,\s+(\d+) dynamic", stats))
            out["hits"] = _int(re.search(r"Hits:\s+(\d+)", stats))
            out["misses"] = _int(re.search(r"Misses:\s+(\d+)", stats))
            drops = re.search(r"In-to-out drops:\s+(\d+)\s+Out-to-in drops:\s+(\d+)", stats)
            out["in_to_out_drops"], out["out_to_in_drops"] = (_int(drops, 1), _int(drops, 2)) if drops else (None, None)
            out["aggregates"] = {}
            for kind, prefix in exp["aggregates"].items():
                net, plen = prefix.split("/")
                mask = ".".join(str((0xFFFFFFFF << (32 - int(plen)) >> s) & 0xFF) for s in (24, 16, 8, 0))
                r = c.send_command(f"show ip route {net} {mask}", read_timeout=60)
                src = re.search(r'Known via "([^"]+)"', r)                      # bgp 65208 / static / connected
                nh = re.search(r"^\s+\*?\s*([0-9]+(?:\.[0-9]+){3})", r, re.M) or re.search(r"directly connected,\s+(?:via\s+)?(\S+)", r)
                out["aggregates"][kind] = {"prefix": prefix, "present": f"Routing entry for {prefix}" in r,
                                           "source": src.group(1).split()[0] if src else None,
                                           "via": nh.group(1) if nh else None}
        finally: c.disconnect()
    except Exception as e:                                     # noqa: BLE001 — the DCI may be down or busy
        out["errors"][exp["router"]] = f"{e.__class__.__name__}: {e}"

    out["zones"] = {}
    for name, z in exp["zones"].items():
        try:
            c = ConnectHandler(device_type="cisco_xe", host=z["mgmt_ip"], username=creds[0], password=creds[1], fast_cli=False, conn_timeout=20)
            try:
                n = _int(re.search(r"=\s*(\d+)", c.send_command("show running-config | count ^ip host", read_timeout=180)))
                server = "ip dns server" in c.send_command("show running-config | include ^ip dns server", read_timeout=120)
            finally: c.disconnect()
            out["zones"][name] = {"domain": z["domain"], "records": n, "expected": z["records"], "server": server}
        except Exception as e:                                 # noqa: BLE001
            out["errors"][name] = f"{e.__class__.__name__}: {e}"
            out["zones"][name] = {"domain": z["domain"], "records": None, "expected": z["records"], "server": None}

    out["fixup"] = verdict()
    return out


def verdict(path=VERDICT):
    """The DNS fix-up verdict left by the last test run's packet capture (tools/dns_capture.py)."""
    try: v = json.loads(Path(path).read_text())
    except Exception: return None                              # noqa: BLE001 — no run has captured yet
    return v


class Interconnect:
    """The collector behind a cache that a **background thread** keeps warm.

    Collecting means three SSH sessions and a `show running-config | count` over a 2300-line configuration — ten to twenty
    seconds. Doing that inside a Prometheus scrape blows the scrape timeout and the portal's own `up` starts flapping, so the
    scrape only ever reads what the thread last put in the cache (and exports nothing until the first collection finishes)."""

    def __init__(self, creds=("admin", "admin"), ttl=60, enabled=None):
        self.creds, self.ttl, self._cache, self._lock = creds, ttl, None, threading.Lock()
        self.enabled = enabled or (lambda: True)        # e.g. "the DCI VM is running": don't SSH into a powered-off lab
        self._thread = None

    def start(self):
        if self._thread: return self
        self._thread = threading.Thread(target=self._loop, name="interconnect", daemon=True); self._thread.start()
        return self

    def _loop(self):
        while True:
            try:
                if self.enabled(): self.refresh()
                else:
                    with self._lock: self._cache = None
            except Exception:                            # noqa: BLE001 — a collector must not take the portal down
                pass
            time.sleep(self.ttl)

    def refresh(self):
        d = collect(self.creds)                          # outside the lock: this is the slow part
        with self._lock: self._cache = d
        return d

    def get(self, refresh=False):
        """What the thread last collected (None until the first cycle). `refresh=True` collects now — for a caller that can wait."""
        if refresh: return self.refresh()
        with self._lock: return self._cache


if __name__ == "__main__":
    print(json.dumps(collect(), indent=1, default=str))
