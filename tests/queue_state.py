#!/usr/bin/env python3
"""Is the portal's run queue busy? Prints one line describing the run that holds it, or nothing when it is free.

  tests/queue_state.py [--json]

Runs execute one at a time (one Terraform state, one intent), so a suite started while the portal is mid-run fails every
test that needs the queue. `tests/run.sh` waits on this. The portal is asked first; when it cannot be reached the run
records on disk are read instead (a record left `running` by a portal that died is ignored — the portal marks those
`interrupted` on start-up, and nothing is executing if the portal is not).
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
RUNS = LAB / "webapp" / "runs"
PORTAL = os.environ.get("PORTAL_URL", "http://127.0.0.1:8090")
BUSY = ("running", "queued")

a = argparse.ArgumentParser(description=__doc__.split("\n")[0])
a.add_argument("--json", action="store_true", help="print the run record instead of a sentence")
a = a.parse_args()


def from_portal():
    import requests
    s = requests.Session()
    s.post(f"{PORTAL}/api/login", json={"username": os.environ.get("PORTAL_USER", "viewer"),
                                        "password": os.environ.get("PORTAL_PASSWORD", "viewer")}, timeout=10)
    r = s.get(f"{PORTAL}/api/runs", timeout=20); r.raise_for_status()
    return [x for x in r.json() if x.get("status") in BUSY]


def from_disk():
    if subprocess.run(["pgrep", "-f", "uvicorn app:app"], capture_output=True).returncode != 0:
        return []                                             # no portal, nothing is executing
    out = []
    for f in RUNS.glob("*.json"):
        if f.name.endswith(".intent.json"): continue
        try: d = json.loads(f.read_text())
        except ValueError: continue
        if d.get("status") in BUSY: out.append(d)
    return out


try: busy = from_portal()
except Exception: busy = from_disk()                          # noqa: BLE001 — the portal may be down or restarting

mine = os.environ.get("PORTAL_RUN_ID")
busy = [r for r in busy if r.get("id") != mine]               # the run that started these tests does not block them
if not busy: sys.exit(0)

if a.json:
    print(json.dumps(busy, indent=1)); sys.exit(0)
r = sorted(busy, key=lambda x: x.get("started") or 0)[0]
who = (r.get("spoke") or {}).get("name") or "the whole lab"
age = int(time.time() - (r.get("started") or time.time()))
print(f"{r['id']} ({r.get('mode')} on {who}, {r.get('status')} for {age // 60}m{age % 60:02d}s, started by {r.get('user') or '?'})")
