#!/usr/bin/env python3
"""Download the running and startup configuration of every router into a directory."""
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "resources"))
from LabLib import LabLib          # noqa: E402
from lab_vars import ROUTERS       # noqa: E402

out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
lib = LabLib(); stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
try:
    for name, r in ROUTERS.items():
        for cmd, suffix in (("show running-config", "running-config"), ("show startup-config", "startup-config")):
            try:
                cfg = lib.run_command(r["host"], cmd, timeout=120)
            except Exception as e:      # a router that is down must not stop the capture
                print(f"[{name}] {cmd}: {e.__class__.__name__}: {e}"); continue
            path = out / f"{name}.{suffix}.txt"
            path.write_text(f"! {name} ({r['host']}) {cmd} captured {stamp}\n{cfg}\n")
            print(f"[{name}] {path} ({len(cfg)} bytes)")
finally:
    lib.close_all_connections()
