#!/usr/bin/env python3
"""Rename a router everywhere it is known: libvirt domain, nodes/<name>/, lab.conf, lab-intent.json and the
Terraform state (state mv, so the rename is a hostname change, not a destroy/create of the router's config).
Nautobot follows on the next seed (devices are matched by management IP).  The VM must be stopped.
Usage: rename_node.py OLD NEW"""
import json, os, re, shutil, subprocess, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent)); import intent as intent_mod   # noqa: E402

LAB = Path(__file__).resolve().parents[1]
old, new = sys.argv[1], sys.argv[2]
if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,30}", new): sys.exit("bad name")
C = intent_mod.lab_conf("ROLE")["ROLE"]
if old not in C and new not in C: sys.exit(f"{old} is not in lab.conf")
for n in (old, new):   # (every step below is skipped when already done, so a half-finished rename can be re-run)
    if subprocess.run(["virsh", "-c", "qemu:///system", "domstate", n], capture_output=True, text=True).stdout.strip() == "running": sys.exit(f"{n} is running: ./lab.sh down {n} first")

# libvirt + node directory
doms = subprocess.run(["virsh", "-c", "qemu:///system", "list", "--all", "--name"], capture_output=True, text=True).stdout.split()
if old in doms: subprocess.run(["virsh", "-c", "qemu:///system", "domrename", old, new], check=True, capture_output=True)
if (LAB / "nodes" / old).exists(): shutil.move(LAB / "nodes" / old, LAB / "nodes" / new)
d0 = LAB / "nodes" / new / "iosxe_config.txt"
if d0.exists(): d0.write_text(re.sub(rf"^hostname {re.escape(old)}$", f"hostname {new}", d0.read_text(), flags=re.M))

# lab.conf: array keys, link/tunnel tokens, node lists
p = LAB / "lab.conf"; s = p.read_text(); shutil.copy(p, LAB / "lab.conf.bak")
if old not in C: s = s   # already renamed
s = re.sub(rf"\[{re.escape(old)}\]=", f"[{new}]=", s)
s = re.sub(rf'(?<=["\s]){re.escape(old)}(?=:\d+)', new, s)                       # "old:port" in LINKS
s = re.sub(rf'^(\s*"\d+ )({re.escape(old)})( \S+ \S+")', rf"\g<1>{new}\g<3>", s, flags=re.M)     # tunnel hub
s = re.sub(rf'^(\s*"\d+ \S+ )({re.escape(old)})( \S+")', rf"\g<1>{new}\g<3>", s, flags=re.M)     # tunnel spoke
s = re.sub(rf"^(ROUTERS|ALL_NODES)=\((.*?)\)", lambda m: f"{m.group(1)}=({' '.join(new if x == old else x for x in m.group(2).split())})", s, flags=re.M)
p.write_text(s); subprocess.run(["bash", "-n", str(p)], check=True)
assert new in intent_mod.lab_conf("ROLE")["ROLE"] and old not in intent_mod.lab_conf("ROLE")["ROLE"]

# intent
I = intent_mod.load()
for d in I["devices"]:
    if d["name"] == old: d["name"] = new
for l in I["links"]:
    for k in ("a", "b"):
        if l[k] == old: l[k] = new
for t in I["tunnels"]:
    for k in ("hub", "spoke"):
        if t[k] == old: t[k] = new
problems = intent_mod.validate(I)
if problems: sys.exit("intent invalid after rename: " + "; ".join(problems))
intent_mod.save(I)

# terraform state: every resource keyed by the old device name
env = {**os.environ, "PATH": f"{Path.home()}/.local/bin:" + os.environ.get("PATH", "")}
res = subprocess.run(["terraform", "state", "list"], cwd=LAB / "nac", capture_output=True, text=True, env=env, check=True).stdout.split()
moved = 0
for r in res:
    for pat, rep in ((f'["{old}/', f'["{new}/'), (f'["{old}"]', f'["{new}"]')):
        if pat in r:
            subprocess.run(["terraform", "state", "mv", r, r.replace(pat, rep)], cwd=LAB / "nac", check=True, capture_output=True, text=True, env=env); moved += 1; break
# ...and the `device` attribute inside each moved resource (the provider looks the router up by it on refresh)
st = json.loads(subprocess.run(["terraform", "state", "pull"], cwd=LAB / "nac", capture_output=True, text=True, env=env, check=True).stdout)
n_attr = 0
for r in st.get("resources", []):
    for inst in r.get("instances", []):
        if inst.get("attributes", {}).get("device") == old: inst["attributes"]["device"] = new; n_attr += 1
if n_attr:
    st["serial"] = int(st.get("serial", 0)) + 1
    tmp = LAB / "nac" / ".rename.tfstate"; tmp.write_text(json.dumps(st))
    subprocess.run(["terraform", "state", "push", str(tmp)], cwd=LAB / "nac", check=True, capture_output=True, text=True, env=env); tmp.unlink()
print(f"renamed {old} -> {new}: libvirt domain, nodes/, lab.conf, intent, {moved} terraform resources ({n_attr} device attributes); next: ./lab.sh rebuild {new} && ./lab.sh up {new}, then nautobot seed/render/nac apply")
