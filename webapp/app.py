#!/usr/bin/env python3
"""VPN provisioning portal for the C8000v IPsec lab.

A form (static/index.html) edits the lab intent (site / hostnames / metadata / tunnels / crypto / PSK); "Deploy"
runs the pipeline behind the scenes and streams its progress:

    validate intent -> save lab-intent.json -> Nautobot seed (source of truth) -> render NAC data from Nautobot
    -> terraform plan -> terraform apply (+ save config) -> Golden Config (backup/intended/compliance)
    -> Robot Framework tests -> report

Runs are executed one at a time in a background thread; state is kept in memory and mirrored to runs/<id>.json.
Start with ./lab.sh webapp (uvicorn on 0.0.0.0:8090).
"""
import json, os, re, subprocess, sys, threading, time, uuid, xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
import requests
from inventory import Inventory, to_csv
import spokes

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "nautobot")); import intent as intent_mod   # noqa: E402
RUNS_DIR = Path(__file__).resolve().parent / "runs"; RUNS_DIR.mkdir(exist_ok=True)
RESULTS = LAB / "results"
NAUTOBOT_URL = os.environ.get("NAUTOBOT_URL", "http://10.0.0.10:8080")
NAUTOBOT_PUBLIC_URL = os.environ.get("NAUTOBOT_PUBLIC_URL", "http://192.168.50.231:8080")
STEP_TITLES = {"validate": "Validate intent", "save": "Save intent", "nautobot": "Nautobot source of truth (seed)",
               "spoke_validate": "Validate spoke allocation", "spoke_labconf": "Register the spoke in lab.conf + day-0 config",
               "spoke_vm": "Create and boot the spoke VM", "spoke_bootstrap": "Bootstrap (day-0, license reload, RESTCONF)",
               "spoke_onboard": "Onboard the spoke into Nautobot", "spoke_intent": "Add the spoke to the intent (hub link, tunnel, BGP)",
               "hub_validate": "Validate hub allocation", "hub_labconf": "Register the hub in lab.conf + day-0 config (links to every spoke)",
               "hub_vm": "Create and boot the hub VM", "hub_bootstrap": "Bootstrap (day-0, license reload, RESTCONF)", "hub_onboard": "Onboard the hub into Nautobot",
               "hub_intent": "Add the hub, its links and tunnels to the intent",
               "rm_validate": "Validate removal", "rm_down": "Power off the spoke VM", "rm_nautobot": "Remove the spoke from Nautobot (tunnel, endpoints, BGP, device, addresses)",
               "rm_intent": "Remove from lab.conf and the intent", "rm_state": "Forget the spoke in the Terraform state", "rm_vm": "Delete the VM",
               "render": "Render NAC data from Nautobot", "plan": "Terraform plan", "apply": "Terraform apply + save config",
               "golden": "Golden Config backup / intended / compliance", "test": "Robot Framework tests"}

app = FastAPI(title="C8000v IPsec VPN portal")
runs, runs_lock, worker_lock = {}, threading.Lock(), threading.Lock()
inventory_svc = None   # created lazily (needs the Nautobot token)


def nautobot_token():
    tok = os.environ.get("NAUTOBOT_TOKEN")
    if not tok:
        tok = subprocess.run(["bash", "-c", f"cd {LAB} && ./lab.sh nautobot token"], capture_output=True, text=True, timeout=60).stdout.strip()
    return tok


class Run:
    def __init__(self, mode, intent, options, spoke=None, resume_of=None):
        self.id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + "-" + uuid.uuid4().hex[:4]
        self.mode, self.intent, self.options, self.spoke = mode, intent, options, spoke
        self.started, self.finished, self.status = time.time(), None, "queued"
        self.steps = [{"name": s, "title": STEP_TITLES[s], "status": "pending", "started": None, "finished": None, "summary": ""} for s in self.plan()]
        self.log, self.tests, self.results_dir, self.error, self.resume_of, self.removal = [], None, None, None, resume_of, None
        if resume_of:   # steps that succeeded in the interrupted/failed run are carried over, everything from the failure on is redone
            done = {st["name"]: st for st in resume_of["steps"] if st["status"] == "success"}
            for st in self.steps:
                if st["name"] not in done: break
                st.update({"status": "success", "summary": f"(from run {resume_of['id']}) {done[st['name']]['summary']}", "started": done[st["name"]]["started"], "finished": done[st["name"]]["finished"]})
            if self.mode == "remove" and "rm_validate" in done: self.removal = resume_of.get("removal")

    def plan(self):
        if self.mode == "test": return ["validate", "test"]
        if self.mode == "spoke":
            steps = ["spoke_validate", "spoke_labconf", "spoke_vm", "spoke_bootstrap", "spoke_onboard", "spoke_intent", "nautobot", "render", "plan", "apply"]
            if self.options.get("golden", True): steps.append("golden")
            if self.options.get("test", True): steps.append("test")
            return steps
        if self.mode == "hub":
            steps = ["hub_validate", "hub_labconf", "hub_vm", "hub_bootstrap", "hub_onboard", "hub_intent", "nautobot", "render", "plan", "apply"]
            if self.options.get("golden", True): steps.append("golden")
            if self.options.get("test", True): steps.append("test")
            return steps
        if self.mode == "remove":
            # hub config is removed by Terraform (native tunnel/ethernet/BGP resources are destroyed) once the spoke is gone from Nautobot
            steps = ["rm_validate", "rm_down", "rm_nautobot", "rm_intent", "nautobot", "render", "rm_state", "plan", "apply", "rm_vm"]
            if self.options.get("golden", True): steps.append("golden")
            if self.options.get("test", True): steps.append("test")
            return steps
        if self.mode == "plan": return ["validate", "save", "nautobot", "render", "plan"]
        steps = ["validate", "save", "nautobot", "render", "plan", "apply"]
        if self.options.get("golden", True): steps.append("golden")
        if self.options.get("test", True): steps.append("test")
        return steps

    def to_dict(self, with_log=True):
        d = {"id": self.id, "mode": self.mode, "status": self.status, "started": self.started, "finished": self.finished, "steps": self.steps,
             "tests": self.tests, "results_dir": self.results_dir, "error": self.error, "options": self.options,
             "site": self.intent.get("site", {}).get("name"), "vpn": self.intent.get("vpn", {}).get("name"), "change_ticket": self.intent.get("vpn", {}).get("change_ticket"),
             "devices": [d["name"] for d in self.intent.get("devices", [])], "spoke": self.spoke, "resume_of": self.resume_of and self.resume_of["id"],
             "removal": getattr(self, "removal", None)}
        if with_log: d["log"] = self.log
        return d

    def say(self, line):
        self.log.append({"t": time.time(), "line": line.rstrip("\n")})

    def persist(self):
        (RUNS_DIR / f"{self.id}.json").write_text(json.dumps(self.to_dict(), indent=1))

    def step(self, name):
        return next(s for s in self.steps if s["name"] == name)

    def sh(self, cmd, cwd=LAB, env=None, timeout=3600):
        """Run a command, streaming stdout+stderr into the run log; returns the exit code."""
        self.say(f"$ {' '.join(cmd)}")
        proc = subprocess.Popen(cmd, cwd=cwd, env={**os.environ, **(env or {})}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in proc.stdout:
            self.say(line)
        proc.wait(timeout=timeout); return proc.returncode

    def execute(self):
        self.status = "running"; self.persist()
        try:
            for s in self.steps:
                if s["status"] == "success": continue   # carried over from the run being resumed
                s["status"], s["started"] = "running", time.time(); self.persist()
                getattr(self, "do_" + s["name"])(s)
                s["status"], s["finished"] = "success", time.time(); self.persist()
            self.status = "success"
        except Exception as e:  # noqa: BLE001 - any failure ends the run
            cur = next((s for s in self.steps if s["status"] == "running"), None)
            if cur: cur["status"], cur["finished"] = "failed", time.time(); cur["summary"] = cur["summary"] or str(e)
            for s in self.steps:
                if s["status"] == "pending": s["status"] = "skipped"
            self.error = str(e); self.status = "failed"; self.say(f"!! {e}")
        self.finished = time.time(); self.persist()

    # ---- spoke provisioning steps ---------------------------------------------
    def do_spoke_validate(self, s):
        problems = spokes.validate(self.spoke)
        if problems: raise RuntimeError("invalid spoke: " + "; ".join(problems))
        hc = spokes.hub_changes(self.spoke)
        s["summary"] = f"{self.spoke['name']} ({self.spoke['mgmt_ip']}), AS {self.spoke['asn']}: " + "; ".join(f"{l['hub']} {l['interface']} / {l['tunnel']}" for l in hc["links"])
        self.say(s["summary"])
        for l in hc["links"]: self.say(f"{l['hub']} will get: {l['interface']} {l['wan_ip']}, {l['tunnel']} {l['tunnel_ip']} -> {l['tunnel_destination']}, neighbor {l['bgp_neighbor']}")

    def do_spoke_labconf(self, s):
        for l in self.spoke.get("links", []): l["spoke"] = self.spoke["name"]
        if self.spoke["name"] in intent_mod.lab_conf("ROLE")["ROLE"]: self.say("already in lab.conf (resumed run)")
        else: spokes.add_to_lab_conf(self.spoke)
        d = spokes.write_day0(self.spoke)
        s["summary"] = "lab.conf updated (" + ", ".join(f"{l['hub']}:{l['hub_port']} <-> {self.spoke['name']}:{l['spoke_port']}" for l in self.spoke.get("links", [])) + f"), {d.relative_to(LAB)}/iosxe_config.txt written"
        self.say(s["summary"])

    def do_spoke_vm(self, s):
        rc = self.sh(["./lab.sh", "up", self.spoke["name"]])
        if rc: raise RuntimeError(f"lab.sh up failed (rc={rc})")
        s["summary"] = f"VM {self.spoke['name']} defined and started (console 127.0.0.1:{self.spoke['console_port']})"

    def do_spoke_bootstrap(self, s):
        self.say("this takes 6-10 minutes: first boot, day-0 config, license boot level reload, RESTCONF")
        rc = self.sh(["./lab.sh", "bootstrap", self.spoke["name"]], timeout=2400)
        if rc: raise RuntimeError(f"bootstrap failed (rc={rc})")
        if not any("RESTCONF up" in l["line"] for l in self.log): raise RuntimeError("RESTCONF did not come up on the new spoke")
        s["summary"] = f"{self.spoke['name']} reachable: ssh admin@{self.spoke['mgmt_ip']}, RESTCONF up"

    def do_spoke_onboard(self, s):
        rc = self.sh(["./lab.sh", "nautobot", "onboard", self.spoke["mgmt_ip"]])
        if rc: raise RuntimeError(f"onboarding failed (rc={rc})")
        s["summary"] = f"{self.spoke['name']} discovered by Nautobot (Sync Devices From Network)"

    def do_spoke_intent(self, s):
        cur = intent_mod.load()
        self.intent = cur if any(d["name"] == self.spoke["name"] for d in cur["devices"]) else spokes.add_to_intent(self.spoke)
        (RUNS_DIR / f"{self.id}.intent.json").write_text(json.dumps(self.intent, indent=2))
        hc = spokes.hub_changes(self.spoke)
        s["summary"] = f"intent now has {len(self.intent['devices'])} devices / {len(self.intent['tunnels'])} tunnels; " + "; ".join(f"{l['hub']} gets {l['interface']} {l['wan_ip']}, {l['tunnel']}, neighbor {l['bgp_neighbor']}" for l in hc["links"])
        self.say(s["summary"])

    # ---- hub provisioning steps ------------------------------------------------
    def do_hub_validate(self, s):
        problems = spokes.validate({**self.spoke, "role": "hub"})
        if problems: raise RuntimeError("invalid hub: " + "; ".join(problems))
        self.spoke["links"] = spokes.hub_links(self.spoke["name"], self.spoke.get("connect_spokes") or [])
        s["summary"] = f"{self.spoke['name']} ({self.spoke['mgmt_ip']}), AS {self.spoke['asn']}; links: " + ", ".join(f"Gi{l['hub_port']}->{l['spoke']} Gi{l['spoke_port']} Tunnel{l['tunnel_id']}" for l in self.spoke["links"])
        self.say(s["summary"])

    def do_hub_labconf(self, s):
        spokes.add_to_lab_conf({**self.spoke, "role": "hub"}); d = spokes.write_day0(self.spoke)
        s["summary"] = f"lab.conf updated ({len(self.spoke['links'])} links), {d.relative_to(LAB)}/iosxe_config.txt written"
        # the existing spokes get a new WAN link: their libvirt definition changes, but the link is anchored on the
        # (new) hub side so only the spoke's second NIC target changes - it needs a re-define + reboot of each spoke
        for l in self.spoke["links"]:
            self.say(f"re-defining {l['spoke']} for its new port Gi{l['spoke_port']} (reboot)")
            for cmd in (["./lab.sh", "down", l["spoke"]], ["./lab.sh", "rebuild", l["spoke"]], ["./lab.sh", "up", l["spoke"]]):
                if self.sh(cmd): raise RuntimeError(f"{' '.join(cmd)} failed")

    def do_hub_vm(self, s):
        rc = self.sh(["./lab.sh", "up", self.spoke["name"]])
        if rc: raise RuntimeError(f"lab.sh up failed (rc={rc})")
        s["summary"] = f"VM {self.spoke['name']} defined and started (console 127.0.0.1:{self.spoke['console_port']})"

    def do_hub_bootstrap(self, s):
        self.say("this takes 6-10 minutes: first boot, day-0 config, license boot level reload, RESTCONF")
        rc = self.sh(["./lab.sh", "bootstrap", self.spoke["name"]], timeout=2400)
        if rc: raise RuntimeError(f"bootstrap failed (rc={rc})")
        if not any("RESTCONF up" in l["line"] for l in self.log): raise RuntimeError("RESTCONF did not come up on the new hub")
        rc = self.sh(["./lab.sh", "wait", *[l["spoke"] for l in self.spoke["links"]]])   # the rebooted spokes
        if rc: raise RuntimeError("a rebooted spoke did not come back")
        s["summary"] = f"{self.spoke['name']} reachable, RESTCONF up; rebooted spokes back"

    def do_hub_onboard(self, s):
        rc = self.sh(["./lab.sh", "nautobot", "onboard", self.spoke["mgmt_ip"]])
        if rc: raise RuntimeError(f"onboarding failed (rc={rc})")
        s["summary"] = f"{self.spoke['name']} discovered by Nautobot"

    def do_hub_intent(self, s):
        cur = intent_mod.load()
        self.intent = cur if any(d["name"] == self.spoke["name"] for d in cur["devices"]) else spokes.add_to_intent({**self.spoke, "role": "hub"})
        (RUNS_DIR / f"{self.id}.intent.json").write_text(json.dumps(self.intent, indent=2))
        s["summary"] = f"intent now has {len(self.intent['devices'])} devices / {len(self.intent['tunnels'])} tunnels"

    # ---- spoke removal steps --------------------------------------------------
    def do_rm_validate(self, s):
        problems, det = spokes.removal_plan(self.spoke["name"])
        if problems: raise RuntimeError("cannot remove: " + "; ".join(problems))
        self.removal = det
        s["summary"] = f"{det['name']} ({det['mgmt_ip']}), AS {det['asn']}: frees " + "; ".join(f"{l['hub']} {l['hub_interface']} / {l['tunnel']} {l['tunnel_prefix']} / WAN {l['wan_prefix']}" for l in det["links"])
        self.say(s["summary"])

    def do_rm_down(self, s):
        rc = self.sh(["./lab.sh", "down", self.spoke["name"]])
        if rc: raise RuntimeError(f"lab.sh down failed (rc={rc})")
        s["summary"] = "VM powered off (config saved)"

    def do_rm_nautobot(self, s):
        det = self.removal
        pfx = [p for l in det["links"] for p in (l.get("wan_prefix"), l.get("tunnel_prefix")) if p] + [det["lan"], f"{det['router_id']}/32"]
        done = spokes.remove_from_nautobot(self.spoke["name"], NAUTOBOT_URL, nautobot_token(), pfx)
        for d in done: self.say("  removed " + d)
        s["summary"] = f"{len(done)} objects removed"

    def do_rm_intent(self, s):
        new = spokes.remove_from_intent(self.spoke["name"])
        if self.spoke["name"] in intent_mod.lab_conf("ROLE")["ROLE"]: spokes.remove_from_lab_conf(self.spoke["name"])
        problems = intent_mod.validate(new)
        if problems: raise RuntimeError("intent invalid after removal: " + "; ".join(problems))
        intent_mod.save(new); self.intent = new; (RUNS_DIR / f"{self.id}.intent.json").write_text(json.dumps(new, indent=2))
        s["summary"] = f"intent now has {len(new['devices'])} devices / {len(new['tunnels'])} tunnels; lab.conf no longer lists {self.spoke['name']}"

    def do_rm_state(self, s):
        n = spokes.forget_in_terraform(self.spoke["name"], self.say); s["summary"] = f"{n} resources dropped from the state (the router is gone; the hub's are destroyed by the apply)"

    def do_rm_vm(self, s):
        spokes.destroy_vm(self.spoke["name"], self.options.get("delete_disk", True))
        s["summary"] = "VM undefined" + (", disk and node directory deleted" if self.options.get("delete_disk", True) else " (disk kept)")

    # ---- steps ---------------------------------------------------------------
    def do_validate(self, s):
        problems = intent_mod.validate(self.intent)
        if problems: raise RuntimeError("invalid intent: " + "; ".join(problems))
        s["summary"] = f"{len(self.intent['devices'])} devices, {len(self.intent['tunnels'])} tunnels, VPN {self.intent['vpn']['name']}"
        self.say(s["summary"])

    def do_save(self, s):
        intent_mod.save(self.intent); (RUNS_DIR / f"{self.id}.intent.json").write_text(json.dumps(self.intent, indent=2))
        s["summary"] = f"lab-intent.json written"; self.say(s["summary"])

    def do_nautobot(self, s):
        rc = self.sh(["./lab.sh", "nautobot", "seed"])
        if rc: raise RuntimeError(f"Nautobot seed failed (rc={rc})")
        m = [l["line"] for l in self.log if l["line"].startswith("seed complete")]
        s["summary"] = m[-1] if m else "seeded"

    def do_render(self, s):
        rc = self.sh(["./lab.sh", "nautobot", "render"])
        if rc: raise RuntimeError(f"render failed (rc={rc})")
        s["summary"] = "nac/data/devices.nac.yaml + device_groups.nac.yaml regenerated from Nautobot"

    def do_plan(self, s):
        rc = self.sh(["./lab.sh", "nac", "plan", "-no-color", "-input=false", "-detailed-exitcode", "-parallelism=1"])
        if rc == 1: raise RuntimeError("terraform plan failed")
        summary = [l["line"] for l in self.log if l["line"].startswith("Plan:") or l["line"].startswith("No changes")]
        s["summary"] = summary[-1] if summary else ("changes pending" if rc == 2 else "no changes")
        self.plan_rc = rc

    def do_apply(self, s):
        if getattr(self, "plan_rc", 2) == 0:
            s["summary"] = "nothing to apply"; self.say("no changes — skipping apply"); return
        # the NAC module has no dependency from tunnel interfaces to the IPsec profile they reference, so on a new
        # router the VTI could be pushed before its profile exists ("Device refused one or more commands"):
        # create the crypto profiles (and everything they depend on) first
        rc = self.sh(["./lab.sh", "nac", "apply", "-auto-approve", "-no-color", "-input=false", "-parallelism=1",
                      "-target=module.iosxe.iosxe_crypto_ipsec_profile.crypto_ipsec_profile"])
        if rc: raise RuntimeError(f"terraform apply (crypto profiles first) failed (rc={rc})")
        rc = self.sh(["./lab.sh", "nac", "apply", "-auto-approve", "-no-color", "-input=false", "-parallelism=1"])
        if rc: raise RuntimeError(f"terraform apply failed (rc={rc})")
        summary = [l["line"] for l in self.log if l["line"].startswith("Apply complete")]
        s["summary"] = summary[-1] if summary else "applied"
        # IOS-XE re-syncs its YANG datastore after interface deletions/reloads and then elides some values (e.g. the
        # transform-set key size), which reads back as drift: converge with one more apply instead of failing later
        rc = self.sh(["./lab.sh", "nac", "plan", "-no-color", "-input=false", "-detailed-exitcode", "-parallelism=1"])
        if rc == 2:
            self.say("post-apply drift (DMI re-sync) — re-asserting once")
            if self.sh(["./lab.sh", "nac", "apply", "-auto-approve", "-no-color", "-input=false", "-parallelism=1"]): raise RuntimeError("convergence apply failed")
            s["summary"] += " (+1 convergence apply)"

    def do_golden(self, s):
        rc = self.sh(["./lab.sh", "nautobot", "golden"])
        if rc: raise RuntimeError(f"Golden Config run failed (rc={rc})")
        rows = [l["line"] for l in self.log if "compliance " in l["line"] and ("COMPLIANT" in l["line"])]
        bad = [r for r in rows if "NON-COMPLIANT" in r]
        s["summary"] = f"{len(rows) - len(bad)}/{len(rows)} compliance rows compliant"
        if bad: raise RuntimeError(s["summary"] + ": " + bad[0].strip())

    def do_test(self, s):
        rc = self.sh(["./lab.sh", "test"])
        latest = (RESULTS / "latest").resolve()
        self.results_dir = latest.name
        self.tests = parse_robot(latest / "output.xml") if (latest / "output.xml").exists() else None
        if self.tests:
            s["summary"] = f"{self.tests['passed']}/{self.tests['total']} tests passed"
            if self.tests["failed"]: raise RuntimeError(f"{self.tests['failed']} test(s) failed")
        elif rc: raise RuntimeError(f"tests failed to run (rc={rc})")


def parse_robot(path):
    root = ET.parse(path).getroot(); suites = []
    for suite in root.iter("suite"):
        tests = suite.findall("test")
        if not tests: continue
        rows = []
        for t in tests:
            st = t.find("status"); rows.append({"name": t.get("name"), "status": st.get("status"), "message": (st.text or "").strip()[:800],
                                                "elapsed": st.get("elapsed"), "start": st.get("start")})
        suites.append({"name": suite.get("name"), "tests": rows, "passed": sum(r["status"] == "PASS" for r in rows), "failed": sum(r["status"] == "FAIL" for r in rows)})
    total = sum(len(s["tests"]) for s in suites); failed = sum(s["failed"] for s in suites)
    return {"suites": suites, "total": total, "passed": total - failed, "failed": failed}


# ---- API -------------------------------------------------------------------
@app.get("/")
def index():
    return FileResponse(Path(__file__).resolve().parent / "static" / "index.html", headers={"Cache-Control": "no-store"})


@app.get("/api/intent")
def get_intent():
    return {"intent": intent_mod.load(), "wiring": intent_mod.wiring(), "nodes": intent_mod.nodes(),
            "intent_file": str(intent_mod.INTENT_FILE), "nautobot_url": NAUTOBOT_PUBLIC_URL}


@app.get("/api/inventory")
def inventory():
    """What Nautobot knows about the location's routers (from onboarding)."""
    try:
        I = intent_mod.load(); H = {"Authorization": f"Token {nautobot_token()}"}
        r = requests.get(f"{NAUTOBOT_URL}/api/dcim/devices/", params={"location": I["site"]["name"], "depth": 1, "limit": 100}, headers=H, timeout=20); r.raise_for_status()
        devs = [{"name": d["name"], "mgmt_ip": d["primary_ip4"]["address"].split("/")[0] if d.get("primary_ip4") else None, "serial": d.get("serial"),
                 "model": (d.get("device_type") or {}).get("model"), "role": (d.get("role") or {}).get("name"), "status": (d.get("status") or {}).get("name"),
                 "url": f"{NAUTOBOT_PUBLIC_URL}/dcim/devices/{d['id']}/"} for d in r.json()["results"]]
        v = requests.get(f"{NAUTOBOT_URL}/api/vpn/vpns/", params={"name": I["vpn"]["name"]}, headers=H, timeout=20).json()
        vpn_url = f"{NAUTOBOT_PUBLIC_URL}/vpn/vpns/{v['results'][0]['id']}/" if v.get("count") else None
        return {"devices": devs, "vpn_url": vpn_url, "ok": True}
    except Exception as e:  # noqa: BLE001
        return {"devices": [], "ok": False, "error": str(e)}


def inv():
    global inventory_svc
    if inventory_svc is None:
        inventory_svc = Inventory(NAUTOBOT_URL, NAUTOBOT_PUBLIC_URL, nautobot_token, os.environ.get("IOSXE_USERNAME", "admin"), os.environ.get("IOSXE_PASSWORD", "admin"))
    return inventory_svc


@app.get("/api/vpn-inventory")
def vpn_inventory(refresh: bool = False, live: bool = True):
    """Modelled tunnels (Nautobot) + live state from the headends + capacity; cached 30 s, ?refresh=1 to re-collect."""
    try: return inv().get(refresh=refresh, with_live=live)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"inventory unavailable: {e}")


@app.get("/api/vpn-inventory.csv")
def vpn_inventory_csv(refresh: bool = False):
    data = inv().get(refresh=refresh)
    return PlainTextResponse(to_csv(data), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=vpn-inventory-{datetime.now():%Y%m%d-%H%M%S}.csv"})


@app.post("/api/validate")
def validate(body: dict):
    return {"problems": intent_mod.validate(body.get("intent") or {})}


@app.get("/api/spokes/suggest")
def spoke_suggest(hubs: str = ""):
    return spokes.suggest([h for h in hubs.split(",") if h] or None)


@app.get("/api/hubs/suggest")
def hub_suggest():
    return spokes.suggest_hub()


@app.post("/api/spokes/validate")
def spoke_validate(body: dict):
    spec = body.get("spoke") or {}
    problems = spokes.validate(spec)
    return {"problems": problems, "hub_changes": spokes.hub_changes(spec) if not problems else None}


@app.get("/api/spokes/{name}/removal")
def spoke_removal(name: str):
    problems, det = spokes.removal_plan(name)
    return {"problems": problems, "details": det}


@app.post("/api/runs")
def start_run(body: dict):
    mode = body.get("mode", "deploy")
    if mode not in ("deploy", "plan", "test", "spoke", "hub", "remove"): raise HTTPException(400, "mode must be deploy, plan, test, spoke, hub or remove")
    spoke = None
    if mode == "remove":
        spoke = body.get("spoke") or {}; problems, _ = spokes.removal_plan(spoke.get("name", ""))
        if problems: raise HTTPException(422, {"problems": problems})
        intent = intent_mod.load()
    elif mode == "hub":
        spoke = body.get("hub") or {}; problems = spokes.validate({**spoke, "role": "hub"})
        if problems: raise HTTPException(422, {"problems": problems})
        intent = intent_mod.load()
    elif mode == "spoke":
        spoke = body.get("spoke") or {}; problems = spokes.validate(spoke)
        if problems: raise HTTPException(422, {"problems": problems})
        intent = intent_mod.load()
    else:
        intent = body.get("intent") if mode != "test" else intent_mod.load()
        problems = intent_mod.validate(intent or {})
        if problems: raise HTTPException(422, {"problems": problems})
    with runs_lock:
        if any(r.status in ("queued", "running") for r in runs.values()): raise HTTPException(409, "a run is already in progress")
        run = Run(mode, intent, body.get("options") or {}, spoke); runs[run.id] = run
    def work():
        with worker_lock: run.execute()
    threading.Thread(target=work, daemon=True).start()
    return run.to_dict(with_log=False)


@app.post("/api/runs/{run_id}/resume")
def resume_run(run_id: str):
    """Start a new run that keeps the successful steps of a failed/interrupted run and redoes the rest."""
    old = runs.get(run_id); d = old.to_dict() if old else (json.loads((RUNS_DIR / f"{run_id}.json").read_text()) if (RUNS_DIR / f"{run_id}.json").exists() else None)
    if d is None: raise HTTPException(404, "no such run")
    if d["status"] not in ("failed", "interrupted"): raise HTTPException(409, f"run is {d['status']}")
    f = RUNS_DIR / f"{run_id}.intent.json"
    intent = json.loads(f.read_text()) if (f.exists() and d["mode"] in ("deploy", "plan")) else intent_mod.load()
    with runs_lock:
        if any(r.status in ("queued", "running") for r in runs.values()): raise HTTPException(409, "a run is already in progress")
        run = Run(d["mode"], intent, d.get("options") or {}, d.get("spoke"), resume_of=d); runs[run.id] = run
    def work():
        with worker_lock: run.execute()
    threading.Thread(target=work, daemon=True).start()
    return run.to_dict(with_log=False)


@app.on_event("startup")
def mark_interrupted():
    """Runs that were in progress when the server stopped are marked so they can be resumed."""
    for f in RUNS_DIR.glob("*.json"):
        if f.name.endswith(".intent.json"): continue
        try: d = json.loads(f.read_text())
        except ValueError: continue
        if d.get("status") in ("running", "queued"):
            for st in d["steps"]:
                if st["status"] == "running": st["status"] = "failed"; st["summary"] = st["summary"] or "interrupted (server restarted)"
                elif st["status"] == "pending": st["status"] = "skipped"
            d["status"], d["error"], d["finished"] = "interrupted", "interrupted: the portal was restarted", time.time(); f.write_text(json.dumps(d, indent=1))


@app.get("/api/runs")
def list_runs():
    items = [r.to_dict(with_log=False) for r in runs.values()]
    seen = {r["id"] for r in items}
    for f in sorted(RUNS_DIR.glob("*.json"), reverse=True):
        if f.name.endswith(".intent.json") or f.stem in seen: continue
        try:
            d = json.loads(f.read_text()); d.pop("log", None); items.append(d)
        except ValueError: pass
    return sorted(items, key=lambda r: r["started"], reverse=True)[:30]


@app.get("/api/runs/{run_id}")
def get_run(run_id: str, since: int = 0):
    run = runs.get(run_id)
    if run:
        d = run.to_dict(); d["log"] = d["log"][since:]; d["log_offset"] = since; return d
    f = RUNS_DIR / f"{run_id}.json"
    if not f.exists(): raise HTTPException(404, "no such run")
    d = json.loads(f.read_text()); d["log"] = d.get("log", [])[since:]; d["log_offset"] = since; return d


app.mount("/results", StaticFiles(directory=str(RESULTS), html=True), name="results")
app.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parent / "static")), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.environ.get("WEBAPP_HOST", "0.0.0.0"), port=int(os.environ.get("WEBAPP_PORT", "8090")))
