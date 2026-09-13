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
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import requests

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "nautobot")); import intent as intent_mod   # noqa: E402
RUNS_DIR = Path(__file__).resolve().parent / "runs"; RUNS_DIR.mkdir(exist_ok=True)
RESULTS = LAB / "results"
NAUTOBOT_URL = os.environ.get("NAUTOBOT_URL", "http://10.0.0.10:8080")
NAUTOBOT_PUBLIC_URL = os.environ.get("NAUTOBOT_PUBLIC_URL", "http://192.168.50.231:8080")
STEPS = ["validate", "save", "nautobot", "render", "plan", "apply", "golden", "test"]
STEP_TITLES = {"validate": "Validate intent", "save": "Save intent", "nautobot": "Nautobot source of truth (seed)",
               "render": "Render NAC data from Nautobot", "plan": "Terraform plan", "apply": "Terraform apply + save config",
               "golden": "Golden Config backup / intended / compliance", "test": "Robot Framework tests"}

app = FastAPI(title="C8000v IPsec VPN portal")
runs, runs_lock, worker_lock = {}, threading.Lock(), threading.Lock()


def nautobot_token():
    tok = os.environ.get("NAUTOBOT_TOKEN")
    if not tok:
        tok = subprocess.run(["bash", "-c", f"cd {LAB} && ./lab.sh nautobot token"], capture_output=True, text=True, timeout=60).stdout.strip()
    return tok


class Run:
    def __init__(self, mode, intent, options):
        self.id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + "-" + uuid.uuid4().hex[:4]
        self.mode, self.intent, self.options = mode, intent, options
        self.started, self.finished, self.status = time.time(), None, "queued"
        self.steps = [{"name": s, "title": STEP_TITLES[s], "status": "pending", "started": None, "finished": None, "summary": ""} for s in self.plan()]
        self.log, self.tests, self.results_dir, self.error = [], None, None, None

    def plan(self):
        if self.mode == "test": return ["validate", "test"]
        if self.mode == "plan": return ["validate", "save", "nautobot", "render", "plan"]
        steps = ["validate", "save", "nautobot", "render", "plan", "apply"]
        if self.options.get("golden", True): steps.append("golden")
        if self.options.get("test", True): steps.append("test")
        return steps

    def to_dict(self, with_log=True):
        d = {"id": self.id, "mode": self.mode, "status": self.status, "started": self.started, "finished": self.finished, "steps": self.steps,
             "tests": self.tests, "results_dir": self.results_dir, "error": self.error, "options": self.options,
             "site": self.intent.get("site", {}).get("name"), "vpn": self.intent.get("vpn", {}).get("name"), "change_ticket": self.intent.get("vpn", {}).get("change_ticket")}
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
        rc = self.sh(["./lab.sh", "nac", "apply", "-auto-approve", "-no-color", "-input=false", "-parallelism=1"])
        if rc: raise RuntimeError(f"terraform apply failed (rc={rc})")
        summary = [l["line"] for l in self.log if l["line"].startswith("Apply complete")]
        s["summary"] = summary[-1] if summary else "applied"

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
    return FileResponse(Path(__file__).resolve().parent / "static" / "index.html")


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


@app.post("/api/validate")
def validate(body: dict):
    return {"problems": intent_mod.validate(body.get("intent") or {})}


@app.post("/api/runs")
def start_run(body: dict):
    mode = body.get("mode", "deploy")
    if mode not in ("deploy", "plan", "test"): raise HTTPException(400, "mode must be deploy, plan or test")
    intent = body.get("intent") if mode != "test" else intent_mod.load()
    problems = intent_mod.validate(intent or {})
    if problems: raise HTTPException(422, {"problems": problems})
    with runs_lock:
        if any(r.status in ("queued", "running") for r in runs.values()): raise HTTPException(409, "a run is already in progress")
        run = Run(mode, intent, body.get("options") or {}); runs[run.id] = run
    def work():
        with worker_lock: run.execute()
    threading.Thread(target=work, daemon=True).start()
    return run.to_dict(with_log=False)


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
