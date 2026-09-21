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
import ipaddress, json, os, re, subprocess, sys, time
from datetime import datetime
from pathlib import Path
from labportal import RunBase, RunRegistry, install_runs_api, metric_line, run_metrics, exposition, metrics_generated

from fastapi import FastAPI, HTTPException, Query, Path as PathParam, Request, Response
import auth
import firewalls as fw_mod
from fastapi.openapi.docs import get_swagger_ui_html
import schemas as S
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
import requests
from inventory import Inventory, to_csv
import spokes

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "nautobot")); import intent as intent_mod   # noqa: E402
sys.path.insert(0, str(LAB / "pki")); import ca as lab_ca   # noqa: E402
import cities  # noqa: E402
RUNS_DIR = Path(__file__).resolve().parent / "runs"; RUNS_DIR.mkdir(exist_ok=True)
RESULTS = LAB / "results"
NAUTOBOT_URL = os.environ.get("NAUTOBOT_URL", "http://10.0.0.10:8080")
NAUTOBOT_PUBLIC_URL = os.environ.get("NAUTOBOT_PUBLIC_URL", "http://192.168.50.231:8080")
STEP_TITLES = {"validate": "Validate intent", "save": "Save intent", "nautobot": "Nautobot source of truth (seed)", "firewalls": "VyOS firewalls rendered from Nautobot and pushed",
               "spoke_validate": "Validate spoke allocation", "spoke_labconf": "Register the spoke in lab.conf + day-0 config",
               "spoke_vm": "Create and boot the spoke VM", "spoke_bootstrap": "Bootstrap (day-0, license reload, RESTCONF)",
               "spoke_onboard": "Onboard the spoke into Nautobot", "spoke_intent": "Add the spoke to the intent (hub link, tunnel, BGP)",
               "rh_validate": "Validate the re-homing (headends to add / drop, allocations)", "rh_intent": "Intent + lab.conf: new links and tunnels, dropped ones removed",
               "rh_nautobot": "Nautobot: dropped links cleaned up", "rh_vm": "Spoke VM redefined with the new WAN link and rebooted",
               "rh_verify": "Verify: new tunnels READY + eBGP Established, dropped ones gone",
               "rot_validate": "Validate the rotation (spoke, tunnels, headends)", "rot_intent": "New pre-shared key into the intent",
               "rot_rekey": "Re-key: clear the spoke's IKEv2 SAs", "rot_verify": "Verify: IKEv2 READY and eBGP Established on every tunnel",
               "pki": "Certificates: enrol the routers with the lab CA (trustpoint, CA cert, router cert)", "pki_verify": "Certificates: pre-shared keys off the routers, every tunnel re-authenticated with RSA",
               "renew_validate": "Validate the renewal (router, current certificate)", "renew_pki": "Renew: new CSR signed by the lab CA and imported", "renew_verify": "Verify: every tunnel of the router re-authenticated with the new certificate",
               "hub_validate": "Validate hub allocation", "hub_labconf": "Register the hub in lab.conf + day-0 config (links to every spoke)",
               "hub_vm": "Create and boot the hub VM", "hub_bootstrap": "Bootstrap (day-0, license reload, RESTCONF)", "hub_onboard": "Onboard the hub into Nautobot",
               "hub_intent": "Add the hub, its links and tunnels to the intent",
               "rm_validate": "Validate removal", "rm_down": "Power off the spoke VM", "rm_nautobot": "Remove the spoke from Nautobot (tunnel, endpoints, BGP, device, addresses)",
               "rm_intent": "Remove from lab.conf and the intent", "rm_state": "Forget the spoke in the Terraform state", "rm_vm": "Delete the VM",
               "render": "Render NAC data from Nautobot", "plan": "Terraform plan", "apply": "Terraform apply + save config",
               "golden": "Golden Config backup / intended / compliance", "test": "Robot Framework tests"}

TAGS = [{"name": "intent", "description": "The VPN service intent (what the Provision form edits) and what Nautobot knows about the routers."},
        {"name": "provisioning", "description": "Suggest / validate a new spoke or headend, plan a removal."},
        {"name": "runs", "description": "Pipeline runs: deploy, dry run, tests, provision a spoke or headend, decommission a spoke; status, log and test report."},
        {"name": "inventory", "description": "Every VPN tunnel: the Nautobot model joined with live IKEv2 / VTI / eBGP / ESP state from the headends, headend capacity, CSV export."}]
app = FastAPI(title="VPN Provisioning Portal API", version="1.0",
              description="REST API behind the C8000v IPsec VPN provisioning portal.\n\n"
                          "Nautobot is the source of truth; every change goes **intent → Nautobot seed → NAC data rendered from Nautobot → Terraform plan/apply → Golden Config → Robot tests**. "
                          "Runs are asynchronous: `POST /api/runs` returns a run id, poll `GET /api/runs/{id}`.\n\n"
                          "Portal UI: [/](/) · this page: [/docs](/docs) · ReDoc: [/redoc](/redoc) · OpenAPI JSON: [/openapi.json](/openapi.json)",
              openapi_tags=TAGS, docs_url="/docs", redoc_url="/redoc")
registry = RunRegistry(RUNS_DIR)
inventory_svc = None   # created lazily (needs the Nautobot token)
AUDIT = RUNS_DIR / "audit.jsonl"


# ---- login, roles, audit (see auth.py) ------------------------------------------------------------------------------
@app.middleware("http")
async def auth_and_audit(request: Request, call_next):
    """Every request: resolve the user (session cookie or bearer token), check the role the verb / path needs, and write
    the audit record for anything that changes something (with the body, secrets redacted) once it has been handled."""
    user = None
    tok = request.headers.get("authorization", "")
    if tok.lower().startswith("bearer "): user = auth.user_for_token(tok[7:].strip())
    if user is None and request.cookies.get(auth.COOKIE): user = auth.read_session(request.cookies[auth.COOKIE])
    request.state.user = user; auth.current_user.set(user)
    body = None
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.headers.get("content-type", "").startswith("application/json"):
        raw = await request.body()
        try: body = json.loads(raw) if raw else None
        except ValueError: body = None
    need = auth.required_role(request.method, request.url.path, body)
    if need and (user is None or auth.role_rank(user["role"]) < auth.role_rank(need)):
        status = 401 if user is None else 403
        if request.method != "GET": auth.audit(AUDIT, user, "denied", request.client.host if request.client else None, method=request.method, path=request.url.path, required_role=need, mode=(body or {}).get("mode") if isinstance(body, dict) else None, status=status)
        return JSONResponse({"detail": "login required" if status == 401 else f"role {need} required (you are {user['role']})", "required_role": need}, status_code=status)
    response = await call_next(request)
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and not request.url.path.endswith(("/login", "/logout", "/validate")):   # validation is read-only, not audited
        detail = {"method": request.method, "path": request.url.path, "status": response.status_code}
        if isinstance(body, dict):
            detail["mode"] = body.get("mode"); detail["spec"] = body.get("spoke") or body.get("hub") or ({"intent": "..."} if body.get("intent") else None); detail["options"] = body.get("options")
        rid = getattr(request.state, "run_id", None)
        if rid: detail["run_id"] = rid
        auth.audit(AUDIT, user, "run.start" if request.url.path == "/api/runs" else ("run.resume" if request.url.path.endswith("/resume") else "write"), request.client.host if request.client else None, **detail)
    return response


@app.post("/api/login", tags=["auth"], summary="Log in (local user); sets the session cookie")
def login(body: dict, request: Request, response: Response):
    name, pw = (body.get("username") or "").strip(), body.get("password") or ""
    u = auth.load_users().get(name)
    if not auth.check_password(u, pw):
        auth.audit(AUDIT, {"name": name}, "login.failed", request.client.host if request.client else None); raise HTTPException(401, "wrong username or password")
    response.set_cookie(auth.COOKIE, auth.make_session(name, u["role"]), max_age=auth.SESSION_HOURS * 3600, httponly=True, samesite="lax")
    auth.audit(AUDIT, {"name": name, "role": u["role"]}, "login", request.client.host if request.client else None)
    return {"name": name, "role": u["role"], "roles": auth.ROLES}


@app.post("/api/logout", tags=["auth"], summary="Log out")
def logout(request: Request, response: Response):
    response.delete_cookie(auth.COOKIE)
    if request.state.user: auth.audit(AUDIT, request.state.user, "logout", request.client.host if request.client else None)
    return {"ok": True}


@app.get("/api/me", tags=["auth"], summary="Who am I (name, role) — null when not logged in")
def me(request: Request):
    return {"user": request.state.user, "roles": auth.ROLES, "rules": {"viewer": "read everything", "operator": "+ start / resume runs that build or change", "approver": "+ remove a spoke, manage users"}}


@app.get("/api/audit", tags=["auth"], summary="The audit trail: logins and every write, newest first")
def audit_log(limit: int = Query(200, le=2000), user: str = Query(None), action: str = Query(None, description="prefix: login, run.start, run.resume, write")):
    return auth.read_audit(AUDIT, limit, user, action)


@app.get("/api/users", tags=["auth"], summary="Users and roles (approver)")
def users_list():
    return [{"name": n, "role": u["role"], "token": bool(u.get("token"))} for n, u in auth.load_users().items()]


@app.post("/api/users", tags=["auth"], summary="Add or update a user: {name, role, password?} (approver)")
def users_add(body: dict, request: Request):
    name, role = (body.get("name") or "").strip(), body.get("role")
    if not re.fullmatch(r"[a-z][a-z0-9_.-]{1,30}", name) or role not in auth.ROLES: raise HTTPException(422, "name: lowercase letters/digits/_.-; role: viewer, operator or approver")
    users = auth.load_users(); u = users.get(name, {})
    if body.get("password"): u["salt"], u["hash"] = auth.hash_password(body["password"])
    elif not u.get("hash"): raise HTTPException(422, "a new user needs a password")
    u["role"] = role; users[name] = u; auth.save_users(users)
    return {"name": name, "role": role}


@app.delete("/api/users/{name}", tags=["auth"], summary="Delete a user (approver)")
def users_del(name: str, request: Request):
    if request.state.user and request.state.user["name"] == name: raise HTTPException(422, "not yourself")
    users = auth.load_users(); users.pop(name, None); auth.save_users(users); return {"ok": True}


def nautobot_token():
    tok = os.environ.get("NAUTOBOT_TOKEN")
    if not tok:
        tok = subprocess.run(["bash", "-c", f"cd {LAB} && ./lab.sh nautobot token"], capture_output=True, text=True, timeout=60).stdout.strip()
    return tok


class Run(RunBase):
    LAB = "cat8000v-ipsec"
    STEP_TITLES = STEP_TITLES
    EXTRA = {"site": "site", "vpn": "vpn", "change_ticket": "change_ticket", "devices": "devices", "spoke": "spoke", "removal": "removal", "rehome": "rehome", "user": "user"}

    def __init__(self, mode, intent, options, spoke=None, resume_of=None):
        self.intent, self.spoke = intent, spoke
        self.user = ((resume_of or {}).get("user") if resume_of else None) or ((auth.current_user.get() or {}).get("name"))   # who started it (a resume keeps the original starter, the resumer is in the audit trail)
        self.site, self.vpn = intent.get("site", {}).get("name"), intent.get("vpn", {}).get("name"); self.change_ticket = intent.get("vpn", {}).get("change_ticket")
        self.devices = [d["name"] for d in intent.get("devices", [])]
        self.removal = (resume_of or {}).get("removal") if mode == "remove" and resume_of and any(st["name"] == "rm_validate" and st["status"] == "success" for st in resume_of["steps"]) else None
        if mode == "rehome" and resume_of:
            # the allocation made by the original run (recomputing it after the intent changed would see nothing to do); a run that
            # failed before the intent step carries none, and then the plan is simply computed again
            self.rehome = resume_of.get("rehome") or spokes.rehome_plan((spoke or {}).get("name", ""), (spoke or {}).get("hubs") or [])[1]
        if mode == "rotate" and resume_of:   # a resumed rotation: the intent already holds the new key, so its fingerprint is the "new" one
            _, det = spokes.rotation_plan((spoke or {}).get("name", "")); self.rotation = {**(det or {}), "new_fingerprint": (det or {}).get("fingerprint")}
        super().__init__(mode, options, resume_of, runs_dir=RUNS_DIR, cwd=LAB)

    def sh(self, cmd, cwd=None, env=None, timeout=3600, check=False):   # this portal inspects exit codes itself (terraform's -detailed-exitcode)
        return super().sh(cmd, cwd=cwd, env=env, timeout=timeout, check=check)

    def plan(self):
        if self.mode == "test": return ["validate", "test"]
        if self.mode == "spoke":
            steps = ["spoke_validate", "spoke_labconf", "spoke_vm", "spoke_bootstrap", "spoke_onboard", "spoke_intent", "nautobot", "render", "pki", "firewalls", "plan", "apply", "pki_verify"]
            if self.options.get("golden", True): steps.append("golden")
            if self.options.get("test", True): steps.append("test")
            return steps
        if self.mode == "hub":
            steps = ["hub_validate", "hub_labconf", "hub_vm", "hub_bootstrap", "hub_onboard", "hub_intent", "nautobot", "render", "pki", "firewalls", "plan", "apply", "pki_verify"]
            if self.options.get("golden", True): steps.append("golden")
            if self.options.get("test", True): steps.append("test")
            return steps
        if self.mode == "remove":
            # hub config is removed by Terraform (native tunnel/ethernet/BGP resources are destroyed) once the spoke is gone from Nautobot
            steps = ["rm_validate", "rm_down", "rm_nautobot", "rm_intent", "nautobot", "render", "firewalls", "rm_state", "plan", "apply", "rm_vm"]
            if self.options.get("golden", True): steps.append("golden")
            if self.options.get("test", True): steps.append("test")
            return steps
        if self.mode == "rehome":
            # the spoke stays; its set of headends changes: new link(s) + tunnel(s) allocated and wired (the VM is redefined and
            # rebooted for a new NIC pair), dropped ones removed from the model — terraform then adds / destroys on hub and spoke
            steps = ["rh_validate", "rh_intent", "rh_nautobot", "rh_vm", "nautobot", "render", "pki", "firewalls", "plan", "apply", "rh_verify"]
            if self.options.get("golden", True): steps.append("golden")
            if self.options.get("test", False): steps.append("test")
            return steps
        if self.mode == "rotate":
            # new key -> intent -> Nautobot (fingerprint + date on the tunnels) -> NaC render (group variable) -> terraform on the spoke
            # and every headend's keyring -> clear the spoke's SAs so the new key is used now -> every tunnel back up
            steps = ["rot_validate", "rot_intent", "nautobot", "render", "plan", "apply", "rot_rekey", "rot_verify"]
            if self.options.get("golden", True): steps.append("golden")
            if self.options.get("test", False): steps.append("test")
            return steps
        if self.mode == "renew":
            # certificate renewal of one router: new CSR -> signed by the lab CA -> imported (Nautobot's cert_* fields follow) -> the
            # router's IKEv2 SAs cleared so its peers see the new certificate -> every tunnel back READY with RSA
            steps = ["renew_validate", "renew_pki", "renew_verify"]
            if self.options.get("test", False): steps.append("test")
            return steps
        if self.mode == "plan": return ["validate", "save", "nautobot", "render", "plan"]
        steps = ["validate", "save", "nautobot", "render", "pki", "firewalls", "plan", "apply", "pki_verify"]
        if self.options.get("golden", True): steps.append("golden")
        if self.options.get("test", True): steps.append("test")
        return steps

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

    # ---- re-homing steps ---------------------------------------------------------
    def do_rh_validate(self, s):
        if getattr(self, "rehome", None): self.say("resumed: keeping the allocation made by the original run"); det = self.rehome
        else:
            problems, det = spokes.rehome_plan(self.spoke["name"], self.spoke.get("hubs") or [])
            if problems: raise RuntimeError("cannot re-home: " + "; ".join(problems))
            self.rehome = det
        s["summary"] = f"{det['name']}: {', '.join(det['current'])} -> {', '.join(det['wanted'])}; add " + (", ".join(f"{l['hub']} ({l.get('edge') or l['hub']} port {l['hub_port']} <-> Gi{l['spoke_port']}, Tunnel{l['tunnel_id']} {l['tunnel_prefix']})" for l in det["add"]) or "none") + \
                       "; drop " + (", ".join(f"{d['hub']} (Tunnel{d['tunnel_id']})" for d in det["drop"]) or "none") + ("; the spoke reboots for the new NIC" if det["reboot"] else "")
        self.say(s["summary"])

    def do_rh_intent(self, s):
        new = spokes.apply_rehome(self.rehome); self.intent = new; (RUNS_DIR / f"{self.id}.intent.json").write_text(json.dumps(new, indent=2))
        s["summary"] = f"intent: {len(new['tunnels'])} tunnels; lab.conf: +{len(self.rehome['add'])} / -{len(self.rehome['drop'])} link(s)"

    def do_rh_nautobot(self, s):
        if not self.rehome["drop"]: s["summary"] = "nothing dropped"; return
        n = 0
        for d in self.rehome["drop"]:
            done = spokes.remove_link_from_nautobot(d["hub"], self.spoke["name"], d["tunnel_id"], d["tunnel_prefix"], d["wan_prefix"], NAUTOBOT_URL, nautobot_token())
            for x in done: self.say("  removed " + x)
            n += len(done)
        s["summary"] = f"{n} objects removed for {len(self.rehome['drop'])} dropped link(s)"

    def do_rh_vm(self, s):
        if not self.rehome["reboot"]: s["summary"] = "no new NIC: the VM stays up"; return
        name = self.spoke["name"]
        for cmd in (["./lab.sh", "down", name], ["./lab.sh", "rebuild", name], ["./lab.sh", "up", name]):
            if self.sh(cmd, timeout=600): raise RuntimeError(f"{' '.join(cmd[1:])} failed")
        self.say("booting (about 5 minutes until RESTCONF answers)")
        if self.sh(["./lab.sh", "wait", name], timeout=1500): raise RuntimeError(f"{name} did not come back")
        s["summary"] = f"{name} redefined with the new WAN link, rebooted, RESTCONF up"

    def do_rh_verify(self, s):
        det = self.rehome; hubs_ip = {d["name"]: d["mgmt_ip"] for d in self.intent["devices"]}
        want = {(l["hub"], l["spoke_wan_ip"], l["spoke_tunnel_ip"]) for l in det["add"]}; gone = {(d["hub"], str(ipaddress.IPv4Network(d["wan_prefix"]).network_address + 2)) for d in det["drop"] if d.get("wan_prefix")}
        deadline = time.time() + 300; missing = set(want); lingering = set(gone)
        while time.time() < deadline and (missing or lingering):
            time.sleep(15); still, linger = set(), set()
            for hub in {w[0] for w in missing} | {g[0] for g in lingering}:
                try:
                    c = self._ios(hubs_ip[hub]); sa = c.send_command("show crypto ikev2 sa"); bgp = c.send_command("show bgp ipv4 unicast summary | begin Neighbor"); c.disconnect()
                except Exception as e:  # noqa: BLE001
                    self.say(f"{hub}: {e.__class__.__name__}, retrying"); still |= {w for w in missing if w[0] == hub}; linger |= {g for g in lingering if g[0] == hub}; continue
                for w in missing:
                    if w[0] != hub: continue
                    ok = any(w[1] in l and "READY" in l for l in sa.splitlines()) and any(l.split() and l.split()[0] == w[2] and l.split()[-1].isdigit() for l in bgp.splitlines())
                    if ok: self.say(f"{hub} <- {det['name']} ({w[1]}): IKEv2 READY, eBGP Established")
                    else: still.add(w)
                for g in lingering:
                    if g[0] == hub and any(g[1] in l for l in sa.splitlines()): linger.add(g)
                    elif g[0] == hub: self.say(f"{hub}: no SA left for {det['name']} ({g[1]})")
            missing, lingering = still, linger
        if missing or lingering: raise RuntimeError("not converged: " + "; ".join([f"{h} <- {ip} not up" for h, ip, _ in sorted(missing)] + [f"{h}: SA for {ip} still present" for h, ip in sorted(lingering)]))
        s["summary"] = f"{det['name']} homed on {', '.join(det['wanted'])}: {len(want)} new tunnel(s) up, {len(gone)} dropped"

    # ---- certificates (IKE authentication "certificate" in the intent) -----------
    def do_pki(self, s):
        """nautobot/pki.py: every router enrolled with the lab CA — key pair, trustpoint (CA fingerprint pinned), CA certificate, a router
        certificate signed by the CA (renewed when it is missing, foreign, or close to expiry); Nautobot's cert_* fields follow. A no-op
        while the intent authenticates with pre-shared keys."""
        rc = self.sh(["./lab.sh", "nautobot", "pki"])
        if rc: raise RuntimeError(f"certificate enrolment failed (rc={rc})")
        lines = [l["line"] for l in self.log if re.match(r"^\S+: (ok|renewed) — ", l["line"])]
        renewed = [l.split(":")[0] for l in lines if ": renewed" in l]
        s["summary"] = ("IKE authenticates with pre-shared keys: nothing to enrol" if any("nothing to enrol" in l["line"] for l in self.log[-5:]) else
                        f"{len(lines)} router(s) hold a certificate from the lab CA" + (f"; enrolled now: {', '.join(renewed)}" if renewed else ""))

    def do_pki_verify(self, s):
        """After Terraform put the IKEv2 profiles on rsa-sig: the keyrings (pre-shared keys) leave the routers, SAs still authenticated
        with a key are cleared, and every tunnel must come back READY with RSA both ways. A no-op in PSK mode."""
        rc = self.sh(["./lab.sh", "nautobot", "pki", "--post-apply"])
        if rc: raise RuntimeError(f"certificate verification failed (rc={rc})")
        done = [l["line"] for l in self.log if "IKEv2 SAs READY, authenticated with certificates" in l["line"]]
        s["summary"] = "; ".join(x.split(" IKEv2")[0] for x in done) or "IKE authenticates with pre-shared keys: nothing to verify"

    def do_renew_validate(self, s):
        problems, det = spokes.renewal_plan(self.spoke["name"])
        if problems: raise RuntimeError("cannot renew: " + "; ".join(problems))
        self.renewal = det
        s["summary"] = f"{det['name']}: certificate {det.get('serial', '-')[:12]}… expires {det.get('expires', '-')}, {len(det['tunnels'])} tunnel(s) to re-authenticate"
        self.say(s["summary"])

    def do_renew_pki(self, s):
        rc = self.sh(["./lab.sh", "nautobot", "pki", "--force", self.spoke["name"]])
        if rc: raise RuntimeError(f"certificate renewal failed (rc={rc})")
        m = [l["line"] for l in self.log if l["line"].startswith(f"{self.spoke['name']}: renewed")]
        s["summary"] = m[-1] if m else "renewed"

    def do_renew_verify(self, s):
        rc = self.sh(["./lab.sh", "nautobot", "pki", "--post-apply", "--rekey", self.spoke["name"]])
        if rc: raise RuntimeError(f"verification after the renewal failed (rc={rc})")
        m = [l["line"] for l in self.log if "IKEv2 SAs READY, authenticated with certificates" in l["line"]]
        s["summary"] = m[-1] if m else "verified"

    # ---- PSK rotation steps -----------------------------------------------------
    def do_rot_validate(self, s):
        problems, det = spokes.rotation_plan(self.spoke["name"])
        if problems: raise RuntimeError("cannot rotate: " + "; ".join(problems))
        self.rotation = det
        s["summary"] = f"{det['name']}: {len(det['tunnels'])} tunnel(s) to {', '.join(det['headends'])}; current key fingerprint {det['fingerprint']}" + (f", rotated {det['rotated']}" if det.get("rotated") else "")
        self.say(s["summary"])

    def do_rot_intent(self, s):
        key, fp = spokes.rotate_psk(self.spoke["name"], (self.spoke.get("psk") or None))
        self.rotation["new_fingerprint"] = fp
        s["summary"] = f"new {len(key)}-character key for {self.spoke['name']} (fingerprint {fp}) written to lab-intent.json; the key itself is never logged"
        self.say(s["summary"])

    def _ios(self, host):
        from netmiko import ConnectHandler
        return ConnectHandler(device_type="cisco_xe", host=host, username=os.environ.get("IOSXE_USERNAME", "admin"), password=os.environ.get("IOSXE_PASSWORD", "admin"), fast_cli=False)

    def do_rot_rekey(self, s):
        """IKEv2 keeps an established SA until its lifetime ends: clear the spoke's SAs so every tunnel re-authenticates with the new key now."""
        det = self.rotation; c = self._ios(det["mgmt_ip"])
        try:
            before = c.send_command("show crypto ikev2 sa | count READY"); c.send_command("clear crypto ikev2 sa", read_timeout=60)
            self.say(f"{det['name']}: cleared IKEv2 SAs ({before.strip()})")
        finally: c.disconnect()
        s["summary"] = f"{det['name']}: IKEv2 SAs cleared, tunnels re-authenticating with the new key"

    def do_rot_verify(self, s):
        """Every tunnel of the spoke must come back with the new key: IKEv2 SA READY on the headend for the spoke's WAN address and the
        eBGP session over the tunnel Established — within 4 minutes, else the run fails (the old key is gone from the intent, so a
        failed verification is a page-worthy state, not a silent one)."""
        det = self.rotation; want = {(t["hub"], t["spoke_src_ip"], str(ipaddress.IPv4Network(t["tunnel_prefix"]).network_address + 2)) for t in det["tunnels"]}
        deadline = time.time() + 240; missing = set(want)
        while time.time() < deadline and missing:
            time.sleep(15); still = set()
            for hub in det["headends"]:
                hub_ip = next(d["mgmt_ip"] for d in self.intent["devices"] if d["name"] == hub)
                try:
                    c = self._ios(hub_ip); sa = c.send_command("show crypto ikev2 sa"); bgp = c.send_command("show bgp ipv4 unicast summary | begin Neighbor"); c.disconnect()
                except Exception as e:  # noqa: BLE001
                    self.say(f"{hub}: {e.__class__.__name__}, retrying"); still |= {w for w in missing if w[0] == hub}; continue
                for w in missing:
                    if w[0] != hub: continue
                    ike_ok = any(w[1] in l and "READY" in l for l in sa.splitlines())
                    bgp_ok = any(l.split() and l.split()[0] == w[2] and l.split()[-1].isdigit() for l in bgp.splitlines())
                    if not (ike_ok and bgp_ok): still.add(w)
                    else: self.say(f"{hub} <- {det['name']} ({w[1]}): IKEv2 READY, eBGP Established")
            missing = still
        if missing: raise RuntimeError("not back with the new key: " + "; ".join(f"{h} <- {ip}" for h, ip, _ in sorted(missing)))
        s["summary"] = f"all {len(want)} tunnels of {det['name']} re-keyed: IKEv2 READY + eBGP Established on {', '.join(det['headends'])} (key {det['new_fingerprint']})"

    def do_nautobot(self, s):
        rc = self.sh(["./lab.sh", "nautobot", "seed"])
        if rc: raise RuntimeError(f"Nautobot seed failed (rc={rc})")
        m = [l["line"] for l in self.log if l["line"].startswith("seed complete")]
        s["summary"] = m[-1] if m else "seeded"

    def do_render(self, s):
        rc = self.sh(["./lab.sh", "nautobot", "render"])
        if rc: raise RuntimeError(f"render failed (rc={rc})")
        s["summary"] = "nac/data/devices.nac.yaml + device_groups.nac.yaml regenerated from Nautobot"

    def do_firewalls(self, s):
        """VyOS firewalls: interface addresses from the model, policy from the config context; pushed before Terraform so
        the underlay through the firewall exists when the tunnels come up."""
        rc = self.sh(["./lab.sh", "nautobot", "vyos"])
        if rc: raise RuntimeError(f"firewall push failed (rc={rc})")
        done = [l["line"] for l in self.log if l["line"].endswith("commands)") and ": " in l["line"]]
        s["summary"] = "; ".join(x.split(" (")[0] for x in done[-8:]) or "no firewalls"

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


from labportal import parse_robot   # noqa: E402


# ---- API -------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def index():
    return FileResponse(Path(__file__).resolve().parent / "static" / "index.html", headers={"Cache-Control": "no-store"})


@app.get("/metrics", tags=["monitoring"], summary="Prometheus metrics: VMs running per role, run outcomes, last test results", response_class=PlainTextResponse)
def prometheus_metrics():
    """Scraped by the Prometheus on the NMS (lab-portal/monitoring). The routers themselves are not scraped: IOS-XE has no
    Prometheus exporter; the VyOS firewalls get node-exporter / frr-exporter when the lab is next brought up."""
    out = metrics_generated("cat8000v-ipsec"); L = "cat8000v-ipsec"
    out += ["# HELP lab_vm_running 1 if the lab VM is running (virsh)", "# TYPE lab_vm_running gauge"]
    states = _vm_states()
    for (node, role), st in states.items(): out.append(metric_line("lab_vm_running", {"lab": L, "node": node, "role": role}, int(st == "running")))
    # tunnels and headends: the live inventory (IKEv2 SA / VTI / eBGP / ESP counters from every headend over SSH, cached by the
    # inventory service for its TTL) — only while the headends run, so a powered-off lab costs nothing and raises no alert
    hubs_up = any(st == "running" for (node, role), st in states.items() if role == "hub")
    if hubs_up:
        try: out += tunnel_metrics(inv().get(with_live=True), L)
        except Exception as e:  # noqa: BLE001
            out += ["# HELP lab_inventory_error 1 if the tunnel inventory could not be collected", "# TYPE lab_inventory_error gauge", metric_line("lab_inventory_error", {"lab": L, "error": e.__class__.__name__}, 1)]
    return PlainTextResponse(exposition(out + run_metrics(L, registry.list())), media_type="text/plain; version=0.0.4")


def tunnel_metrics(data, L):
    """Per tunnel: health (2 up / 1 degraded = IKE READY but VTI or BGP not / 0 down), IKE SA age, BGP prefixes, ESP packet and
    error counters, VTI rates. Per headend: tunnels modelled / up, capacity and free slots (model, effective), utilisation
    (the binding constraint), CPU / QFP / DRAM, IKE sessions, bandwidth. Summary: totals."""
    H = {"up": 2, "degraded": 1, "down": 0}
    out = ["# HELP lab_tunnel_health 2 = up (IKE READY, VTI up, eBGP Established), 1 = degraded (IKE up, VTI or BGP not), 0 = down", "# TYPE lab_tunnel_health gauge",
           "# HELP lab_tunnel_ike_sa_age_seconds Age of the IKEv2 SA", "# TYPE lab_tunnel_ike_sa_age_seconds gauge",
           "# HELP lab_tunnel_bgp_prefixes Prefixes received from the spoke over the tunnel's eBGP session", "# TYPE lab_tunnel_bgp_prefixes gauge",
           "# HELP lab_tunnel_esp_encaps_packets_total ESP packets encapsulated on the headend's VTI", "# TYPE lab_tunnel_esp_encaps_packets_total counter",
           "# HELP lab_tunnel_esp_decaps_packets_total ESP packets decapsulated on the headend's VTI", "# TYPE lab_tunnel_esp_decaps_packets_total counter",
           "# HELP lab_tunnel_esp_send_errors_total ESP send errors on the headend's VTI", "# TYPE lab_tunnel_esp_send_errors_total counter",
           "# HELP lab_tunnel_esp_recv_errors_total ESP receive errors on the headend's VTI", "# TYPE lab_tunnel_esp_recv_errors_total counter",
           "# HELP lab_tunnel_in_bps VTI input rate on the headend (5-minute average, bit/s)", "# TYPE lab_tunnel_in_bps gauge",
           "# HELP lab_tunnel_out_bps VTI output rate on the headend (5-minute average, bit/s)", "# TYPE lab_tunnel_out_bps gauge"]
    for t in data["tunnels"]:
        lv = t.get("live") or {}
        if not lv or "error" in lv: continue
        lab = {"lab": L, "tunnel": t["name"], "tunnel_id": t["tunnel_id"], "headend": t["headend"], "spoke": t["spoke"], "vpn": t["vpn"], "region": t.get("spoke_region") or ""}
        out.append(metric_line("lab_tunnel_health", lab, H.get(lv.get("health"), 0)))
        for key, name in (("ike_active_s", "lab_tunnel_ike_sa_age_seconds"), ("bgp_prefixes", "lab_tunnel_bgp_prefixes"), ("encaps", "lab_tunnel_esp_encaps_packets_total"), ("decaps", "lab_tunnel_esp_decaps_packets_total"),
                          ("send_errors", "lab_tunnel_esp_send_errors_total"), ("recv_errors", "lab_tunnel_esp_recv_errors_total"), ("in_rate_bps", "lab_tunnel_in_bps"), ("out_rate_bps", "lab_tunnel_out_bps")):
            if lv.get(key) is not None: out.append(metric_line(name, lab, lv[key]))
    out += ["# HELP lab_headend_tunnels Tunnels modelled on the headend", "# TYPE lab_headend_tunnels gauge",
            "# HELP lab_headend_tunnels_up Tunnels of the headend that are up (IKE + VTI + BGP)", "# TYPE lab_headend_tunnels_up gauge",
            "# HELP lab_headend_capacity Tunnel capacity of the headend (model)", "# TYPE lab_headend_capacity gauge",
            "# HELP lab_headend_effective_free Free tunnel slots after the tunnel, bandwidth and CPU constraints", "# TYPE lab_headend_effective_free gauge",
            "# HELP lab_headend_utilisation_pct Utilisation of the binding constraint (tunnels, bandwidth or CPU)", "# TYPE lab_headend_utilisation_pct gauge",
            "# HELP lab_headend_cpu_pct Control-plane CPU of the headend (show platform resources)", "# TYPE lab_headend_cpu_pct gauge",
            "# HELP lab_headend_qfp_cpu_pct QFP (data-plane) CPU of the headend", "# TYPE lab_headend_qfp_cpu_pct gauge",
            "# HELP lab_headend_dram_pct DRAM in use on the headend", "# TYPE lab_headend_dram_pct gauge",
            "# HELP lab_headend_ike_sessions IKEv2 SAs on the headend", "# TYPE lab_headend_ike_sessions gauge",
            "# HELP lab_headend_bandwidth_used_mbps Bandwidth committed by the headend's tunnels", "# TYPE lab_headend_bandwidth_used_mbps gauge",
            "# HELP lab_headend_bandwidth_mbps Bandwidth of the firewall in front of the headend", "# TYPE lab_headend_bandwidth_mbps gauge",
            "# HELP lab_headend_collect_error 1 if the live state of the headend could not be collected", "# TYPE lab_headend_collect_error gauge",
            "# HELP lab_headend_binding The constraint that binds the headend's capacity (tunnels, bandwidth or cpu) as a label", "# TYPE lab_headend_binding gauge"]
    for h in data["headends"]:
        lab = {"lab": L, "headend": h["name"], "region": h.get("region") or ""}; lv = h.get("live") or {}
        out.append(metric_line("lab_headend_collect_error", {"lab": L, "headend": h["name"]}, int("error" in lv)))
        out.append(metric_line("lab_headend_binding", {**lab, "binding": h.get("binding") or "unknown"}, 1))
        for key, name in (("tunnels", "lab_headend_tunnels"), ("tunnels_up", "lab_headend_tunnels_up"), ("capacity", "lab_headend_capacity"), ("effective_free", "lab_headend_effective_free"),
                          ("aggregate_utilisation", "lab_headend_utilisation_pct"), ("cpu_pct", "lab_headend_cpu_pct"), ("qfp_cpu_pct", "lab_headend_qfp_cpu_pct"), ("dram_pct", "lab_headend_dram_pct"),
                          ("bandwidth_used_mbps", "lab_headend_bandwidth_used_mbps"), ("bandwidth_mbps", "lab_headend_bandwidth_mbps")):
            if h.get(key) is not None: out.append(metric_line(name, lab, h[key]))
        if lv.get("ike_sessions") is not None: out.append(metric_line("lab_headend_ike_sessions", lab, lv["ike_sessions"]))
    # certificates (pki/index.json — what the lab CA issued; the pki step keeps the routers on it): expiry per router, the IKE authentication mode
    try:
        I = intent_mod.load(); cert_mode = (I.get("profile", {}).get("ike") or {}).get("authentication", "psk") == "certificate"; st = lab_ca.status()
        out += ["# HELP lab_ike_certificate_auth 1 when IKE authenticates with certificates from the lab CA, 0 with pre-shared keys", "# TYPE lab_ike_certificate_auth gauge", metric_line("lab_ike_certificate_auth", {"lab": L}, int(cert_mode)),
                "# HELP lab_cert_not_after_seconds Expiry of the router certificate the lab CA issued (unix time)", "# TYPE lab_cert_not_after_seconds gauge"]
        roles = {d["name"]: d["role"] for d in I.get("devices", [])}
        for dev, e in (st.get("devices") or {}).items():
            if dev in roles: out.append(metric_line("lab_cert_not_after_seconds", {"lab": L, "device": dev, "role": roles[dev]}, int(datetime.datetime.fromisoformat(e["not_after"]).timestamp())))
        if st.get("ca"): out += ["# HELP lab_ca_not_after_seconds Expiry of the lab CA certificate (unix time)", "# TYPE lab_ca_not_after_seconds gauge", metric_line("lab_ca_not_after_seconds", {"lab": L}, int(datetime.datetime.fromisoformat(st["ca"]["not_after"]).timestamp()))]
    except Exception as e:  # noqa: BLE001 — never break the scrape over the CA index
        out.append(f"# certificate metrics unavailable: {e.__class__.__name__}")
    sm = data.get("summary") or {}
    out += ["# HELP lab_tunnels_total Tunnels modelled in Nautobot", "# TYPE lab_tunnels_total gauge", metric_line("lab_tunnels_total", {"lab": L}, sm.get("tunnels", 0)),
            "# HELP lab_tunnels_up Tunnels up (IKE + VTI + BGP)", "# TYPE lab_tunnels_up gauge", metric_line("lab_tunnels_up", {"lab": L}, sm.get("tunnels_up", 0))]
    return out


@app.get("/api/sd", tags=["monitoring"], summary="Prometheus HTTP service discovery: this portal (and the firewalls' exporters once configured)")
def prometheus_sd():
    return [{"targets": [f"{os.environ.get('LAB_HOST_IP', '10.2.0.1')}:{os.environ.get('WEBAPP_PORT', '8090')}"], "labels": {"lab": "cat8000v-ipsec", "job": "portal", "role": "portal"}}]


def _vm_states():
    """virsh state per lab VM (a stopped lab is a normal state, not an error)."""
    try: running = set(subprocess.run(["sg", "libvirt", "-c", "virsh list --name"], capture_output=True, text=True, timeout=20).stdout.split())
    except Exception: running = set()  # noqa: BLE001
    return {(n["node"], n["role"]): ("running" if n["node"] in running else "shut off") for n in intent_mod.nodes().values()}


@app.get("/api/firewalls", tags=["monitoring"], summary="The Firewalls page: each VyOS firewall's interfaces, live rule set with counters, and its firewall log for the last hours")
def firewalls_page(hours: int = Query(3, ge=1, le=2160, description="how far back to read the firewall log (ssh: what the firewall's journal holds; logs: up to VictoriaLogs' 90-day retention)"),
                   refresh: bool = Query(False, description="collect again now (otherwise cached for 60 s)"),
                   source: str = Query("ssh", pattern="^(ssh|logs)$", description="where the log comes from: ssh = `show log firewall` on the box, logs = VictoriaLogs on the NMS (the firewalls' remote syslog)")):
    """Collected over SSH from every firewall: `show interfaces`, `show firewall` (rules, packets, bytes, conditions) joined with the rule
    descriptions from the configuration, and — `source=ssh` — `show log firewall` parsed into fields (rule, verdict, in / out, source /
    destination with the lab device names, protocol, ports) plus the same entries grouped per flow. With `source=logs` the log and the
    per-flow summary come from VictoriaLogs instead (the firewalls ship their syslog there), aggregated over the whole window."""
    return fw_mod.collect(hours, refresh, source)


@app.get("/api/tools", tags=["monitoring"], summary="The Tools page: every tool's URL, and how to reach each router / firewall (lab credentials)")
def tools():
    """LAN-side URLs of the shared tools (the NMS services are relayed on the lab host's LAN address) and, per lab VM, the
    management address, SSH / RESTCONF / console access and the credentials. Lab infrastructure: the credentials are the
    well-known lab defaults, which is why this is fine to show here and never would be anywhere else."""
    lan = os.environ.get("LAB_LAN_HOST", "192.168.50.231"); ios_u, ios_p = os.environ.get("IOSXE_USERNAME", "admin"), os.environ.get("IOSXE_PASSWORD", "admin")
    vy_u, vy_p = os.environ.get("VYOS_USERNAME", "vyos"), os.environ.get("VYOS_PASSWORD", "vyos")
    tools = [
        {"name": "Lab hub", "url": f"http://{lan}:8088", "what": "every lab on this host at a glance; links to all of the below", "login": "none"},
        {"name": "This portal", "url": f"http://{lan}:8090", "what": "VPN provisioning (C8000v IPsec lab); REST API at /docs", "login": "local users — lab defaults admin / admin (approver), operator / operator, viewer / viewer; `python3 webapp/auth.py add …` to change"},
        {"name": "SRv6 core portal", "url": f"http://{lan}:8091", "what": "the SRv6 lab's tenant provisioning portal", "login": "none"},
        {"name": "Nautobot", "url": NAUTOBOT_PUBLIC_URL, "what": "source of truth: devices, locations (with coordinates), VPN app, BGP, Golden Config", "login": "superuser — see NAUTOBOT_SUPERUSER_* in lab@10.0.0.10:/opt/nautobot/.env"},
        {"name": "Grafana", "url": f"http://{lan}:3001", "what": "dashboards (C8000v IPsec overview, SRv6 core overview, node detail, fleet); anonymous viewing", "login": "admin / admin (edit)"},
        {"name": "Grafana: IPsec overview", "url": f"http://{lan}:3001/d/cat8000v-ipsec-overview", "what": "tunnels, headend capacity / CPU, the lab host", "login": "none"},
        {"name": "Prometheus", "url": f"http://{lan}:9091", "what": "scrapes the portals, exporters and the lab host; alert rules at /alerts (9090 on the host is Cockpit)", "login": "none"},
        {"name": "VictoriaMetrics", "url": f"http://{lan}:8428/vmui", "what": "long-term metrics (Prometheus remote-write, Telegraf)", "login": "none"},
        {"name": "VictoriaLogs", "url": f"http://{lan}:9428/select/vmui", "what": "syslog from the routers, sFlow flows", "login": "none"},
        {"name": "Gitea", "url": f"http://{lan}:3000", "what": "Golden Config backups (lab/c8000v-ipsec-configs, lab/srv6-core-configs), CI mirror + runs", "login": "lab — see GITEA_PASSWORD in lab@10.0.0.10:/opt/nautobot/.env"},
        {"name": "GitHub", "url": "https://github.com/dcantor/cat8000v-ipsec", "what": "this lab's repository (srv6-core and lab-portal alongside)", "login": "public"},
    ]
    I = intent_mod.load(); nodes = {v["node"]: v for v in intent_mod.nodes().values()}
    devices = []
    for d in sorted(I["devices"], key=lambda x: ({"hub": 0, "firewall": 1, "spoke": 2}.get(x["role"], 3), x["name"])):
        n = nodes.get(d["name"], {}); ios = d["role"] in ("hub", "spoke")
        devices.append({"name": d["name"], "role": d["role"], "platform": "Cisco C8000v (IOS-XE)" if ios else "VyOS", "mgmt_ip": d["mgmt_ip"], "region": d.get("region"), "site": d.get("site"), "city": d.get("city"),
                        "ssh": f"ssh {ios_u if ios else vy_u}@{d['mgmt_ip']}", "username": ios_u if ios else vy_u, "password": ios_p if ios else vy_p,
                        "restconf": f"https://{d['mgmt_ip']}/restconf/" if ios else None, "netconf": f"{d['mgmt_ip']}:830" if ios else None,
                        "console_port": n.get("console"), "console": f"./lab.sh console {d['name']}" + (f"  (or: telnet 127.0.0.1 {n['console']} on the host)" if n.get("console") else ""),
                        "lan": d.get("lan"), "asn": d.get("asn") if ios else None})
    return {"disclaimer": "LAB INFRASTRUCTURE — NOT PRODUCTION. Everything here is a simulated environment on one KVM host: the addresses are private, the credentials are lab defaults shared by every device, and nothing on this page may be reused for, or connected to, a production network.",
            "lan_host": lan, "oob": {"prefix": I["oob"]["prefix"], "gateway": I["oob"]["gateway"], "note": f"the OOB network is reachable from the lab host only (ssh {os.environ.get('USER', 'dcantor')}@{lan} first, or through the portal / Nautobot)"},
            "host": {"ssh": f"ssh {os.environ.get('USER', 'dcantor')}@{lan}", "lab_dir": str(LAB), "console_note": "serial consoles are raw TCP on the host's 127.0.0.1 (./lab.sh console <node> wraps them)"},
            "tools": tools, "devices": devices}


@app.get("/api/intent", tags=["intent"], summary="Current intent + wiring facts")
def get_intent():
    """The saved `lab-intent.json` plus the physical wiring and VM facts from `lab.conf` (the form cannot change those)."""
    return {"intent": intent_mod.load(), "wiring": intent_mod.wiring(), "nodes": intent_mod.nodes(),
            "intent_file": str(intent_mod.INTENT_FILE), "nautobot_url": NAUTOBOT_PUBLIC_URL}


@app.get("/api/inventory", tags=["intent"], summary="Routers as Nautobot sees them")
def inventory():
    """Devices at the lab location as onboarded into Nautobot (serial, model, role, management IP) and the VPN object's URL."""
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


@app.get("/api/vpn-inventory", tags=["inventory"], summary="Tunnel inventory with live state and capacity")
def vpn_inventory(refresh: bool = Query(False, description="re-collect live state now (otherwise cached for 30 s)"), live: bool = Query(True, description="include live state from the headends (SSH)")):
    """Modelled tunnels from Nautobot's VPN app joined with live IKEv2 SA / VTI / eBGP / ESP state collected from every headend,
    per-headend capacity (custom field `vpn_tunnel_capacity`), the location's devices (for the topology map) and summary KPIs."""
    try: return inv().get(refresh=refresh, with_live=live)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"inventory unavailable: {e}")


@app.get("/api/vpn-inventory.csv", tags=["inventory"], summary="Tunnel inventory as CSV", response_class=PlainTextResponse)
def vpn_inventory_csv(refresh: bool = Query(False)):
    """One row per tunnel: model fields (headend, spoke, region/site, addresses, profile, ticket) and live fields (health, IKE SA age, BGP, ESP counters, rates)."""
    data = inv().get(refresh=refresh)
    return PlainTextResponse(to_csv(data), media_type="text/csv", headers={"Content-Disposition": f"attachment; filename=vpn-inventory-{datetime.now():%Y%m%d-%H%M%S}.csv"})


@app.post("/api/validate", tags=["intent"], summary="Validate an intent", response_model=S.Problems)
def validate(body: dict):
    """Shape, addressing, uniqueness, capacity, and that the links match the physical wiring. Body: `{"intent": Intent}`."""
    return {"problems": intent_mod.validate(body.get("intent") or {})}


@app.get("/api/spokes/suggest", tags=["provisioning"], summary="Suggest a fully allocated new spoke")
def spoke_suggest(hubs: str = Query("", description="comma-separated headends to connect to (default: the two nearest to the region)"),
                  region: str = Query("", description="the spoke's region (default: the first region)")):
    """Hostname, management IP, VM index/console port, router-id, LAN, AS, site/site code/contact, a generated PSK, and per-headend
    link allocations (hub port, spoke port, WAN /30, tunnel number, tunnel /30). Everything is editable; POST it to `/api/runs` with mode `spoke`."""
    return spokes.suggest([h for h in hubs.split(",") if h] or None, region or None)


@app.get("/api/cities", tags=["provisioning"], summary="US cities a site can be placed in (name, lat, lon, region) — the map places sites by these coordinates")
def cities_list():
    I = intent_mod.load(); regions = I.get("regions") or []
    return [{"city": c, "lat": ll[0], "lon": ll[1], "region": cities.region_of(ll[1], regions)} for c, ll in cities.CITIES.items()]


@app.get("/api/hubs/suggest", tags=["provisioning"], summary="Suggest a new headend")
def hub_suggest():
    """Identity for a new headend; `connect_spokes` lists the spokes it will be linked to (each on its next free WAN port). POST to `/api/runs` with mode `hub`."""
    return spokes.suggest_hub()


@app.post("/api/spokes/validate", tags=["provisioning"], summary="Validate a spoke spec", response_model=S.SpokeValidation)
def spoke_validate(body: dict):
    """Body: `{"spoke": SpokeSpec}`. Checks free hub ports, unused prefixes / tunnel ids / AS, at least two headends, capacity, host memory.
    When valid, `hub_changes` describes what each headend and the spoke will be configured with."""
    spec = body.get("spoke") or {}
    problems = spokes.validate(spec)
    return {"problems": problems, "hub_changes": spokes.hub_changes(spec) if not problems else None}


@app.get("/api/spokes/{name}/rehome", tags=["provisioning"], summary="Plan a re-homing: the spoke on a given set of headends (what is added, dropped, allocated)")
def spoke_rehome(name: str = PathParam(..., examples=["spoke2"]), hubs: str = Query(..., description="comma-separated wanted headends (at least two)")):
    problems, details = spokes.rehome_plan(name, [h for h in hubs.split(",") if h])
    return {"problems": problems, "details": details}


@app.get("/api/routers/{name}/renewal", tags=["provisioning"], summary="Plan a certificate renewal for a router (its current certificate, the tunnels that re-authenticate)")
def renewal_plan(name: str):
    problems, details = spokes.renewal_plan(name)
    return {"ok": not problems, "problems": problems, **(details or {})}


@app.get("/api/pki", tags=["monitoring"], summary="The lab CA and every router certificate it issued (pki/index.json), with days left; the IKE authentication mode")
def pki_status():
    I = intent_mod.load(); st = lab_ca.status()
    return {"authentication": (I.get("profile", {}).get("ike") or {}).get("authentication", "psk"), "pki": I.get("profile", {}).get("pki") or {}, **st}


@app.get("/api/spokes/{name}/rotation", tags=["provisioning"], summary="Plan a PSK rotation for a spoke (what it touches; the current key's fingerprint)")
def spoke_rotation(name: str = PathParam(..., examples=["spoke3"])):
    problems, details = spokes.rotation_plan(name)
    return {"problems": problems, "details": details}


@app.get("/api/spokes/{name}/removal", tags=["provisioning"], summary="Plan a spoke's removal", response_model=S.RemovalPlan)
def spoke_removal(name: str = PathParam(..., description="spoke hostname", examples=["spoke5"])):
    """What decommissioning releases (LAN, router-id, WAN/tunnel prefixes) and what each headend loses (port, TunnelN, BGP neighbour), with capacity after."""
    problems, det = spokes.removal_plan(name)
    return {"problems": problems, "details": det}


@app.post("/api/runs", tags=["runs"], summary="Start a pipeline run", response_model=S.Run, response_model_exclude_none=True, status_code=200,
          responses={409: {"description": "a run is already in progress"}, 422: {"description": "validation problems ({detail: {problems: [...]}})"}})
def start_run(body: S.RunRequest, request: Request):
    """Runs execute one at a time in the background. Modes:

    * **deploy** – `intent` → save → Nautobot seed → render NAC → terraform plan → apply → Golden Config → tests
    * **plan** – the same, stopping after terraform plan (nothing pushed)
    * **test** – Robot Framework suite only
    * **spoke** – `spoke` (a SpokeSpec): register in lab.conf, create + boot the VM, bootstrap, onboard, add to the intent, then the deploy pipeline (hub + spoke in one apply)
    * **hub** – `hub` (a HubSpec): same for a new headend, linked to every spoke
    * **remove** – `spoke.name`: power off, Nautobot clean-up, intent/lab.conf, terraform state, apply on the headends, delete the VM, Golden Config, tests
    * **rehome** – `spoke.name` + `spoke.hubs` (the wanted set of headends, at least two): new links / tunnels allocated for the headends to
      add (the spoke VM is redefined and rebooted for the new NIC), the dropped ones removed from intent, lab.conf and Nautobot, then
      seed → render → firewalls → terraform on the hubs and the spoke → verify new tunnels up and dropped ones gone → Golden Config
    * **rotate** – `spoke.name` (optional `spoke.psk` to set a chosen key): new pre-shared key → intent → Nautobot (fingerprint + date on the
      tunnels) → NaC render → terraform on the spoke and every headend → clear the spoke's IKEv2 SAs → verify every tunnel is back
      (IKEv2 READY + eBGP Established) → Golden Config; tests optional (`options.test`, default off)
    * **renew** – `spoke.name` (any router, headend or spoke; IKE authentication `certificate`): a new CSR from the router, signed by the
      lab CA, imported → Nautobot's cert_* fields → the router's IKEv2 SAs cleared → every tunnel back READY with RSA; tests optional
    """
    body = body.model_dump(exclude_none=True)
    mode = body.get("mode", "deploy")
    if mode not in ("deploy", "plan", "test", "spoke", "hub", "remove", "rotate", "rehome", "renew"): raise HTTPException(400, "mode must be deploy, plan, test, spoke, hub, remove, rotate, rehome or renew")
    spoke = None
    if mode == "renew":
        spoke = body.get("spoke") or body.get("router") or {}; problems, _ = spokes.renewal_plan(spoke.get("name", ""))
        if problems: raise HTTPException(422, {"problems": problems})
        intent = intent_mod.load()
    elif mode == "rehome":
        spoke = body.get("spoke") or {}; problems, _ = spokes.rehome_plan(spoke.get("name", ""), spoke.get("hubs") or [])
        if problems: raise HTTPException(422, {"problems": problems})
        intent = intent_mod.load()
    elif mode == "rotate":
        spoke = body.get("spoke") or {}; problems, _ = spokes.rotation_plan(spoke.get("name", ""))
        if spoke.get("psk") and not re.fullmatch(r"[A-Za-z0-9_.-]{8,64}", spoke["psk"]): problems.append("pre-shared key: 8-64 characters, letters/digits/_.-")
        if problems: raise HTTPException(422, {"problems": problems})
        intent = intent_mod.load()
    elif mode == "remove":
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
    try: run = registry.start(Run(mode, intent, body.get("options") or {}, spoke))
    except RuntimeError as e: raise HTTPException(409, str(e))
    request.state.run_id = run["id"] if isinstance(run, dict) else getattr(run, "id", None)
    return run


def _resume(d):
    f = RUNS_DIR / f"{d['id']}.intent.json"
    intent = json.loads(f.read_text()) if (f.exists() and d["mode"] in ("deploy", "plan")) else intent_mod.load()
    return Run(d["mode"], intent, d.get("options") or {}, d.get("spoke"), resume_of=d)


install_runs_api(app, registry, resume_factory=_resume)


app.mount("/results", StaticFiles(directory=str(RESULTS), html=True), name="results")
app.mount("/static", StaticFiles(directory=str(Path(__file__).resolve().parent / "static")), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.environ.get("WEBAPP_HOST", "0.0.0.0"), port=int(os.environ.get("WEBAPP_PORT", "8090")))
