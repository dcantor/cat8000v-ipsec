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
import json, os, re, subprocess, sys, time
from datetime import datetime
from pathlib import Path
from labportal import RunBase, RunRegistry, install_runs_api, metric_line, run_metrics, exposition, metrics_generated

from fastapi import FastAPI, HTTPException, Query, Path as PathParam
from fastapi.openapi.docs import get_swagger_ui_html
import schemas as S
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
STEP_TITLES = {"validate": "Validate intent", "save": "Save intent", "nautobot": "Nautobot source of truth (seed)", "firewalls": "VyOS firewalls rendered from Nautobot and pushed",
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


def nautobot_token():
    tok = os.environ.get("NAUTOBOT_TOKEN")
    if not tok:
        tok = subprocess.run(["bash", "-c", f"cd {LAB} && ./lab.sh nautobot token"], capture_output=True, text=True, timeout=60).stdout.strip()
    return tok


class Run(RunBase):
    LAB = "cat8000v-ipsec"
    STEP_TITLES = STEP_TITLES
    EXTRA = {"site": "site", "vpn": "vpn", "change_ticket": "change_ticket", "devices": "devices", "spoke": "spoke", "removal": "removal"}

    def __init__(self, mode, intent, options, spoke=None, resume_of=None):
        self.intent, self.spoke = intent, spoke
        self.site, self.vpn = intent.get("site", {}).get("name"), intent.get("vpn", {}).get("name"); self.change_ticket = intent.get("vpn", {}).get("change_ticket")
        self.devices = [d["name"] for d in intent.get("devices", [])]
        self.removal = (resume_of or {}).get("removal") if mode == "remove" and resume_of and any(st["name"] == "rm_validate" and st["status"] == "success" for st in resume_of["steps"]) else None
        super().__init__(mode, options, resume_of, runs_dir=RUNS_DIR, cwd=LAB)

    def sh(self, cmd, cwd=None, env=None, timeout=3600, check=False):   # this portal inspects exit codes itself (terraform's -detailed-exitcode)
        return super().sh(cmd, cwd=cwd, env=env, timeout=timeout, check=check)

    def plan(self):
        if self.mode == "test": return ["validate", "test"]
        if self.mode == "spoke":
            steps = ["spoke_validate", "spoke_labconf", "spoke_vm", "spoke_bootstrap", "spoke_onboard", "spoke_intent", "nautobot", "render", "firewalls", "plan", "apply"]
            if self.options.get("golden", True): steps.append("golden")
            if self.options.get("test", True): steps.append("test")
            return steps
        if self.mode == "hub":
            steps = ["hub_validate", "hub_labconf", "hub_vm", "hub_bootstrap", "hub_onboard", "hub_intent", "nautobot", "render", "firewalls", "plan", "apply"]
            if self.options.get("golden", True): steps.append("golden")
            if self.options.get("test", True): steps.append("test")
            return steps
        if self.mode == "remove":
            # hub config is removed by Terraform (native tunnel/ethernet/BGP resources are destroyed) once the spoke is gone from Nautobot
            steps = ["rm_validate", "rm_down", "rm_nautobot", "rm_intent", "nautobot", "render", "firewalls", "rm_state", "plan", "apply", "rm_vm"]
            if self.options.get("golden", True): steps.append("golden")
            if self.options.get("test", True): steps.append("test")
            return steps
        if self.mode == "plan": return ["validate", "save", "nautobot", "render", "plan"]
        steps = ["validate", "save", "nautobot", "render", "firewalls", "plan", "apply"]
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


@app.get("/api/spokes/{name}/removal", tags=["provisioning"], summary="Plan a spoke's removal", response_model=S.RemovalPlan)
def spoke_removal(name: str = PathParam(..., description="spoke hostname", examples=["spoke5"])):
    """What decommissioning releases (LAN, router-id, WAN/tunnel prefixes) and what each headend loses (port, TunnelN, BGP neighbour), with capacity after."""
    problems, det = spokes.removal_plan(name)
    return {"problems": problems, "details": det}


@app.post("/api/runs", tags=["runs"], summary="Start a pipeline run", response_model=S.Run, response_model_exclude_none=True, status_code=200,
          responses={409: {"description": "a run is already in progress"}, 422: {"description": "validation problems ({detail: {problems: [...]}})"}})
def start_run(body: S.RunRequest):
    """Runs execute one at a time in the background. Modes:

    * **deploy** – `intent` → save → Nautobot seed → render NAC → terraform plan → apply → Golden Config → tests
    * **plan** – the same, stopping after terraform plan (nothing pushed)
    * **test** – Robot Framework suite only
    * **spoke** – `spoke` (a SpokeSpec): register in lab.conf, create + boot the VM, bootstrap, onboard, add to the intent, then the deploy pipeline (hub + spoke in one apply)
    * **hub** – `hub` (a HubSpec): same for a new headend, linked to every spoke
    * **remove** – `spoke.name`: power off, Nautobot clean-up, intent/lab.conf, terraform state, apply on the headends, delete the VM, Golden Config, tests
    """
    body = body.model_dump(exclude_none=True)
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
    try: return registry.start(Run(mode, intent, body.get("options") or {}, spoke))
    except RuntimeError as e: raise HTTPException(409, str(e))


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
