#!/usr/bin/env python3
"""Golden Config for the C8000v IPsec VTI routers in the shared Nautobot: a GoldenConfigSetting scoped to
location c8000v-ipsec-lab (same Gitea repos, template c8000v-ipsec.j2), the shared SoT query extended with the
core VPN app's tunnel endpoints, a wan-interface compliance feature, then backup -> intended -> compliance.
Usage: NAUTOBOT_TOKEN=... GITEA_PASSWORD=... golden_config.py [--no-run]"""
import argparse, base64, os, sys, time
from pathlib import Path
import pynautobot, requests

SITE, SLUG, TPL = "c8000v-ipsec-lab", "c8000v-ipsec", "c8000v-ipsec.j2"
p = argparse.ArgumentParser()
p.add_argument("--url", default=os.environ.get("NAUTOBOT_URL", "http://10.0.0.10:8080"))
p.add_argument("--token", default=os.environ.get("NAUTOBOT_TOKEN"))
p.add_argument("--gitea", default=os.environ.get("GITEA_URL", "http://10.0.0.10:3000"))
p.add_argument("--gitea-user", default=os.environ.get("GITEA_USER", "lab"))
p.add_argument("--no-run", action="store_true")
a = p.parse_args()
nb = pynautobot.api(a.url, token=a.token)
gc = nb.plugins.golden_config
H = {"Authorization": f"Token {a.token}", "Accept": "application/json"}

# the shared SoT query (switch lab, extended by the DMVPN lab) gets the core VPN app's tunnel endpoint per interface
gq = nb.extras.graphql_queries.get(name="golden-config-lab")
Q = gq.query
VPN_EP = ("                 vpn_tunnel_endpoints_tunnel { source_interface { name } source_ipaddress { address }\n"
          "                   vpn_profile { name keepalive_enabled keepalive_interval keepalive_retries extra_options\n"
          "                     vpn_phase1_policies { ike_version encryption_algorithm integrity_algorithm dh_group authentication_method }\n"
          "                     vpn_phase2_policies { encryption_algorithm integrity_algorithm } }\n"
          "                   endpoint_a_vpn_tunnels { encapsulation endpoint_z { source_ipaddress { address } } }\n"
          "                   endpoint_z_vpn_tunnels { encapsulation endpoint_a { source_ipaddress { address } } } }\n")
anchor = "                 rel_tunnel_source_source { name ip_addresses { address } }\n"
legacy = "                 rel_tunnel_peer { rel_tunnel_source_source { ip_addresses { address } } }\n"
Q = Q.replace(legacy, "")   # the relationship was dropped when this lab moved to the core VPN model
if "vpn_tunnel_endpoints_tunnel" not in Q and anchor in Q:
    Q = Q.replace(anchor, anchor + VPN_EP)
if Q != gq.query:
    requests.patch(f"{a.url}/api/extras/graphql-queries/{gq.id}/", json={"query": Q}, headers=H, timeout=30).raise_for_status()
    print("  extended GraphQL query golden-config-lab (vpn tunnel endpoints)")

# template -> Gitea
tpl = Path(__file__).resolve().parent / "golden-config-templates" / TPL
pw = os.environ.get("GITEA_PASSWORD")
if pw:
    api = f"{a.gitea}/api/v1/repos/{a.gitea_user}/golden-config-templates/contents/{TPL}"
    cur = requests.get(api, auth=(a.gitea_user, pw), timeout=30)
    body = {"content": base64.b64encode(tpl.read_bytes()).decode(), "branch": "main", "message": f"{TPL} from cat8000v-ipsec lab"}
    if cur.status_code == 200:
        if base64.b64decode(cur.json()["content"]) != tpl.read_bytes():
            body["sha"] = cur.json()["sha"]; requests.put(api, auth=(a.gitea_user, pw), json=body, timeout=30).raise_for_status(); print(f"  updated {TPL} in Gitea")
    else:
        requests.post(api, auth=(a.gitea_user, pw), json=body, timeout=30).raise_for_status(); print(f"  pushed {TPL} to Gitea")

# scope + settings
dg = nb.extras.dynamic_groups.get(name=f"{SLUG}-routers")
if dg is None:
    dg = nb.extras.dynamic_groups.create(name=f"{SLUG}-routers", content_type="dcim.device", group_type="dynamic-filter",
                                         filter={"location": [SITE]}); print(f"  created dynamic group {SLUG}-routers")
repos = {n: nb.extras.git_repositories.get(name=n) for n in ("config-backups", "intended-configs", "golden-config-templates")}
gcs = gc.golden_config_settings.get(name=SLUG)
fields = {"slug": SLUG, "weight": 3000, "dynamic_group": dg.id, "sot_agg_query": gq.id,
          "backup_repository": repos["config-backups"].id, "backup_path_template": "{{obj.name}}.cfg", "backup_test_connectivity": False,
          "intended_repository": repos["intended-configs"].id, "intended_path_template": "{{obj.name}}.cfg",
          "jinja_repository": repos["golden-config-templates"].id, "jinja_path_template": TPL}
if gcs is None:
    gc.golden_config_settings.create(name=SLUG, **fields); print(f"  created golden config setting {SLUG}")
else:
    gcs.update(fields)

plat = nb.dcim.platforms.get(name="cisco_xe")
for slug, fname, match in (("wan-interface", "WAN interface", "interface GigabitEthernet2\ninterface GigabitEthernet3"),):
    feat = gc.compliance_feature.get(slug=slug) or gc.compliance_feature.create(slug=slug, name=fname, description=f"{fname} (from Nautobot)")
    if gc.compliance_rule.get(feature=feat.id, platform=plat.id) is None:
        gc.compliance_rule.create(feature=feat.id, platform=plat.id, config_type="cli", match_config=match,
                                  config_ordered=False, config_remediation=True); print(f"  created compliance rule {slug}")
if a.no_run:
    sys.exit(0)
devs = [d.id for d in nb.dcim.devices.filter(location=SITE)]
def run(name):
    job = nb.extras.jobs.get(name=name)
    if not job.enabled: job.update({"enabled": True})
    res = nb.extras.jobs.run(job_id=job.id, data={"device": devs, "debug": False}); jr = res.job_result.id
    for _ in range(120):
        st = str(nb.extras.job_results.get(jr).status)
        if st in ("SUCCESS", "FAILURE", "REVOKED"): break
        time.sleep(5)
    errs = [e for e in nb.extras.job_logs.filter(job_result=jr) if str(e.log_level) in ("error", "critical", "failure")]
    print(f"==> {name}: {st}"); [print(f"   [{e.log_level}] {e.message[:300]}") for e in errs]
    return st == "SUCCESS" and not errs
ok = run("Backup Configurations") and run("Generate Intended Configurations") and run("Perform Configuration Compliance")
for c in requests.get(f"{a.url}/api/plugins/golden-config/config-compliance/", params={"location": SITE, "limit": 200, "depth": 1}, headers=H, timeout=60).json()["results"]:
    print(f"   compliance {c['device']['name']} / {c['rule']['display']}: {'COMPLIANT' if c['compliance'] else 'NON-COMPLIANT'}" + ("" if c["compliance"] else f"  missing={c['missing']!r} extra={c['extra']!r}"))
sys.exit(0 if ok else 1)
