#!/usr/bin/env python3
"""Render nac/data/devices.nac.yaml for the C8000v IPsec VTI + eBGP lab from Nautobot.

Per router: management host, WAN GiN interfaces from the cabled links, loopbacks, VTI tunnels from the
TunnelN objects (tunnel_mode / tunnel_ipsec_profile custom fields, tunnel_source -> GiN, tunnel_peer ->
far tunnel whose own tunnel_source gives the tunnel destination), the IKEv2/IPsec suite from the "crypto"
config context, and eBGP from nautobot-bgp-models (one AS per site). Only the PSK stays in
device_groups.nac.yaml.  Usage: NAUTOBOT_TOKEN=... render_nac.py [--check]
"""
import argparse, ipaddress, os, sys
from pathlib import Path
import requests, yaml

LAB = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument("--url", default=os.environ.get("NAUTOBOT_URL", "http://10.0.0.10:8080"))
p.add_argument("--token", default=os.environ.get("NAUTOBOT_TOKEN"))
p.add_argument("--out", default=str(LAB / "nac" / "data" / "devices.nac.yaml"))
p.add_argument("--check", action="store_true")
a = p.parse_args()
H = {"Authorization": f"Token {a.token}"}
q = requests.get(f"{a.url}/api/extras/graphql-queries/", params={"name": "nac-c8000v-ipsec-model"}, headers=H, timeout=30).json()
QUERY = q["results"][0]["query"] if q["count"] == 1 else (Path(__file__).resolve().parent / "nac-c8000v-ipsec-model.graphql").read_text()
r = requests.post(f"{a.url}/api/graphql/", json={"query": QUERY}, headers=H, timeout=60); r.raise_for_status()
data = r.json()
if data.get("errors"): sys.exit(f"GraphQL errors: {data['errors']}")
devices = sorted(data["data"]["devices"], key=lambda d: d["name"])
bgp_ri = {x["device"]["name"]: x for x in data["data"]["bgp_routing_instances"]}
MODES = {"gre-multipoint": "gre multipoint", "gre": "gre ip", "ipsec-ipv4": "ipsec ipv4"}

def parts(cidr):
    i = ipaddress.IPv4Interface(cidr); return str(i.ip), str(i.network.netmask)

def tunnel_cli(i, ip, mask):
    src, peer = i["rel_tunnel_source_source"], i["rel_tunnel_peer"]
    lines = [f"interface {i['name']}", f" description {i['description']}", f" ip address {ip} {mask}", " ip mtu 1400", " ip tcp adjust-mss 1360"]
    if src: lines.append(f" tunnel source {src['name']}")
    if peer and peer["rel_tunnel_source_source"]:
        lines.append(f" tunnel destination {peer['rel_tunnel_source_source']['ip_addresses'][0]['address'].split('/')[0]}")
    if i["cf_tunnel_mode"]: lines.append(f" tunnel mode {MODES[i['cf_tunnel_mode']]}")
    if i["cf_tunnel_key"] is not None: lines.append(f" tunnel key {i['cf_tunnel_key']}")
    if i["cf_tunnel_ipsec_profile"]: lines.append(f" tunnel protection ipsec profile {i['cf_tunnel_ipsec_profile']}")
    return "\n".join(lines) + "\n"

def crypto_model(c):
    enc = {"aes-cbc-256": "aes_cbc_256", "aes-cbc-128": "aes_cbc_128", "aes-gcm-256": "aes_gcm_256"}[c["ikev2_proposal"]["encryption"]]
    return {"ikev2": {"proposals": [{"name": c["ikev2_proposal"]["name"], "encryption": [enc], "integrity": [c["ikev2_proposal"]["integrity"]], "group": [str(c["ikev2_proposal"]["group"])]}],
                      "policies": [{"name": c["ikev2_policy"]["name"], "proposals": [c["ikev2_proposal"]["name"]]}],
                      "keyrings": [{"name": c["ikev2_keyring"]["name"], "peers": [{"name": c["ikev2_keyring"]["peer"], "ipv4_address": c["ikev2_keyring"]["peer_address"],
                                                                                  "ipv4_mask": c["ikev2_keyring"]["peer_mask"], "pre_shared_key": "${vpn_psk}"}]}],
                      "profiles": [{"name": c["ikev2_profile"]["name"],
                                    "match_identity_remote_ipv4_addresses": [{"address": c["ikev2_keyring"]["peer_address"], "mask": c["ikev2_keyring"]["peer_mask"]}],
                                    "authentication_local_pre_share": True, "authentication_remote_pre_share": True, "keyring_local": c["ikev2_keyring"]["name"],
                                    "dpd_interval": c["ikev2_profile"]["dpd_interval"], "dpd_retry": c["ikev2_profile"]["dpd_retry"], "dpd_query": "on-demand"}]},
            "ipsec_transform_sets": [{"name": c["ipsec_transform_set"]["name"], "esp": c["ipsec_transform_set"]["esp"], "esp_hmac": c["ipsec_transform_set"]["esp_hmac"]}],
            "ipsec_profiles": [{"name": c["ipsec_profile"]["name"], "set_transform_set": [c["ipsec_transform_set"]["name"]], "set_ikev2_profile": c["ikev2_profile"]["name"]}]}

def render(dev):
    name, ctx = dev["name"], dev["config_context"] or {}
    ethernets, loopbacks, networks, templates, router_id = [], [], [], [], None
    for i in dev["interfaces"]:
        ips = i["ip_addresses"]
        if not ips: continue
        ip, mask = parts(ips[0]["address"]); parent = ips[0]["parent"] or {}
        if any(t["name"] == "bgp:advertise" for t in parent.get("tags", [])):
            pfx = ipaddress.IPv4Network(parent["prefix"])
            classful = pfx.prefixlen == 24 and 192 <= int(str(pfx.network_address).split(".")[0]) <= 223
            networks.append({"network": str(pfx.network_address)} if classful else {"network": str(pfx.network_address), "mask": str(pfx.netmask)})
        n = i["name"]
        if n.startswith("GigabitEthernet") and n != "GigabitEthernet1":
            ethernets.append({"type": "GigabitEthernet", "id": n[15:], "description": i["description"], "shutdown": not i["enabled"], "cdp": True,
                              "ipv4": {"address": ip, "address_mask": mask}})
        elif n.startswith("Loopback"):
            loopbacks.append({"id": int(n[8:]), "description": i["description"], "ipv4": {"address": ip, "address_mask": mask}})
            if n == "Loopback0": router_id = ip
        elif n.startswith("Tunnel"):
            templates.append({"name": f"tunnel_{name}_{n.lower()}", "type": "cli", "content": tunnel_cli(i, ip, mask)})
    ri = bgp_ri[name]
    neighbors, afn = [], []
    for ep in sorted(ri["endpoints"], key=lambda e: e["peer"]["source_ip"]["address"] if e["peer"] else ""):
        if not ep["enabled"] or not ep["peer"]: continue
        peer_ip = ep["peer"]["source_ip"]["address"].split("/")[0]
        neighbors.append({"ip": peer_ip, "remote_as": ep["peer"]["autonomous_system"]["asn"], "description": ep["description"]})
        afn.append({"ip": peer_ip, "activate": True})
    bgp = {"as_number": ri["autonomous_system"]["asn"], "router_id": ri["router_id"]["address"].split("/")[0],
           "log_neighbor_changes": bool((ri["extra_attributes"] or {}).get("log_neighbor_changes", True)), "neighbors": neighbors,
           "address_family": {"ipv4_unicast": {"neighbors": afn, "networks": sorted(networks, key=lambda x: (x.get("mask") != "255.255.255.255", ipaddress.IPv4Address(x["network"])))}}}
    return {"name": name, "host": dev["primary_ip4"]["address"].split("/")[0], "protocol": "restconf", "device_groups": ["IPSEC_VPN"],
            "templates": [t["name"] for t in templates], "_templates": templates,
            "variables": {"router_id": router_id, "bgp_asn": ri["autonomous_system"]["asn"]},
            "configuration": {"system": {"hostname": name, "ip_domain_name": ctx.get("domain_name")},
                              **({"crypto": crypto_model(ctx["crypto"])} if ctx.get("crypto") else {}),
                              "interfaces": {"ethernets": sorted(ethernets, key=lambda e: e["id"]), "loopbacks": loopbacks},
                              "routing": {"bgp": bgp}}}

rendered = [render(d) for d in devices]
templates = [t for d in rendered for t in d.pop("_templates")]
out = ("---\n# GENERATED from Nautobot by nautobot/render_nac.py — do not edit by hand.\n"
       f"# Source of truth: {a.url} (location c8000v-ipsec-lab, saved GraphQL query nac-c8000v-ipsec-model)\n"
       + yaml.safe_dump({"iosxe": {"templates": templates, "devices": rendered}}, sort_keys=False, width=120))
if a.check:
    cur = Path(a.out).read_text() if Path(a.out).exists() else ""
    if cur != out:
        import difflib; sys.stdout.writelines(difflib.unified_diff(cur.splitlines(True), out.splitlines(True), "on-disk", "nautobot")); sys.exit(1)
    print(f"{a.out} matches Nautobot")
else:
    Path(a.out).write_text(out); print(f"wrote {a.out}: {len(devices)} devices")
