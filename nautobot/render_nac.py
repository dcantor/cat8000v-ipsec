#!/usr/bin/env python3
"""Render nac/data/devices.nac.yaml for the C8000v IPsec VTI + eBGP lab from Nautobot.

Per router: management host, WAN GiN interfaces from the cabled links, loopbacks, VTI tunnels as native NAC tunnel
interfaces from the core VPN app (the TunnelN interface's VPN tunnel endpoint: source interface/address, the VPN
tunnel it terminates and the far endpoint's source address = tunnel destination), the IKEv2/IPsec suite from the endpoint's VPN
profile (Phase 1 / Phase 2 policies, Cisco object names in extra_options.ios), and eBGP from
nautobot-bgp-models (one AS per site). Only the PSK stays in device_groups.nac.yaml.  Usage: NAUTOBOT_TOKEN=... render_nac.py [--check]
"""
import argparse, ipaddress, os, sys
from pathlib import Path
import requests, yaml
sys.path.insert(0, str(Path(__file__).resolve().parent)); import intent as intent_mod   # noqa: E402

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
# GraphQL renders choice values as enum names (IPSEC_TUNNEL, AES_256_CBC, IKEV2); keys below use that form
ENCAP = {"IPSEC_TUNNEL": "ipsec ipv4", "GRE": "gre ip"}
IKE_ENC = {"AES_256_CBC": "aes_cbc_256", "AES_192_CBC": "aes_cbc_192", "AES_128_CBC": "aes_cbc_128", "AES_256_GCM": "aes_gcm_256", "AES_128_GCM": "aes_gcm_128"}
ESP_ENC = {"AES_256_CBC": "esp-256-aes", "AES_192_CBC": "esp-192-aes", "AES_128_CBC": "esp-aes", "AES_256_GCM": "esp-gcm 256", "AES_128_GCM": "esp-gcm"}
ESP_HMAC = {"SHA256": "esp-sha256-hmac", "SHA384": "esp-sha384-hmac", "SHA512": "esp-sha512-hmac", "SHA1": "esp-sha-hmac", "MD5": "esp-md5-hmac"}

def parts(cidr):
    i = ipaddress.IPv4Interface(cidr); return str(i.ip), str(i.network.netmask)

def norm(v): return str(v).upper().replace("-", "_")   # "IPsec-Tunnel" and "IPSEC_TUNNEL" -> IPSEC_TUNNEL

def far_end(ep):
    """The VPN tunnel this endpoint terminates and its other endpoint (A<->Z)."""
    for t in ep["endpoint_a_vpn_tunnels"]: return t, t["endpoint_z"]
    for t in ep["endpoint_z_vpn_tunnels"]: return t, t["endpoint_a"]
    return None, None

def tunnel_model(i, ip, mask):
    """Native NAC tunnel interface (iosxe_interface_tunnel) - destroyed cleanly when a spoke is removed."""
    ep = i["vpn_tunnel_endpoints_tunnel"]; tun, peer = far_end(ep); ios = ep["vpn_profile"]["extra_options"]["ios"]
    assert norm(tun["encapsulation"]) == "IPSEC_TUNNEL", f"{i['name']}: only IPsec-Tunnel encapsulation is rendered natively"
    return {"name": i["name"][6:], "description": i["description"], "ipv4": {"address": ip, "address_mask": mask}, "ip_mtu": 1400,
            "tunnel_source": ep["source_interface"]["name"], "tunnel_destination_ipv4": peer["source_ipaddress"]["address"].split("/")[0],
            "tunnel_mode_ipsec_ipv4": True, "tunnel_protection_ipsec_profile": ios["ipsec_profile"]}

def mss_cli(i):   # the module has no ip_tcp_adjust_mss attribute for tunnels: one raw line on top of the native interface
    return f"interface {i['name']}\n ip tcp adjust-mss 1360\n"

def crypto_model(prof):
    """NAC crypto: block from a VPN profile (one Phase 1 and one Phase 2 policy)."""
    ios, p1, p2 = prof["extra_options"]["ios"], prof["vpn_phase1_policies"][0], prof["vpn_phase2_policies"][0]
    assert norm(p1["ike_version"]) == "IKEV2" and norm(p1["authentication_method"]) == "PSK", "renderer supports IKEv2 + PSK only"
    return {"ikev2": {"proposals": [{"name": ios["ikev2_proposal"], "encryption": [IKE_ENC[norm(e)] for e in p1["encryption_algorithm"]],
                                     "integrity": [x.lower() for x in p1["integrity_algorithm"]], "group": list(p1["dh_group"])}],
                      "policies": [{"name": ios["ikev2_policy"], "proposals": [ios["ikev2_proposal"]]}],
                      "keyrings": [{"name": ios["ikev2_keyring"], "peers": [{"name": ios["keyring_peer"], "ipv4_address": "0.0.0.0", "ipv4_mask": "0.0.0.0", "pre_shared_key": "${vpn_psk}"}]}],
                      "profiles": [{"name": ios["ikev2_profile"], "match_identity_remote_ipv4_addresses": [{"address": "0.0.0.0"}],   # no mask: IOS drops "0.0.0.0" on reload, which would read back as drift
                                    "authentication_local_pre_share": True, "authentication_remote_pre_share": True, "keyring_local": ios["ikev2_keyring"],
                                    **({"dpd_interval": prof["keepalive_interval"], "dpd_retry": prof["keepalive_retries"], "dpd_query": "on-demand"} if prof["keepalive_enabled"] else {})}]},
            "ipsec_transform_sets": [{"name": ios["transform_set"], "esp": ESP_ENC[norm(p2["encryption_algorithm"][0])], "esp_hmac": ESP_HMAC[norm(p2["integrity_algorithm"][0])]}],
            "ipsec_profiles": [{"name": ios["ipsec_profile"], "set_transform_set": [ios["transform_set"]], "set_ikev2_profile": ios["ikev2_profile"]}]}

def render(dev):
    name, ctx = dev["name"], dev["config_context"] or {}
    ethernets, loopbacks, tunnels, networks, templates, router_id, profiles, templates_vpn = [], [], [], [], [], None, {}, []
    for i in dev["interfaces"]:
        ips = i["ip_addresses"]
        n = i["name"]
        if n.startswith("GigabitEthernet") and n != "GigabitEthernet1" and not i["enabled"]:
            ethernets.append({"type": "GigabitEthernet", "id": n[15:], "shutdown": True})   # unwired spoke-facing port: NAC owns the shut state
            continue
        if not ips: continue
        ip, mask = parts(ips[0]["address"]); parent = ips[0]["parent"] or {}
        if any(t["name"] == "bgp:advertise" for t in parent.get("tags", [])):
            pfx = ipaddress.IPv4Network(parent["prefix"])
            classful = pfx.prefixlen == 24 and 192 <= int(str(pfx.network_address).split(".")[0]) <= 223
            networks.append({"network": str(pfx.network_address)} if classful else {"network": str(pfx.network_address), "mask": str(pfx.netmask)})
        if n.startswith("GigabitEthernet") and n != "GigabitEthernet1":
            ethernets.append({"type": "GigabitEthernet", "id": n[15:], "description": i["description"], "shutdown": not i["enabled"], "cdp": True,
                              "ipv4": {"address": ip, "address_mask": mask}})
        elif n.startswith("Loopback"):
            loopbacks.append({"id": int(n[8:]), "description": i["description"], "ipv4": {"address": ip, "address_mask": mask}})
            if n == "Loopback0": router_id = ip
        elif n.startswith("Tunnel") and i["vpn_tunnel_endpoints_tunnel"]:
            tunnels.append(tunnel_model(i, ip, mask))
            templates.append({"name": f"mss_{name}_{n.lower()}", "type": "cli", "content": mss_cli(i)})
            profiles[i["vpn_tunnel_endpoints_tunnel"]["vpn_profile"]["name"]] = i["vpn_tunnel_endpoints_tunnel"]["vpn_profile"]
            templates_vpn.append(far_end(i["vpn_tunnel_endpoints_tunnel"])[0] or {})
    assert len(profiles) <= 1, f"{name}: one VPN profile per router is supported, got {list(profiles)}"
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
    group = next((t["vpn"]["extra_attributes"].get("nac_device_group") for t in templates_vpn if t.get("vpn")), "IPSEC_VPN")
    return {"name": name, "host": dev["primary_ip4"]["address"].split("/")[0], "protocol": "restconf", "device_groups": [group],
            "templates": [t["name"] for t in templates], "_templates": templates,
            "variables": {"router_id": router_id, "bgp_asn": ri["autonomous_system"]["asn"]},
            "configuration": {"system": {"hostname": name, "ip_domain_name": ctx.get("domain_name")},
                              **({"crypto": crypto_model(next(iter(profiles.values())))} if profiles else {}),
                              "interfaces": {"ethernets": sorted(ethernets, key=lambda e: e["id"]), "loopbacks": loopbacks, "tunnels": sorted(tunnels, key=lambda t: int(t["name"]))},
                              "routing": {"bgp": bgp}}}

rendered = [render(d) for d in devices]
templates = [t for d in rendered for t in d.pop("_templates")]
out = ("---\n# GENERATED from Nautobot by nautobot/render_nac.py — do not edit by hand.\n"
       f"# Source of truth: {a.url} (location {intent_mod.load()['site']['name']}, saved GraphQL query nac-c8000v-ipsec-model)\n"
       + yaml.safe_dump({"iosxe": {"templates": templates, "devices": rendered}}, sort_keys=False, width=120))
# the pre-shared key is the one secret: it comes from lab-intent.json, not Nautobot, into the NAC device group
groups_out = ("---\n# GENERATED by nautobot/render_nac.py — the PSK comes from lab-intent.json (never stored in Nautobot).\n"
              + yaml.safe_dump({"iosxe": {"device_groups": [{"name": rendered[0]["device_groups"][0], "devices": [d["name"] for d in rendered],
                                                             "variables": {"vpn_psk": intent_mod.load()["psk"]}}]}}, sort_keys=False))
groups_path = Path(a.out).with_name("device_groups.nac.yaml")
if a.check:
    rc = 0
    for path, new in ((Path(a.out), out), (groups_path, groups_out)):
        cur = path.read_text() if path.exists() else ""
        if cur != new:
            import difflib; sys.stdout.writelines(difflib.unified_diff(cur.splitlines(True), new.splitlines(True), f"on-disk {path.name}", "nautobot")); rc = 1
    print("nac/data matches Nautobot + intent" if rc == 0 else "nac/data differs"); sys.exit(rc)
else:
    Path(a.out).write_text(out); groups_path.write_text(groups_out); print(f"wrote {a.out}: {len(devices)} devices (+ {groups_path.name})")
