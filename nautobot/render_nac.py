#!/usr/bin/env python3
"""Render nac/data/devices.nac.yaml for the C8000v IPsec VTI + eBGP lab from Nautobot.

Per router: management host, WAN GiN interfaces from the cabled links, loopbacks, VTI tunnels as native NAC tunnel
interfaces from the core VPN app (the TunnelN interface's VPN tunnel endpoint: source interface/address, the VPN
tunnel it terminates and the far endpoint's source address = tunnel destination), the IKEv2/IPsec suite from the endpoint's VPN
profile (Phase 1 / Phase 2 policies, Cisco object names in extra_options.ios), and eBGP from
nautobot-bgp-models (one AS per site). Only the PSK stays in device_groups.nac.yaml.  Usage: NAUTOBOT_TOKEN=... render_nac.py [--check]
"""
import argparse, ipaddress, os, re, sys
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
devices = sorted((d for d in data["data"]["devices"] if (d.get("role") or {}).get("name") != "vpn-firewall"), key=lambda d: d["name"])   # firewalls are VyOS: rendered by render_vyos.py
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

def source_iface(ep):
    """The tunnel source interface: the endpoint's source interface, else the interface that holds its source address
    (a headend behind a firewall sources every tunnel from the same WAN interface, so those endpoints carry only the address)."""
    if ep.get("source_interface"): return ep["source_interface"]["name"]
    return ep["source_ipaddress"]["interfaces"][0]["name"]

def tunnel_model(i, ip, mask):
    """Native NAC tunnel interface (iosxe_interface_tunnel) - destroyed cleanly when a spoke is removed."""
    ep = i["vpn_tunnel_endpoints_tunnel"]; tun, peer = far_end(ep); ios = ep["vpn_profile"]["extra_options"]["ios"]
    assert norm(tun["encapsulation"]) == "IPSEC_TUNNEL", f"{i['name']}: only IPsec-Tunnel encapsulation is rendered natively"
    return {"name": i["name"][6:], "description": i["description"], "ipv4": {"address": ip, "address_mask": mask}, "ip_mtu": 1400,
            "tunnel_source": source_iface(ep), "tunnel_destination_ipv4": peer["source_ipaddress"]["address"].split("/")[0],
            "tunnel_mode_ipsec_ipv4": True, "tunnel_protection_ipsec_profile": ios["ipsec_profile"]}

def static_routes(dev):
    """Through a firewall the far end of a tunnel is not on a connected network: one static route per tunnel towards the
    far endpoint's source address, next hop = the address on the other side of this router's WAN link (the firewall)."""
    routes = {}
    for i in dev["interfaces"]:
        ep = i["vpn_tunnel_endpoints_tunnel"]
        if not ep: continue
        tun, far = far_end(ep)
        if not far: continue
        src_if = next((x for x in dev["interfaces"] if x["name"] == source_iface(ep)), None)
        if not src_if or not src_if.get("connected_interface") or not src_if["connected_interface"]["ip_addresses"]: continue
        peer_dev = src_if["connected_interface"]["device"]
        if (peer_dev.get("role") or {}).get("name") != "vpn-firewall": continue   # directly connected: no route needed
        via = src_if["connected_interface"]["ip_addresses"][0]["address"].split("/")[0]
        dst = ipaddress.IPv4Interface(far["source_ipaddress"]["address"])
        net = dst.network if (ep.get("role") or {}).get("name", "").lower() == "hub" else ipaddress.IPv4Network(f"{dst.ip}/32")   # headend: the spoke's link /30; spoke: the headend's WAN /32
        routes[str(net)] = {"prefix": str(net.network_address), "mask": str(net.netmask), "next_hops": [{"ip": via, "name": f"via-{peer_dev['name']}"}]}
    return [routes[k] for k in sorted(routes, key=lambda k: ipaddress.IPv4Network(k))]

def mss_cli(i):   # the module has no ip_tcp_adjust_mss attribute for tunnels: one raw line on top of the native interface
    return f"interface {i['name']}\n ip tcp adjust-mss 1360\n"

def psk_var(name): return "psk_" + re.sub(r"[^A-Za-z0-9]", "_", name)

def tunnel_far_ends(dev, prof_name=None):
    """(far endpoint, this endpoint) per tunnel of the device — optionally only the tunnels on one VPN profile."""
    out = []
    for i in dev["interfaces"]:
        ep = i["vpn_tunnel_endpoints_tunnel"]
        if not ep or (prof_name and ep["vpn_profile"]["name"] != prof_name): continue
        tun, far = far_end(ep)
        if far: out.append((far, ep))
    return sorted(out, key=lambda x: x[0]["source_ipaddress"]["address"])

def keyring_peers(dev, prof):
    """One keyring entry per far end of the tunnels on the PSK profile: a headend lists each PSK spoke (matched on the spoke's WAN
    address, that spoke's key); a spoke lists each headend with its own key. Keys are NAC variables rendered into device_groups.nac.yaml."""
    peers = []
    for far, ep in tunnel_far_ends(dev, prof["name"]):
        far_dev = far["device"]["name"]; is_hub = norm((ep.get("role") or {}).get("name", "")) == "HUB"
        peers.append({"name": far_dev, "ipv4_address": far["source_ipaddress"]["address"].split("/")[0], "ipv4_mask": "255.255.255.255",
                      "pre_shared_key": "${%s}" % psk_var(far_dev if is_hub else dev["name"])})
    return peers

def cert_auth(prof):
    """True when the profile's Phase 1 policy authenticates with certificates (RSA = rsa-sig against the lab CA) rather than PSK."""
    return norm(prof["vpn_phase1_policies"][0]["authentication_method"]) == "RSA"

def cert_auth_cli(prof):
    """The IKEv2 profile lines the iosxe provider cannot express (its profile resource knows only pre-share authentication): the
    certificate map the peers are matched on, rsa-sig both ways, the trustpoint — one raw CLI template on top of the native profile.
    The trustpoint itself and the certificates are enrolled by nautobot/pki.py before Terraform runs."""
    ios = prof["extra_options"]["ios"]
    return (f"crypto ikev2 profile {ios['ikev2_profile']}\n match certificate {ios['certificate_map']}\n identity local dn\n"
            f" authentication remote rsa-sig\n authentication local rsa-sig\n pki trustpoint {ios['trustpoint']}\n")

def crypto_model(profiles, dev):
    """NAC crypto: block from the VPN profiles this router's tunnels use (one per IKE authentication method; each has one Phase 1 and one
    Phase 2 policy, the proposal / policy / transform-set names are shared). PSK profile: a keyring with one entry per far end on it and a
    pre-share IKEv2 profile matching exactly those peers' WAN addresses; certificate profile: no keyring, an IKEv2 profile whose match
    (the certificate map) and rsa-sig lines come from cert_auth_cli — so a headend can serve PSK spokes and certificate spokes at once."""
    out = {"ikev2": {"proposals": [], "policies": [], "keyrings": [], "profiles": []}, "ipsec_transform_sets": [], "ipsec_profiles": []}
    seen = set()
    for prof in sorted(profiles.values(), key=lambda p: p["name"]):
        ios, p1, p2 = prof["extra_options"]["ios"], prof["vpn_phase1_policies"][0], prof["vpn_phase2_policies"][0]
        assert norm(p1["ike_version"]) == "IKEV2" and norm(p1["authentication_method"]) in ("PSK", "RSA"), "renderer supports IKEv2 with PSK or RSA (certificates) only"
        cert = cert_auth(prof)
        if ios["ikev2_proposal"] not in seen:
            out["ikev2"]["proposals"].append({"name": ios["ikev2_proposal"], "encryption": [IKE_ENC[norm(e)] for e in p1["encryption_algorithm"]], "integrity": [x.lower() for x in p1["integrity_algorithm"]], "group": list(p1["dh_group"])})
            out["ikev2"]["policies"].append({"name": ios["ikev2_policy"], "proposals": [ios["ikev2_proposal"]]}); seen.add(ios["ikev2_proposal"])
        if ios["transform_set"] not in seen:
            out["ipsec_transform_sets"].append({"name": ios["transform_set"], "esp": ESP_ENC[norm(p2["encryption_algorithm"][0])], "esp_hmac": ESP_HMAC[norm(p2["integrity_algorithm"][0])]}); seen.add(ios["transform_set"])
        dpd = {"dpd_interval": prof["keepalive_interval"], "dpd_retry": prof["keepalive_retries"], "dpd_query": "on-demand"} if prof["keepalive_enabled"] else {}
        if cert:   # no address match: the peers are matched on their certificate (cert_auth_cli), which a PSK peer never presents
            out["ikev2"]["profiles"].append({"name": ios["ikev2_profile"], **dpd})
        else:
            out["ikev2"]["keyrings"].append({"name": ios["ikev2_keyring"], "peers": keyring_peers(dev, prof)})
            out["ikev2"]["profiles"].append({"name": ios["ikev2_profile"], "match_identity_remote_ipv4_addresses": [{"address": p["ipv4_address"], "mask": "255.255.255.255"} for p in keyring_peers(dev, prof)],
                                             "authentication_local_pre_share": True, "authentication_remote_pre_share": True, "keyring_local": ios["ikev2_keyring"], **dpd})
        out["ipsec_profiles"].append({"name": ios["ipsec_profile"], "set_transform_set": [ios["transform_set"]], "set_ikev2_profile": ios["ikev2_profile"]})
    if not out["ikev2"]["keyrings"]: del out["ikev2"]["keyrings"]
    return out

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
    for p in sorted(profiles.values(), key=lambda p: p["name"]):
        if cert_auth(p): templates.append({"name": f"ikev2_cert_auth_{name}", "type": "cli", "content": cert_auth_cli(p)})
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
                              **({"crypto": crypto_model(profiles, dev)} if profiles else {}),
                              "interfaces": {"ethernets": sorted(ethernets, key=lambda e: e["id"]), "loopbacks": loopbacks, "tunnels": sorted(tunnels, key=lambda t: int(t["name"]))},
                              "routing": {"bgp": bgp, **({"static_routes": static_routes(dev)} if static_routes(dev) else {})}}}

rendered = [render(d) for d in devices]
templates = [t for d in rendered for t in d.pop("_templates")]
out = ("---\n# GENERATED from Nautobot by nautobot/render_nac.py — do not edit by hand.\n"
       f"# Source of truth: {a.url} (location {intent_mod.load()['site']['name']}, saved GraphQL query nac-c8000v-ipsec-model)\n"
       + yaml.safe_dump({"iosxe": {"templates": templates, "devices": rendered}}, sort_keys=False, width=120))
# the pre-shared keys are the one secret: one per spoke, from lab-intent.json (never in Nautobot), as NAC variables
I = intent_mod.load()
psk_spokes = [d for d in I["devices"] if d["role"] == "spoke" and intent_mod.spoke_auth(I, d["name"]) == "psk"]
groups_out = ("---\n# GENERATED by nautobot/render_nac.py — per-spoke pre-shared keys come from lab-intent.json (never stored in Nautobot);"
              " only spokes that authenticate with a key get one (the others use certificates from the lab CA).\n"
              + yaml.safe_dump({"iosxe": {"device_groups": [{"name": rendered[0]["device_groups"][0], "devices": [d["name"] for d in rendered],
                                                             **({"variables": {psk_var(d["name"]): d["psk"] for d in psk_spokes}} if psk_spokes else {})}]}}, sort_keys=False))
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
