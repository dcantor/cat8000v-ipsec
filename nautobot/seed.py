#!/usr/bin/env python3
"""Seed the shared Nautobot with the C8000v IPsec VTI + eBGP lab intent (idempotent).

From ../lab.conf: roles hub/spoke, point-to-point WAN links (cables between GiN interfaces with
/30 addressing), VTI tunnels TunnelN (custom fields tunnel_mode=ipsec-ipv4 / tunnel_ipsec_profile,
relationships tunnel_source -> GiN and tunnel_peer <-> the far tunnel), loopbacks (router-id, site
LAN), config context "c8000v-ipsec" (crypto suite, OOB), one AS per site and eBGP peerings over the
tunnels (nautobot-bgp-models), bgp:advertise tags, saved GraphQL query nac-c8000v-ipsec-model.
"""
import argparse, ipaddress, os, re, subprocess, sys
from pathlib import Path
import pynautobot

LAB = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument("--url", default=os.environ.get("NAUTOBOT_URL", "http://10.0.0.10:8080"))
p.add_argument("--token", default=os.environ.get("NAUTOBOT_TOKEN"))
a = p.parse_args()
nb = pynautobot.api(a.url, token=a.token)
H = {"Authorization": f"Token {a.token}", "Accept": "application/json"}
SITE = "c8000v-ipsec-lab"

def lab_conf(*names):
    out = subprocess.run(["bash", "-c", f"source {LAB}/lab.conf; declare -p {' '.join(names)}"], capture_output=True, text=True, check=True).stdout
    return {n: dict(re.findall(r'\[(\w+)\]="([^"]*)"', re.search(rf"declare -[aA] {n}=\((.*?)\)\n", out, re.S).group(1))) for n in names}
C = lab_conf("ROLE", "MGMT_IP", "BGP_AS", "LAN", "LINKS", "TUNNELS", "NODE_IDX")
ROUTERS = sorted(C["ROLE"]); HUB = next(r for r in ROUTERS if C["ROLE"][r] == "hub")
RID = {r: f"10.255.1.{C['NODE_IDX'][r]}" for r in ROUTERS}
LAN_IP = {r: str(ipaddress.IPv4Network(C["LAN"][r])[1]) for r in ROUTERS}
LINKS = [l.split() for l in C["LINKS"].values()]       # [a:port, b:port, prefix]
TUNNELS = [t.split() for t in C["TUNNELS"].values()]   # [id, spoke, prefix]
WIRED = {}                                              # (router, port) -> "peer GiN"
for a_end, b_end, _ in LINKS:
    (an, ap), (bn, bp) = a_end.split(":"), b_end.split(":"); WIRED[(an, int(ap))] = f"{bn} Gi{bp}"; WIRED[(bn, int(bp))] = f"{an} Gi{ap}"
OUI = subprocess.run(["bash", "-c", f"source {LAB}/lab.conf; echo $MAC_OUI"], capture_output=True, text=True).stdout.strip() or "52:54:00:c7"

created = []
def get_or_create(ep, lookup, **d):
    o = ep.get(**lookup)
    if o is None: o = ep.create(**lookup, **d); created.append(f"{ep.name}:{list(lookup.values())[0]}")
    return o
def ensure(obj, **fields):
    ch = {k: v for k, v in fields.items() if str(getattr(getattr(obj, k, None), "id", getattr(obj, k, None))) != str(v)}
    if ch: obj.update(ch)
    return obj

active = nb.extras.statuses.get(name="Active"); connected = nb.extras.statuses.get(name="Connected")
site = nb.dcim.locations.get(name=SITE) or sys.exit("run onboard.py first")
ns = nb.ipam.namespaces.get(name="Global"); plat = nb.dcim.platforms.get(name="cisco_xe")
sg = nb.extras.secrets_groups.get(name="lab-devices"); mgmt_vrf = nb.ipam.vrfs.get(name="Mgmt-vrf", namespace=ns.id)
roles = {"hub": get_or_create(nb.extras.roles, {"name": "vpn-hub"}, color="e91e63", content_types=["dcim.device"]),
         "spoke": get_or_create(nb.extras.roles, {"name": "vpn-spoke"}, color="f48fb1", content_types=["dcim.device"])}
prole = {n: get_or_create(nb.extras.roles, {"name": n}, color=c, content_types=["ipam.prefix"])
         for n, c in (("oob-management", "9e9e9e"), ("wan-p2p", "607d8b"), ("vpn-tunnel", "3f51b5"), ("site-lan", "4caf50"), ("loopback", "795548"))}
tag_adv = get_or_create(nb.extras.tags, {"name": "bgp:advertise"}, color="ff5722", content_types=["ipam.prefix"])

# tunnel model: the custom fields/relationships from the DMVPN lab (created there) + tunnel_peer
cf = {c.key: c for c in nb.extras.custom_fields.all()}
for key, label, ctype, extra in (("tunnel_mode", "Tunnel mode", "select", {"grouping": "Tunnel"}),
                                 ("tunnel_key", "Tunnel key", "integer", {"grouping": "Tunnel"}),
                                 ("tunnel_ipsec_profile", "Tunnel IPsec profile", "text", {"grouping": "Tunnel"})):
    if key not in cf:
        cf[key] = nb.extras.custom_fields.create(key=key, label=label, type=ctype, content_types=["dcim.interface"], **extra); created.append(f"custom-field:{key}")
have = {c.value for c in nb.extras.custom_field_choices.filter(custom_field=cf["tunnel_mode"].id)}
for i, v in enumerate(["gre", "gre-multipoint", "ipsec-ipv4"]):
    if v not in have: nb.extras.custom_field_choices.create(custom_field=cf["tunnel_mode"].id, value=v, weight=100 + 10 * i)
rel = {x.key: x for x in nb.extras.relationships.all()}
for key, label, rtype, sl, dl in (("tunnel_source", "Tunnel source interface", "one-to-many", "tunnels sourced here", "tunnel source"),
                                  ("tunnel_peer", "Tunnel peer (point-to-point)", "symmetric-one-to-one", "tunnel peer", "tunnel peer")):
    if key not in rel:
        rel[key] = nb.extras.relationships.create(key=key, label=label, type=rtype, source_type="dcim.interface", destination_type="dcim.interface",
                                                  source_label=sl, destination_label=dl); created.append(f"relationship:{key}")
def ensure_assoc(key, src, dst):
    ep = nb.extras.relationship_associations
    if not [x for x in ep.filter(destination_id=dst.id) + ep.filter(source_id=dst.id) if str(getattr(x.relationship, "id", x.relationship)) == rel[key].id]:
        ep.create(relationship=rel[key].id, source_type="dcim.interface", source_id=src.id, destination_type="dcim.interface", destination_id=dst.id)
        created.append(f"{key}: {src.device.name}/{src.name} <-> {dst.device.name}/{dst.name}")

CTX = {"crypto": {"ikev2_proposal": {"name": "VPN-PROP", "encryption": "aes-cbc-256", "integrity": "sha256", "group": 14},
                  "ikev2_policy": {"name": "VPN-POL"},
                  "ikev2_keyring": {"name": "VPN-KEYRING", "peer": "ANY", "peer_address": "0.0.0.0", "peer_mask": "0.0.0.0"},
                  "ikev2_profile": {"name": "VPN-IKEV2", "dpd_interval": 30, "dpd_retry": 5},
                  "ipsec_transform_set": {"name": "VPN-TS", "esp": "esp-256-aes", "esp_hmac": "esp-sha256-hmac"},
                  "ipsec_profile": {"name": "VPN-IPSEC"}},
       "oob": {"vrf": "Mgmt-vrf", "gateway": "10.2.0.1", "acl": "MGMT-ACCESS", "prefix": "10.2.0.0/24"},
       "domain_name": "lab.local"}
cc = nb.extras.config_contexts.get(name="c8000v-ipsec")
if cc is None: nb.extras.config_contexts.create(name="c8000v-ipsec", weight=1000, data=CTX, locations=[site.id]); created.append("config-context:c8000v-ipsec")
elif cc.data != CTX: cc.update({"data": CTX})

def ensure_prefix(cidr, role, desc="", ptype="network"):
    net = str(ipaddress.IPv4Network(cidr, strict=False)); pf = nb.ipam.prefixes.get(prefix=net, namespace=ns.id)
    if pf is None: pf = nb.ipam.prefixes.create(prefix=net, namespace=ns.id, status=active.id, type=ptype); created.append(f"prefix:{net}")
    ensure(pf, role=role.id, description=desc, status=active.id, type=ptype); return pf
def tag(pf):
    if tag_adv.id not in [t.id for t in pf.tags]: pf.update({"tags": [t.id for t in pf.tags] + [tag_adv.id]}); created.append(f"tag bgp:advertise on {pf.prefix}")
def ensure_iface(dev, name, itype, desc="", mgmt_only=False, vrf=None, enabled=True, mac=None):
    itf = nb.dcim.interfaces.get(device=dev.id, name=name)
    if itf is None: itf = nb.dcim.interfaces.create(device=dev.id, name=name, type=itype, status=active.id); created.append(f"interface:{dev.name}/{name}")
    ensure(itf, type=itype, description=desc, mgmt_only=mgmt_only, enabled=enabled, status=active.id, vrf=vrf, **({"mac_address": mac} if mac else {})); return itf
def ensure_ip(itf, cidr, primary_of=None):
    ip = nb.ipam.ip_addresses.get(address=cidr, namespace=ns.id) or nb.ipam.ip_addresses.get(address=cidr.split("/")[0], namespace=ns.id)
    if ip is None: ip = nb.ipam.ip_addresses.create(address=cidr, namespace=ns.id, status=active.id); created.append(f"ip:{cidr}")
    if not nb.ipam.ip_address_to_interface.get(ip_address=ip.id, interface=itf.id): nb.ipam.ip_address_to_interface.create(ip_address=ip.id, interface=itf.id)
    if primary_of is not None: ensure(primary_of, primary_ip4=ip.id)
    return ip
def ensure_cable(x, y):
    if x.cable or y.cable: return
    nb.dcim.cables.create(termination_a_type="dcim.interface", termination_a_id=x.id, termination_b_type="dcim.interface", termination_b_id=y.id, status=connected.id)
    created.append(f"cable:{x.device.name}:{x.name}-{y.device.name}:{y.name}")

ensure_prefix("10.2.0.0/24", prole["oob-management"], "cat8000v-ipsec OOB management (host = .1, NMS = .10)")
ensure_prefix("10.255.1.0/24", prole["loopback"], "router-id loopbacks", ptype="container")
devs, gi, tun = {}, {}, {}
for r in ROUTERS:
    dev = nb.dcim.devices.get(name=r) or sys.exit(f"{r} not onboarded")
    ensure(dev, role=roles[C["ROLE"][r]].id, secrets_group=sg.id, platform=plat.id, status=active.id)
    if nb.ipam.vrf_device_assignments.get(vrf=mgmt_vrf.id, device=dev.id) is None:
        nb.ipam.vrf_device_assignments.create(vrf=mgmt_vrf.id, device=dev.id); created.append(f"vrf-device:{r}")
    idx = int(C["NODE_IDX"][r])
    g1 = ensure_iface(dev, "GigabitEthernet1", "1000base-t", "OOB management (Mgmt-vrf)", mgmt_only=True, vrf=mgmt_vrf.id, mac=f"{OUI}:0{idx}:01")
    ensure_ip(g1, f"{C['MGMT_IP'][r]}/24", primary_of=dev)
    for port in (2, 3):  # wired ports get description/enabled from the LINKS loop below; set them here too so one update suffices
        wired = WIRED.get((r, port))
        gi[(r, port)] = ensure_iface(dev, f"GigabitEthernet{port}", "1000base-t", f"WAN to {wired}" if wired else "unwired", enabled=bool(wired), mac=f"{OUI}:0{idx}:0{port}")
    lo0 = ensure_iface(dev, "Loopback0", "virtual", "Router ID"); tag(ensure_prefix(f"{RID[r]}/32", prole["loopback"], f"{r} router-id")); ensure_ip(lo0, f"{RID[r]}/32")
    lo10 = ensure_iface(dev, "Loopback10", "virtual", "site LAN"); tag(ensure_prefix(C["LAN"][r], prole["site-lan"], f"{r} site LAN")); ensure_ip(lo10, f"{LAN_IP[r]}/24")
    devs[r] = dev
# WAN point-to-point links: addresses, cables
for a_end, b_end, pfx in LINKS:
    (an, ap), (bn, bp) = a_end.split(":"), b_end.split(":"); hosts = list(ipaddress.IPv4Network(pfx).hosts())
    ensure_prefix(pfx, prole["wan-p2p"], f"WAN link {an} Gi{ap} - {bn} Gi{bp}")
    ia, ib = gi[(an, int(ap))], gi[(bn, int(bp))]
    ensure_ip(ia, f"{hosts[0]}/30"); ensure_ip(ib, f"{hosts[1]}/30"); ensure_cable(ia, ib)
# VTI tunnels: hub TunnelN <-> spoke TunnelN over the link between them
def wan_iface(r, other):
    for a_end, b_end, _ in LINKS:
        (an, ap), (bn, bp) = a_end.split(":"), b_end.split(":")
        if {an, bn} == {r, other}: return gi[(r, int(ap if an == r else bp))]
tun_ip = {}
for tid, spoke, pfx in TUNNELS:
    hosts = list(ipaddress.IPv4Network(pfx).hosts()); ensure_prefix(pfx, prole["vpn-tunnel"], f"IPsec VTI Tunnel{tid} hub - {spoke}")
    ends = {}
    for r, ip in ((HUB, hosts[0]), (spoke, hosts[1])):
        other = spoke if r == HUB else HUB
        t = ensure_iface(devs[r], f"Tunnel{tid}", "virtual", f"IPsec VTI to {other}")
        want = {"tunnel_mode": "ipsec-ipv4", "tunnel_ipsec_profile": CTX["crypto"]["ipsec_profile"]["name"]}
        if {k: (t.custom_fields or {}).get(k) for k in want} != want: t.update({"custom_fields": want}); created.append(f"tunnel custom fields on {r}/Tunnel{tid}")
        tun_ip[(r, tid)] = ensure_ip(t, f"{ip}/30"); ensure_assoc("tunnel_source", wan_iface(r, other), t); ends[r] = t
    ensure_assoc("tunnel_peer", ends[HUB], ends[spoke])

# eBGP: one AS per site, hub <-> spoke peering over each tunnel
bgp = nb.plugins.bgp
need = [ct for ct in ("nautobot_bgp_models.autonomoussystem", "nautobot_bgp_models.bgproutinginstance", "nautobot_bgp_models.peering") if ct not in active.content_types]
if need: active.update({"content_types": list(active.content_types) + need})
asn = {r: get_or_create(bgp.autonomous_systems, {"asn": int(C["BGP_AS"][r])}, status=active.id, description=f"{r} site AS (eBGP over IPsec VTI)") for r in ROUTERS}
ri = {}
for r in ROUTERS:
    inst = bgp.routing_instances.get(device=devs[r].id)
    if inst is None:
        inst = bgp.routing_instances.create(device=devs[r].id, autonomous_system=asn[r].id, router_id=nb.ipam.ip_addresses.get(address=f"{RID[r]}/32", namespace=ns.id).id,
                                            status=active.id, extra_attributes={"log_neighbor_changes": True}, description="site eBGP"); created.append(f"bgp-ri:{r}")
    ri[r] = inst
    if bgp.address_families.get(routing_instance=inst.id, afi_safi="ipv4_unicast", vrf__isnull=True) is None:
        bgp.address_families.create(routing_instance=inst.id, afi_safi="ipv4_unicast"); created.append(f"bgp-af:{r}")
for tid, spoke, _ in TUNNELS:
    existing = [e for e in bgp.peer_endpoints.filter(routing_instance=ri[spoke].id) if getattr(e.source_ip, "id", None) == tun_ip[(spoke, tid)].id]
    if existing: eps = {spoke: existing[0], HUB: existing[0].peer}
    else:
        peering = bgp.peerings.create(status=active.id); created.append(f"bgp-peering:{HUB}<->{spoke} (Tunnel{tid})")
        eps = {HUB: bgp.peer_endpoints.create(peering=peering.id, routing_instance=ri[HUB].id, source_ip=tun_ip[(HUB, tid)].id, autonomous_system=asn[HUB].id, description=f"eBGP {spoke} (Tunnel{tid})", enabled=True),
               spoke: bgp.peer_endpoints.create(peering=peering.id, routing_instance=ri[spoke].id, source_ip=tun_ip[(spoke, tid)].id, autonomous_system=asn[spoke].id, description=f"eBGP hub (Tunnel{tid})", enabled=True)}
    for r, ep in eps.items():
        if bgp.peer_endpoint_address_families.get(peer_endpoint=ep.id, afi_safi="ipv4_unicast") is None:
            bgp.peer_endpoint_address_families.create(peer_endpoint=ep.id, afi_safi="ipv4_unicast"); created.append(f"bgp-endpoint-af:{r}/Tunnel{tid}")

QUERY = (Path(__file__).resolve().parent / "nac-c8000v-ipsec-model.graphql").read_text()
gq = nb.extras.graphql_queries.get(name="nac-c8000v-ipsec-model")
if gq is None: nb.extras.graphql_queries.create(name="nac-c8000v-ipsec-model", query=QUERY); created.append("graphql-query:nac-c8000v-ipsec-model")
elif gq.query.strip() != QUERY.strip():
    nb.http_session.patch(f"{a.url}/api/extras/graphql-queries/{gq.id}/", json={"query": QUERY}, headers=H).raise_for_status(); created.append("graphql-query updated")
print(f"seed complete: {len(created)} objects created" + (":\n  " + "\n  ".join(created) if created else " (nothing new)"))
