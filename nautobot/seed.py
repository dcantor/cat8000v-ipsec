#!/usr/bin/env python3
"""Seed the shared Nautobot with the C8000v IPsec VTI + eBGP lab intent (idempotent).

Intent comes from lab-intent.json (nautobot/intent.py; generated from lab.conf, edited by the web app):
site metadata (description, site_code, contact), devices matched by management IP (hostname, role, AS,
router-id loopback, site LAN, comments), point-to-point WAN links (cables between GiN interfaces with /30
addressing), the VPN in Nautobot's core vpn app (Phase 1/2 policies, profile, VPN with change/owner
metadata, one VPNTunnel per spoke with hub/spoke endpoints: source GiN + address, TunnelN, protected
prefixes), config context (OOB, domain), one AS per site and eBGP peerings over the tunnels
(nautobot-bgp-models), bgp:advertise tags, saved GraphQL query nac-c8000v-ipsec-model.
Usage: NAUTOBOT_TOKEN=... seed.py [--intent file.json]
"""
import argparse, ipaddress, os, subprocess, sys
import hashlib
from pathlib import Path
import pynautobot, requests
sys.path.insert(0, str(Path(__file__).resolve().parent)); import intent as intent_mod   # noqa: E402

LAB = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument("--url", default=os.environ.get("NAUTOBOT_URL", "http://10.0.0.10:8080"))
p.add_argument("--token", default=os.environ.get("NAUTOBOT_TOKEN"))
p.add_argument("--intent", default=None)
a = p.parse_args()
I = intent_mod.load(a.intent)
problems = intent_mod.validate(I)
if problems: sys.exit("invalid intent:\n  " + "\n  ".join(problems))
nb = pynautobot.api(a.url, token=a.token)
H = {"Authorization": f"Token {a.token}", "Accept": "application/json"}
SITE = I["site"]["name"]
DEV = {d["name"]: d for d in I["devices"]}; ROUTERS = sorted(n for n, d in DEV.items() if d["role"] in ("hub", "spoke")); HUBS = sorted(n for n, d in DEV.items() if d["role"] == "hub")
FIREWALLS = sorted(n for n, d in DEV.items() if d["role"] == "firewall"); LAN_HOSTS = sorted(n for n, d in DEV.items() if d["role"] == "host")
NODES = intent_mod.nodes()                                # mgmt ip -> {node, idx, role} (VM facts)
LAN_IP = {n: str(ipaddress.IPv4Network(d["lan"])[1]) for n, d in DEV.items() if d["role"] in ("hub", "spoke")}   # .1 = the router's LAN port; .2 = its host
LINKS = I["links"]; TUNNELS = I["tunnels"]; PROF = I["profile"]
LAN_LINKS = [l for l in LINKS if intent_mod.is_lan_link(I, l)]; WAN_LINKS = [l for l in LINKS if not intent_mod.is_lan_link(I, l)]
def port_name(node, port): return f"eth{port}" if DEV[node]["role"] in ("firewall", "host") else f"GigabitEthernet{port}"
WIRED = {}                                              # (node, port) -> "peer <interface>"
for l in LINKS:
    WIRED[(l["a"], l["a_port"])] = f"{l['b']} {port_name(l['b'], l['b_port'])}"; WIRED[(l["b"], l["b_port"])] = f"{l['a']} {port_name(l['a'], l['a_port'])}"
SC = intent_mod.scalars("MAC_OUI", "HUB_PORTS", "SPOKE_PORTS", "FW_PORTS"); OUI = SC["MAC_OUI"] or "52:54:00:c7"
PORTS = {"hub": range(2, 2 + int(SC["HUB_PORTS"] or 2)), "spoke": range(2, 2 + int(SC["SPOKE_PORTS"] or 2)), "firewall": range(1, 1 + int(SC["FW_PORTS"] or 8)), "host": range(1, 2)}
LAN_PORT = {n: intent_mod.lan_port(I, n) for n in ROUTERS}   # the router's last port is its site LAN (.1 of the LAN /24; the host behind it .2)

created = []
def gql(query):
    r = requests.post(f"{a.url}/api/graphql/", json={"query": query}, headers=H, timeout=60); r.raise_for_status(); return r.json()["data"]
def get_or_create(ep, lookup, **d):
    o = ep.get(**lookup)
    if o is None: o = ep.create(**lookup, **d); created.append(f"{ep.name}:{list(lookup.values())[0]}")
    return o
def current(v):
    """Comparable form of a pynautobot attribute: related object -> id, choice -> value, else the value itself."""
    if hasattr(v, "id"): return str(v.id)
    if hasattr(v, "value") and hasattr(v, "label"): return v.value
    if hasattr(v, "serialize"): return {k: current(getattr(v, k)) for k in v.serialize()}   # JSON fields come back as (nested) Records
    return v
def ensure(obj, **fields):
    ch = {}
    for k, v in fields.items():
        c = current(getattr(obj, k, None))
        same = c == v if isinstance(v, (dict, list)) else (str(c).lower() == str(v).lower() if k == "mac_address" else str(c) == str(v))
        if not same: ch[k] = v
    if ch: obj.update(ch); created.append(f"updated {getattr(obj, 'name', obj)}: {', '.join(ch)}")
    return obj
def ensure_cf(obj, **fields):
    cur = obj.custom_fields or {}
    if any(cur.get(k) != v for k, v in fields.items()): obj.update({"custom_fields": {**cur, **fields}}); created.append(f"custom fields on {getattr(obj, 'name', obj)}")

active = nb.extras.statuses.get(name="Active"); connected = nb.extras.statuses.get(name="Connected")
site = nb.dcim.locations.get(name=SITE) or sys.exit("run onboard.py first")
ns = nb.ipam.namespaces.get(name="Global"); plat = nb.dcim.platforms.get(name="cisco_xe")
sg = nb.extras.secrets_groups.get(name="lab-devices"); mgmt_vrf = nb.ipam.vrfs.get(name="Mgmt-vrf", namespace=ns.id)
roles = {"hub": get_or_create(nb.extras.roles, {"name": "vpn-hub"}, color="e91e63", content_types=["dcim.device"]),
         "spoke": get_or_create(nb.extras.roles, {"name": "vpn-spoke"}, color="f48fb1", content_types=["dcim.device"]),
         "firewall": get_or_create(nb.extras.roles, {"name": "vpn-firewall"}, color="ff9800", content_types=["dcim.device"])}
prole = {n: get_or_create(nb.extras.roles, {"name": n}, color=c, content_types=["ipam.prefix"])
         for n, c in (("oob-management", "9e9e9e"), ("wan-p2p", "607d8b"), ("vpn-tunnel", "3f51b5"), ("site-lan", "4caf50"), ("loopback", "795548"))}
tag_adv = get_or_create(nb.extras.tags, {"name": "bgp:advertise"}, color="ff5722", content_types=["ipam.prefix"])

# site / device metadata as custom fields (site_code + contact on locations, contact on devices)
cf = {c.key: c for c in nb.extras.custom_fields.all()}
for key, label, ctypes in (("site_code", "Site code", ["dcim.location"]), ("contact", "Contact", ["dcim.location", "dcim.device"])):
    if key not in cf: cf[key] = nb.extras.custom_fields.create(key=key, label=label, type="text", content_types=ctypes, grouping="Metadata"); created.append(f"custom-field:{key}")
if "vpn_tunnel_capacity" not in cf:   # the headend constraint: how many tunnels a hub may terminate (inventory page + deploy-time check)
    cf["vpn_tunnel_capacity"] = nb.extras.custom_fields.create(key="vpn_tunnel_capacity", label="VPN tunnel capacity", type="integer", content_types=["dcim.device"],
                                                               grouping="VPN", description="Maximum IPsec tunnels this headend may terminate"); created.append("custom-field:vpn_tunnel_capacity")
def nudge_cf(field, desc):
    """A second, real save of a custom field created moments earlier: Nautobot's per-content-type field cache ignores a brand-new field
    (values written to it are dropped silently) until the field is saved again — and pynautobot sends nothing when nothing changed,
    so the description goes out changed and comes back."""
    field.update({"description": desc + " "}); field.update({"description": desc})
# the pre-shared key never enters Nautobot; what does is its fingerprint (sha256, first 12 hex) and the rotation date on every
# tunnel of the spoke, so the model says which key generation a tunnel runs and the portal's Rotate PSK action leaves a trace
for key, label, typ, desc in (("psk_fingerprint", "PSK fingerprint", "text", "sha256 of the spoke's pre-shared key, first 12 hex digits (the key itself lives in lab-intent.json / NaC variables)"),
                              ("psk_rotated", "PSK rotated", "text", "when the spoke's pre-shared key was last generated or rotated (ISO date-time)")):
    if key not in cf:
        cf[key] = nb.extras.custom_fields.create(key=key, label=label, type=typ, content_types=["vpn.vpntunnel"], grouping="VPN", description=desc); created.append(f"custom-field:{key}")
        nudge_cf(cf[key], desc)
# the router certificates (IKE authentication "certificate"): what each router presents, written by nautobot/pki.py after an enrolment and
# never touched by the seed — the model says which certificate a router runs, when it expires and when it was last renewed
for key, label, typ, desc in (("cert_serial", "Certificate serial", "text", "serial (hex) of the router certificate the lab CA issued (pki/index.json), as IOS-XE shows it"),
                              ("cert_subject", "Certificate subject", "text", "CN of the router certificate"),
                              ("cert_expires", "Certificate expires", "date", "end of the router certificate's validity"),
                              ("cert_renewed", "Certificate renewed", "date", "when the router last enrolled (pki.py, or the portal's Renew certificate action)")):
    if key not in cf:
        cf[key] = nb.extras.custom_fields.create(key=key, label=label, type=typ, content_types=["dcim.device"], grouping="VPN", description=desc); created.append(f"custom-field:{key}")
        nudge_cf(cf[key], desc)
CAPACITY = int((I.get("capacity") or {}).get("tunnels_per_headend") or 50)
if "firewall_bandwidth_mbps" not in cf:   # the second headend constraint: the bandwidth of the firewall in front of it
    cf["firewall_bandwidth_mbps"] = nb.extras.custom_fields.create(key="firewall_bandwidth_mbps", label="Firewall bandwidth (Mbps)", type="integer", content_types=["dcim.device"],
                                                                   grouping="VPN", description="Throughput the firewall can carry; every tunnel commits bandwidth_per_tunnel_mbps of it"); created.append("custom-field:firewall_bandwidth_mbps")
ensure(site, description=I["site"]["description"]); ensure_cf(site, site_code=I["site"]["site_code"], contact=I["site"]["contact"])

# site hierarchy: lab site -> Region -> Branch (one location per branch/HQ; site_code + contact live on the branch)
lt_site = nb.dcim.location_types.get(name="Site")
lt_region = get_or_create(nb.dcim.location_types, {"name": "Region"}, parent=lt_site.id, content_types=["dcim.device", "ipam.prefix"], description="ordered geographically (lab-intent.json regions)")
lt_branch = get_or_create(nb.dcim.location_types, {"name": "Branch"}, parent=lt_region.id, content_types=["dcim.device", "ipam.prefix"], description="one location per branch office / headend site")
regions, branches = {}, {}
for i, name in enumerate(I["regions"]):
    regions[name] = get_or_create(nb.dcim.locations, {"name": name}, location_type=lt_region.id, parent=site.id, status=active.id)
    ensure(regions[name], parent=site.id, description=f"region #{i + 1} of {len(I['regions'])}")
for d in sorted(I["devices"], key=lambda x: x["role"] in ("firewall", "host")):   # routers first: a firewall / a LAN host shares (and never re-describes) its router's site
    br = branches.get(d["site"]) or get_or_create(nb.dcim.locations, {"name": d["site"]}, location_type=lt_branch.id, parent=regions[d["region"]].id, status=active.id)
    if d["role"] not in ("firewall", "host"):
        where = f" — {d['city']}" if d.get("city") else ""   # the city and its coordinates place the site on the portal's map (Location latitude / longitude)
        ensure(br, parent=regions[d["region"]].id, description=f"{'headend site' if d['role'] == 'hub' else 'branch office'} of {d['name']}{where}",
               **({"latitude": f"{float(d['lat']):.6f}", "longitude": f"{float(d['lon']):.6f}"} if d.get("lat") is not None else {}))
        ensure_cf(br, site_code=d.get("site_code", ""), contact=d.get("contact", ""))
    branches[d["site"]] = br

# VPN model: Nautobot's core "vpn" app (3.2+). Phase 1 / Phase 2 policies -> profile -> VPN -> tunnels with
# hub/spoke endpoints (source interface + address, tunnel interface, protected prefixes). Cisco object names live
# in the profile's extra_options; the PSK stays out of Nautobot (NAC group variable vpn_psk).
need = [ct for ct in ("vpn.vpn", "vpn.vpntunnel") if ct not in active.content_types]
if need: active.update({"content_types": list(active.content_types) + need})
vrole = {n: get_or_create(nb.extras.roles, {"name": n}, color=c, content_types=["vpn.vpntunnelendpoint"]) for n, c in (("hub", "e91e63"), ("spoke", "f48fb1"))}
ike, ipsec, dpd = PROF["ike"], PROF["ipsec"], PROF["dpd"]
# IKE authentication is chosen per spoke (device ike_authentication, else the lab default profile.ike.authentication): one VPN profile per
# method in use — its Phase 1 policy carries the method (PSK, or RSA = rsa-sig with certificates from the lab CA), its extra_options.ios the
# Cisco names (the default method keeps the intent's names, the other one gets -PSK / -CERT). Every tunnel references its spoke's profile;
# a headend therefore renders one IKEv2 / IPsec profile per method its spokes use. Trustpoint / key pair / certificate-map names and the CA
# fingerprint travel in the certificate profile's ios names.
AUTH_DEFAULT = intent_mod.default_auth(I); AUTHS_USED = intent_mod.auths_in_use(I); CERT_ANY = "certificate" in AUTHS_USED
PKI = {**{"trustpoint": "LAB-CA", "keypair": "LAB-VPN", "certificate_map": "LAB-CERT-MAP"}, **{k: v for k, v in (PROF.get("pki") or {}).items() if k in ("trustpoint", "keypair", "certificate_map")}}
if CERT_ANY:
    sys.path.insert(0, str(LAB / "pki")); import ca as lab_ca   # noqa: E402
    lab_ca.init(); ca_info = lab_ca.cert_info(lab_ca.CA_CRT.read_text())   # the CA certificate is public; its fingerprint is pinned on every trustpoint
p2 = get_or_create(nb.vpn.vpn_phase_2_policies, {"name": PROF["ios"]["transform_set"]}, description="IPsec SA (from lab-intent.json)")
ensure(p2, encryption_algorithm=[ipsec["encryption"]], integrity_algorithm=[ipsec["integrity"]], lifetime=int(ipsec["lifetime"]),
       description=f"IPsec SA: ESP {ipsec['encryption']} / {ipsec['integrity']}-HMAC, tunnel mode")
PROFILES = {}   # auth -> VPN profile record
for auth in sorted(AUTHS_USED, key=lambda x: x != AUTH_DEFAULT):
    names = intent_mod.profile_names(I, auth); cert = auth == "certificate"; auth_nb = "RSA" if cert else "PSK"
    ios = {k: v for k, v in names.items() if k not in ("profile", "auth")}
    ios = {**ios, "trustpoint": PKI["trustpoint"], "rsakeypair": PKI["keypair"], "certificate_map": PKI["certificate_map"], "ca_fingerprint": ca_info["fingerprint"], "ca_subject": ca_info["subject"]} if cert else \
          {k: v for k, v in ios.items() if k not in ("trustpoint", "rsakeypair", "certificate_map", "ca_fingerprint", "ca_subject")}
    p1 = get_or_create(nb.vpn.vpn_phase_1_policies, {"name": ios["ikev2_profile"]}, description="IKEv2 SA (from lab-intent.json)")
    ensure(p1, ike_version="IKEv2", encryption_algorithm=[ike["encryption"]], integrity_algorithm=[ike["integrity"]], dh_group=[str(ike["dh_group"])],
           lifetime_seconds=int(ike["lifetime"]), authentication_method=auth_nb, description=f"IKEv2 SA: {ike['encryption']} / {ike['integrity']} / DH group {ike['dh_group']}, {auth_nb}")
    prof = get_or_create(nb.vpn.vpn_profiles, {"name": names["profile"]}, description=f"Static IPsec VTI, IKEv2 {auth_nb}")
    ensure(prof, keepalive_enabled=bool(dpd["enabled"]), keepalive_interval=int(dpd["interval"]), keepalive_retries=int(dpd["retries"]), nat_traversal=False,
           extra_options={"ios": ios}, description=f"Static IPsec VTI, IKEv2 {'certificates (rsa-sig, lab CA)' if cert else 'PSK'}" + (", DPD on-demand" if dpd["enabled"] else "") + ("" if auth == AUTH_DEFAULT else f" — for spokes that chose {auth} over the lab default"))
    # Nautobot 3.2.4 bug: POST to the profile<->policy assignment endpoints 500s ("unexpected keyword _custom_field_data")
    # and the profile serializer silently ignores vpn_phase1/2_policies on write, so these two rows go through the ORM
    # (nautobot-server nbshell inside the container on the NMS).
    have = gql('{ vpn_profiles(name: "%s") { vpn_phase1_policies { name } vpn_phase2_policies { name } } }' % prof.name)["vpn_profiles"][0]
    for key, pol in (("vpn_phase1_policies", p1), ("vpn_phase2_policies", p2)):
        if [x["name"] for x in have[key]] != [pol.name]:
            model = "VPNPhase1Policy" if key.endswith("1_policies") else "VPNPhase2Policy"
            subprocess.run(["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "lab@10.0.0.10",
                            "cd /opt/nautobot && sg docker -c 'docker compose exec -T nautobot nautobot-server nbshell --quiet'"],
                           input=f"from nautobot.vpn.models import VPNProfile, {model}\np = VPNProfile.objects.get(name={prof.name!r})\np.{key}.set([{model}.objects.get(name={pol.name!r})])\n",
                           text=True, check=True, capture_output=True); created.append(f"{prof.name} <- {pol.name} (via nbshell)")
    PROFILES[auth] = prof
prof = PROFILES[AUTH_DEFAULT]
def profile_of(spoke): return PROFILES[intent_mod.spoke_auth(I, spoke)]
vpn = nb.vpn.vpns.get(vpn_profile=prof.id) or get_or_create(nb.vpn.vpns, {"name": I["vpn"]["name"]}, service_type="ipsec", status=active.id, vpn_profile=prof.id)
ensure(vpn, name=I["vpn"]["name"], description=I["vpn"]["description"], service_type="ipsec", status=active.id, vpn_profile=prof.id,
       extra_attributes={"routing": "eBGP over the tunnel /30s", "nac_device_group": "IPSEC_VPN", "change_ticket": I["vpn"].get("change_ticket", ""), "owner": I["vpn"].get("owner", ""),
                         "bandwidth_per_tunnel_mbps": int((I.get("capacity") or {}).get("bandwidth_per_tunnel_mbps") or 0)})

# clean-up of the interface-based tunnel model this lab used before the core VPN app (custom fields, relationships)
def drop_legacy_tunnel_model(t):
    if any((t.custom_fields or {}).get(k) for k in ("tunnel_mode", "tunnel_key", "tunnel_ipsec_profile")):
        t.update({"custom_fields": {"tunnel_mode": None, "tunnel_key": None, "tunnel_ipsec_profile": None}}); created.append(f"cleared tunnel custom fields on {t.device.name}/{t.name}")
    ep = nb.extras.relationship_associations
    for x in ep.filter(destination_id=t.id) + ep.filter(source_id=t.id):
        if str(getattr(x.relationship, "key", "")) in ("tunnel_source", "tunnel_peer"): x.delete(); created.append(f"removed relationship {x.relationship.key} on {t.device.name}/{t.name}")

CTX = {"oob": I["oob"], "domain_name": I["domain_name"],
       # policy for the VyOS firewalls between a headend and its spokes: only what the tunnels need may cross
       # peers_only: IKE and ESP only between the modelled WAN addresses (the headend behind the firewall, the spokes cabled to it) — address groups
       # rendered from Nautobot's cables and addresses; ICMP stays open for the underlay reachability tests. log_accepts: the IKE, ESP and
       # ICMP accept rules log too — one line per new flow, since every later packet of a known flow is taken by the established rule
       # management.syslog: the firewalls ship their syslog (the kernel's firewall log included) to VictoriaLogs on the NMS, which sits on the
       # OOB network as .10 — the Grafana drops panel, the FirewallDropBurst alert and the portal's log history read from there
       "firewall": {"forward": {"default_action": "drop", "allow": ["ike", "esp", "icmp"], "peers_only": True, "log_drops": True, "log_accepts": True},
                    "management": {"ssh": True, "lldp": True, "syslog": {"host": str(ipaddress.IPv4Network(I["oob"]["prefix"])[10]), "port": 5514, "protocol": "udp", "level": "info"}}}}
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
def ensure_ip(itf, cidr, primary_of=None, exclusive=True):
    """Address cidr on itf; other addresses of the same kind (same interface, exclusive) are unassigned so re-addressing works."""
    ip = nb.ipam.ip_addresses.get(address=cidr, namespace=ns.id) or nb.ipam.ip_addresses.get(address=cidr.split("/")[0], namespace=ns.id)
    if ip is None: ip = nb.ipam.ip_addresses.create(address=cidr, namespace=ns.id, status=active.id); created.append(f"ip:{cidr}")
    if str(ip.address) != cidr: ip.update({"address": cidr})
    if exclusive:
        for x in nb.ipam.ip_address_to_interface.filter(interface=itf.id):
            if str(getattr(x.ip_address, "id", x.ip_address)) != ip.id: x.delete(); created.append(f"unassigned old address from {itf.device.name}/{itf.name}")
    if not nb.ipam.ip_address_to_interface.get(ip_address=ip.id, interface=itf.id): nb.ipam.ip_address_to_interface.create(ip_address=ip.id, interface=itf.id)
    if primary_of is not None: ensure(primary_of, primary_ip4=ip.id)
    return ip
def ensure_cable(x, y):
    """Cable x<->y; a cable left with one end (device deleted) or going to another peer (re-wiring) is replaced."""
    for itf in (x, y):
        cur = requests.get(f"{a.url}/api/dcim/interfaces/{itf.id}/", params={"depth": 1}, headers=H, timeout=30).json().get("cable")
        if not cur: continue
        c = requests.get(f"{a.url}/api/dcim/cables/{cur['id']}/", headers=H, timeout=30)
        if c.status_code == 404: continue
        c = c.json(); ends = {c.get("termination_a_id"), c.get("termination_b_id")}
        if None in ends or ends != {x.id, y.id}:
            requests.delete(f"{a.url}/api/dcim/cables/{cur['id']}/", headers=H, timeout=30); created.append(f"removed cable on {itf.device.name}/{itf.name} (dangling or re-wired)")
    x, y = nb.dcim.interfaces.get(x.id), nb.dcim.interfaces.get(y.id)
    if x.cable or y.cable: return
    nb.dcim.cables.create(termination_a_type="dcim.interface", termination_a_id=x.id, termination_b_type="dcim.interface", termination_b_id=y.id, status=connected.id)
    created.append(f"cable:{x.device.name}:{x.name}-{y.device.name}:{y.name}")

ensure_prefix(I["oob"]["prefix"], prole["oob-management"], "cat8000v-ipsec OOB management (host = .1, NMS = .10)")
devs, gi = {}, {}
# devices are matched by management address (set by onboarding), so the hostname is free to change
by_mgmt = {x["primary_ip4"]["address"].split("/")[0]: x["id"] for x in requests.get(f"{a.url}/api/dcim/devices/", params={"location": SITE, "depth": 1, "limit": 100}, headers=H, timeout=30).json()["results"] if x.get("primary_ip4")}
def foreign_wired(dev, name):
    """True if the interface is cabled to a device that is not part of this lab (another lab attaches to it, e.g. the
    SRv6 core on a headend's GigabitEthernet3): its description, state, address and cable belong to that lab's seed."""
    itf = nb.dcim.interfaces.get(device=dev.id, name=name)
    if itf is None or not itf.cable: return False
    cur = requests.get(f"{a.url}/api/dcim/interfaces/{itf.id}/", params={"depth": 2}, headers=H, timeout=30).json()
    far = ((cur.get("cable_peer") or {}).get("device") or {}).get("name")   # REST: cable_peer (connected_interface is GraphQL-only)
    return bool(far) and far not in DEV

for r in ROUTERS:
    d = DEV[r]
    dev = nb.dcim.devices.get(by_mgmt[d["mgmt_ip"]]) if d["mgmt_ip"] in by_mgmt else sys.exit(f"no device with primary IP {d['mgmt_ip']} at {SITE} (run onboard.py)")
    ensure(dev, name=r, role=roles[d["role"]].id, secrets_group=sg.id, platform=plat.id, status=active.id, comments=d.get("comments", ""), location=branches[d["site"]].id)
    ensure_cf(dev, contact=d.get("contact", ""), **({"vpn_tunnel_capacity": CAPACITY} if d["role"] == "hub" else {}))   # every hub is a headend
    if nb.ipam.vrf_device_assignments.get(vrf=mgmt_vrf.id, device=dev.id) is None:
        nb.ipam.vrf_device_assignments.create(vrf=mgmt_vrf.id, device=dev.id); created.append(f"vrf-device:{r}")
    idx = NODES[d["mgmt_ip"]]["idx"]
    g1 = ensure_iface(dev, "GigabitEthernet1", "1000base-t", "OOB management (Mgmt-vrf)", mgmt_only=True, vrf=mgmt_vrf.id, mac=f"{OUI}:{idx:02x}:01")
    ensure_ip(g1, f"{d['mgmt_ip']}/24", primary_of=dev)
    for port in PORTS[d["role"]]:  # wired ports get description/enabled from the links; set here so one update suffices
        wired = WIRED.get((r, port))
        if port == LAN_PORT[r]:   # the site LAN: always up with .1 of the LAN /24 (advertised by BGP), a host behind it when one is wired
            gi[(r, port)] = ensure_iface(dev, f"GigabitEthernet{port}", "1000base-t", f"site LAN {d['lan']}" + (f" ({wired})" if wired else " (no host)"), enabled=True, mac=f"{OUI}:{idx:02x}:{port:02x}")
            continue
        if not wired and foreign_wired(dev, f"GigabitEthernet{port}"):   # cabled by another lab (the SRv6 core's attachment on a headend): theirs, leave it alone
            gi[(r, port)] = nb.dcim.interfaces.get(device=dev.id, name=f"GigabitEthernet{port}"); continue
        gi[(r, port)] = ensure_iface(dev, f"GigabitEthernet{port}", "1000base-t", f"WAN to {wired}" if wired else "unwired", enabled=bool(wired), mac=f"{OUI}:{idx:02x}:{port:02x}")
        if not wired:   # a port that lost its link (re-wiring) must not keep an address
            for x in nb.ipam.ip_address_to_interface.filter(interface=gi[(r, port)].id): x.delete(); created.append(f"unassigned address from unwired {r}/GigabitEthernet{port}")
    lo0 = ensure_iface(dev, "Loopback0", "virtual", "Router ID"); tag(ensure_prefix(f"{d['router_id']}/32", prole["loopback"], f"{r} router-id")); ensure_ip(lo0, f"{d['router_id']}/32")
    # the site LAN used to be Loopback10: it lives on the LAN port now (the host's default gateway)
    lo10 = nb.dcim.interfaces.get(device=dev.id, name="Loopback10")
    if lo10: lo10.delete(); created.append(f"removed {r}/Loopback10 (the site LAN is GigabitEthernet{LAN_PORT[r]} now)")
    tag(ensure_prefix(d["lan"], prole["site-lan"], f"{r} site LAN")); ensure_ip(gi[(r, LAN_PORT[r])], f"{LAN_IP[r]}/24")
    devs[r] = dev
# LAN hosts: one Alpine VM behind every router (cloud-init, no onboarding); eth0 = management, eth1 = the router's LAN (.2)
if LAN_HOSTS:
    hmfr = get_or_create(nb.dcim.manufacturers, {"name": "Alpine Linux"})
    htype = nb.dcim.device_types.get(model="Alpine VM", manufacturer=hmfr.id) or nb.dcim.device_types.create(model="Alpine VM", manufacturer=hmfr.id, u_height=0); htype = nb.dcim.device_types.get(model="Alpine VM", manufacturer=hmfr.id)
    hplat = nb.dcim.platforms.get(name="alpine") or nb.dcim.platforms.create(name="alpine", manufacturer=hmfr.id, network_driver="linux"); hplat = nb.dcim.platforms.get(name="alpine")
    hrole = get_or_create(nb.extras.roles, {"name": "lan-host"}, color="4caf50", content_types=["dcim.device"])
    for h in LAN_HOSTS:
        d = DEV[h]; r = d["router"]
        dev = nb.dcim.devices.get(by_mgmt[d["mgmt_ip"]]) if d["mgmt_ip"] in by_mgmt else nb.dcim.devices.get(name=h)
        if dev is None:
            dev = nb.dcim.devices.create(name=h, device_type=htype.id, role=hrole.id, platform=hplat.id, status=active.id, location=branches[DEV[r]["site"]].id); created.append(f"device:{h}")
        ensure(dev, name=h, role=hrole.id, platform=hplat.id, status=active.id, location=branches[DEV[r]["site"]].id, comments=d.get("comments", ""))
        idx = NODES[d["mgmt_ip"]]["idx"]
        e0 = ensure_iface(dev, "eth0", "1000base-t", "OOB management", mgmt_only=True, mac=f"{OUI}:{idx:02x}:00")
        ensure_ip(e0, f"{d['mgmt_ip']}/24", primary_of=dev)
        gi[(h, 1)] = ensure_iface(dev, "eth1", "1000base-t", f"LAN of {r} (GigabitEthernet{LAN_PORT[r]})", mac=f"{OUI}:{idx:02x}:01")
        devs[h] = dev
# firewalls: VyOS devices created here (no onboarding); eth0 = management, eth1 = headend side, eth2.. = spokes
if FIREWALLS:
    mfr = get_or_create(nb.dcim.manufacturers, {"name": "VyOS"})
    dtype = nb.dcim.device_types.get(model="VyOS", manufacturer=mfr.id) or nb.dcim.device_types.create(model="VyOS", manufacturer=mfr.id, u_height=1); created.append("device-type:VyOS") if not dtype.id in [x.id for x in nb.dcim.device_types.filter(model="VyOS")] else None
    dtype = nb.dcim.device_types.get(model="VyOS", manufacturer=mfr.id)
    vplat = nb.dcim.platforms.get(name="vyos") or nb.dcim.platforms.create(name="vyos", manufacturer=mfr.id, network_driver="vyos", napalm_driver="vyos"); vplat = nb.dcim.platforms.get(name="vyos")
    for f in FIREWALLS:
        d = DEV[f]
        dev = nb.dcim.devices.get(by_mgmt[d["mgmt_ip"]]) if d["mgmt_ip"] in by_mgmt else nb.dcim.devices.get(name=f)
        if dev is None:
            dev = nb.dcim.devices.create(name=f, device_type=dtype.id, role=roles["firewall"].id, platform=vplat.id, status=active.id, location=branches[d["site"]].id); created.append(f"device:{f}")
        ensure(dev, name=f, role=roles["firewall"].id, platform=vplat.id, status=active.id, location=branches[d["site"]].id, comments=d.get("comments", ""))
        ensure_cf(dev, contact=DEV[d["hub"]].get("contact", ""), firewall_bandwidth_mbps=int(d.get("bandwidth_mbps") or 0))
        idx = NODES[d["mgmt_ip"]]["idx"]
        e0 = ensure_iface(dev, "eth0", "1000base-t", "OOB management", mgmt_only=True, mac=f"{OUI}:{idx:02x}:00")
        ensure_ip(e0, f"{d['mgmt_ip']}/24", primary_of=dev)
        for port in PORTS["firewall"]:
            wired = WIRED.get((f, port))
            gi[(f, port)] = ensure_iface(dev, f"eth{port}", "1000base-t", (f"to {wired}" if wired else "unwired"), enabled=bool(wired), mac=f"{OUI}:{idx:02x}:{port:02x}")
        devs[f] = dev

# WAN point-to-point links: addresses, cables
for l in WAN_LINKS:
    an, ap, bn, bp, pfx = l["a"], l["a_port"], l["b"], l["b_port"], l["prefix"]; hosts = list(ipaddress.IPv4Network(pfx).hosts())
    ensure_prefix(pfx, prole["wan-p2p"], f"WAN link {an} Gi{ap} - {bn} Gi{bp}")
    ia, ib = gi[(an, ap)], gi[(bn, bp)]
    ensure_ip(ia, f"{hosts[0]}/30"); ensure_ip(ib, f"{hosts[1]}/30"); ensure_cable(ia, ib)
# LAN links: the router's LAN port (.1, addressed above) <-> its host's eth1 (.2), cabled
for l in LAN_LINKS:
    rn, rp, hn, hp = (l["a"], l["a_port"], l["b"], l["b_port"]) if DEV[l["a"]]["role"] != "host" else (l["b"], l["b_port"], l["a"], l["a_port"])
    hosts = list(ipaddress.IPv4Network(l["prefix"]).hosts())
    ensure_ip(gi[(hn, hp)], f"{hosts[1]}/24"); ensure_cable(gi[(rn, rp)], gi[(hn, hp)])
# VTI tunnels: hub TunnelN <-> spoke TunnelN over the link between them, as core VPN tunnels with two endpoints
def wan_iface(r, other):
    """The interface on r that carries traffic to `other`: the direct link, or (for a headend) its firewall link."""
    for l in LINKS:
        if {l["a"], l["b"]} == {r, other}: return gi[(r, l["a_port"] if l["a"] == r else l["b_port"])]
    # behind a firewall: a headend uses its firewall link for every spoke; a spoke uses its link to the headend's firewall
    fw = intent_mod.firewall_of(I, r if DEV[r]["role"] == "hub" else other)
    if fw:
        for l in LINKS:
            if {l["a"], l["b"]} == {r, fw}: return gi[(r, l["a_port"] if l["a"] == r else l["b_port"])]
    sys.exit(f"no WAN link between {r} and {other} (or {other}'s firewall)")
def ensure_endpoint(r, t, other, prof):
    src = wan_iface(r, other); src_ip = nb.ipam.ip_addresses.get(interfaces=src.id)
    # an interface can be the source of only ONE endpoint (OneToOne): a headend behind a firewall sources every
    # tunnel from the same WAN interface, so its endpoints carry the source address only
    shared = DEV[r]["role"] == "hub" and intent_mod.firewall_of(I, r) is not None
    src_if = None if shared else src.id
    protect = [nb.ipam.prefixes.get(prefix=DEV[r]["lan"], namespace=ns.id).id, nb.ipam.prefixes.get(prefix=f"{DEV[r]['router_id']}/32", namespace=ns.id).id]
    ep = nb.vpn.vpn_tunnel_endpoints.get(tunnel_interface=t.id)
    # the endpoint's device is an explicit field: without a source interface (shared WAN) the VPN app has nothing to derive it from,
    # and the NaC renderer needs the far end's device for the keyring peers
    if ep is None:
        ep = nb.vpn.vpn_tunnel_endpoints.create(**({"source_interface": src_if} if src_if else {}), device=devs[r].id, source_ipaddress=src_ip.id, tunnel_interface=t.id, vpn_profile=prof.id,
                                                role=vrole[DEV[r]["role"]].id, protected_prefixes=protect); created.append(f"vpn-endpoint:{r}/{t.name} via {src.name}")
    else:
        if getattr(ep.device, "id", None) != devs[r].id:
            requests.patch(f"{a.url}/api/vpn/vpn-tunnel-endpoints/{ep.id}/", json={"device": devs[r].id}, headers=H, timeout=30).raise_for_status(); created.append(f"endpoint {r}/{t.name}: device set")
            ep = nb.vpn.vpn_tunnel_endpoints.get(ep.id)
        if shared and getattr(ep.source_interface, "id", None):
            requests.patch(f"{a.url}/api/vpn/vpn-tunnel-endpoints/{ep.id}/", json={"source_interface": None}, headers=H, timeout=30).raise_for_status(); created.append(f"endpoint {r}/{t.name}: source interface cleared (shared WAN)")
            ep = nb.vpn.vpn_tunnel_endpoints.get(ep.id)
        ensure(ep, **({"source_interface": src_if} if src_if else {}), source_ipaddress=src_ip.id, vpn_profile=prof.id, role=vrole[DEV[r]["role"]].id)
        have = gql('{ vpn_tunnel_endpoints(id: "%s") { protected_prefixes { id } } }' % ep.id)["vpn_tunnel_endpoints"][0]["protected_prefixes"]
        if sorted(x["id"] for x in have) != sorted(protect):   # M2M fields are absent from REST reads, so pynautobot's update() never sends them: PATCH directly
            requests.patch(f"{a.url}/api/vpn/vpn-tunnel-endpoints/{ep.id}/", json={"protected_prefixes": protect}, headers=H, timeout=30).raise_for_status()
            created.append(f"protected prefixes on {r}/{t.name}")
    return ep
tun_ip = {}
wanted_tunnels = set()
for t in TUNNELS:
    tid, hub, spoke, pfx = int(t["id"]), t["hub"], t["spoke"], t["prefix"]
    hosts = list(ipaddress.IPv4Network(pfx).hosts()); ensure_prefix(pfx, prole["vpn-tunnel"], f"IPsec VTI Tunnel{tid} {hub} - {spoke}")
    ends = {}
    for r, ip, other in ((hub, hosts[0], spoke), (spoke, hosts[1], hub)):
        # one tunnel interface per far end; if the id changed, the old TunnelN (and its endpoint) goes away
        for old in nb.dcim.interfaces.filter(device=devs[r].id, type="tunnel"):
            if old.name != f"Tunnel{tid}" and old.description == f"IPsec VTI to {other}": old.delete(); created.append(f"removed {r}/{old.name}")
        ti = ensure_iface(devs[r], f"Tunnel{tid}", "tunnel", f"IPsec VTI to {other}")   # type "tunnel": required by the VPN endpoint model
        tun_ip[(r, tid)] = ensure_ip(ti, f"{ip}/30"); drop_legacy_tunnel_model(ti); ends[r] = ensure_endpoint(r, ti, other, profile_of(spoke))
    tp = profile_of(spoke)   # the tunnel and both its endpoints carry the profile of the spoke's chosen authentication
    tun = nb.vpn.vpn_tunnels.get(vpn=vpn.id, tunnel_id=str(tid)) or get_or_create(nb.vpn.vpn_tunnels, {"name": f"{hub}-{spoke}"}, tunnel_id=str(tid), vpn=vpn.id,
                                                                                    vpn_profile=tp.id, status=active.id, encapsulation="IPsec-Tunnel", endpoint_a=ends[hub].id, endpoint_z=ends[spoke].id)
    ensure(tun, name=f"{hub}-{spoke}", tunnel_id=str(tid), vpn=vpn.id, vpn_profile=tp.id, status=active.id, encapsulation="IPsec-Tunnel",
           endpoint_a=ends[hub].id, endpoint_z=ends[spoke].id, description=f"Tunnel{tid}: {hub} <-> {spoke} ({pfx})")
    ensure_cf(tun, psk_fingerprint=hashlib.sha256(DEV[spoke]["psk"].encode()).hexdigest()[:12], psk_rotated=DEV[spoke].get("psk_rotated", ""))
    wanted_tunnels.add(tun.id)
for old in nb.vpn.vpn_tunnels.filter(vpn=vpn.id):
    if old.id not in wanted_tunnels: old.delete(); created.append(f"removed stale VPN tunnel {old.name}")

# eBGP: one AS per site, hub <-> spoke peering over each tunnel
bgp = nb.plugins.bgp
need = [ct for ct in ("nautobot_bgp_models.autonomoussystem", "nautobot_bgp_models.bgproutinginstance", "nautobot_bgp_models.peering") if ct not in active.content_types]
if need: active.update({"content_types": list(active.content_types) + need})
asn = {r: get_or_create(bgp.autonomous_systems, {"asn": int(DEV[r]["asn"])}, status=active.id, description=f"{r} site AS (eBGP over IPsec VTI)") for r in ROUTERS}
ri = {}
for r in ROUTERS:
    rid_ip = nb.ipam.ip_addresses.get(address=f"{DEV[r]['router_id']}/32", namespace=ns.id)
    inst = bgp.routing_instances.get(device=devs[r].id)
    if inst is None:
        inst = bgp.routing_instances.create(device=devs[r].id, autonomous_system=asn[r].id, router_id=rid_ip.id, status=active.id,
                                            extra_attributes={"log_neighbor_changes": True}, description="site eBGP"); created.append(f"bgp-ri:{r}")
    else: ensure(inst, autonomous_system=asn[r].id, router_id=rid_ip.id)
    ri[r] = inst
    if bgp.address_families.get(routing_instance=inst.id, afi_safi="ipv4_unicast", vrf__isnull=True) is None:
        bgp.address_families.create(routing_instance=inst.id, afi_safi="ipv4_unicast"); created.append(f"bgp-af:{r}")
for t in TUNNELS:
    tid, hub, spoke = int(t["id"]), t["hub"], t["spoke"]
    # the spoke's peering towards this hub (matched by description, then re-pointed if the tunnel address changed)
    eps_spoke = list(bgp.peer_endpoints.filter(routing_instance=ri[spoke].id))
    existing = ([e for e in eps_spoke if str(getattr(e.source_ip, "id", "")) == tun_ip[(spoke, tid)].id]
                or [e for e in eps_spoke if str(e.description or "").startswith(f"eBGP {hub} (")])
    if existing:
        eps = {spoke: existing[0], hub: existing[0].peer}
        ensure(eps[spoke], source_ip=tun_ip[(spoke, tid)].id, autonomous_system=asn[spoke].id, description=f"eBGP {hub} (Tunnel{tid})")
        ensure(eps[hub], source_ip=tun_ip[(hub, tid)].id, autonomous_system=asn[hub].id, description=f"eBGP {spoke} (Tunnel{tid})")
    else:
        peering = bgp.peerings.create(status=active.id); created.append(f"bgp-peering:{hub}<->{spoke} (Tunnel{tid})")
        eps = {hub: bgp.peer_endpoints.create(peering=peering.id, routing_instance=ri[hub].id, source_ip=tun_ip[(hub, tid)].id, autonomous_system=asn[hub].id, description=f"eBGP {spoke} (Tunnel{tid})", enabled=True),
               spoke: bgp.peer_endpoints.create(peering=peering.id, routing_instance=ri[spoke].id, source_ip=tun_ip[(spoke, tid)].id, autonomous_system=asn[spoke].id, description=f"eBGP {hub} (Tunnel{tid})", enabled=True)}
    for r, ep in eps.items():
        if bgp.peer_endpoint_address_families.get(peer_endpoint=ep.id, afi_safi="ipv4_unicast") is None:
            bgp.peer_endpoint_address_families.create(peer_endpoint=ep.id, afi_safi="ipv4_unicast"); created.append(f"bgp-endpoint-af:{r}/Tunnel{tid}")
# unused autonomous systems (after an AS change) are removed
for x in bgp.autonomous_systems.all():
    if "IPsec VTI" in (x.description or "") and x.asn not in {int(DEV[r]["asn"]) for r in ROUTERS}: x.delete(); created.append(f"removed AS {x.asn}")

QUERY = (Path(__file__).resolve().parent / "nac-c8000v-ipsec-model.graphql").read_text().replace("__LOCATION__", SITE).replace("__DEVICES__", ", ".join(f'"{r}"' for r in ROUTERS))
gq = nb.extras.graphql_queries.get(name="nac-c8000v-ipsec-model")
if gq is None: nb.extras.graphql_queries.create(name="nac-c8000v-ipsec-model", query=QUERY); created.append("graphql-query:nac-c8000v-ipsec-model")
elif gq.query.strip() != QUERY.strip():
    nb.http_session.patch(f"{a.url}/api/extras/graphql-queries/{gq.id}/", json={"query": QUERY}, headers=H).raise_for_status(); created.append("graphql-query updated")
print(f"seed complete: {len(created)} changes" + (":\n  " + "\n  ".join(created) if created else " (nothing new)"))
