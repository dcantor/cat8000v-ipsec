"""Robot Framework variable file: inventory and expected state of the C8000v IPsec VTI + eBGP lab,
derived from ../../lab-intent.json (the document the web app edits; generated from lab.conf by default)."""
import ipaddress, os, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "nautobot"))
import intent as intent_mod  # noqa: E402

USERNAME = os.environ.get("IOSXE_USERNAME", "admin")
PASSWORD = os.environ.get("IOSXE_PASSWORD", "admin")

_I = intent_mod.load()
HUBS = sorted(d["name"] for d in _I["devices"] if d["role"] == "hub")
HUB = HUBS[0]
SPOKES = sorted(d["name"] for d in _I["devices"] if d["role"] == "spoke")
def _router(d):
    return {"role": d["role"], "host": d["mgmt_ip"], "asn": str(d["asn"]), "router_id": d["router_id"], "lan": d["lan"],
            "lan_ip": str(ipaddress.IPv4Network(d["lan"])[1]), "region": d.get("region"), "site": d.get("site"),
            "site_code": d.get("site_code", ""), "psk": d.get("psk"), "lan_if": f"GigabitEthernet{intent_mod.lan_port(_I, d['name'])}"}
# every Catalyst 8000v; ROUTERS stays the VPN routers (headends + branches) so suites 01-11 keep their scope, EDGE_ROUTERS is the
# DCI chain off west-headend: ACME's interconnect and the acquired company's edge, which peer with plain eBGP (suite 12)
ALL_ROUTERS = {d["name"]: _router(d) for d in _I["devices"] if d["role"] in intent_mod.ROUTER_ROLES}
ROUTERS = {n: r for n, r in ALL_ROUTERS.items() if r["role"] in ("hub", "spoke")}
EDGE_ROUTERS = {n: r for n, r in ALL_ROUTERS.items() if r["role"] in ("dci", "partner")}
# the LAN hosts: one Alpine VM behind a router (eth1 = .2 of the router's LAN /24, default gateway .1; OOB eth0, lab / lab)
LAN_HOSTS = {d["name"]: {"host": d["mgmt_ip"], "router": d["router"], "lan": ALL_ROUTERS[d["router"]]["lan"], "lan_ip": str(ipaddress.IPv4Network(ALL_ROUTERS[d["router"]]["lan"])[2]),
                         "gateway": ALL_ROUTERS[d["router"]]["lan_ip"]} for d in _I["devices"] if d["role"] == "host"}
HOST_OF = {h["router"]: n for n, h in LAN_HOSTS.items()}
REGIONS = _I.get("regions", [])
ROUTER_NAMES = list(ROUTERS)
EDGE_NAMES = list(EDGE_ROUTERS)
# the eBGP sessions that run over a direct link instead of a tunnel (west-headend <-> DCI <-> ACME-acquisition)
DIRECT_PEERINGS = intent_mod.direct_peerings(_I)
EXTRA_LOOPBACKS = {n: intent_mod.extra_loopbacks(_I, n) for n in ALL_ROUTERS}
_ACQ_PREFIXES = sorted([EDGE_ROUTERS[n]["lan"] for n in EDGE_NAMES if EDGE_ROUTERS[n]["role"] == "partner"] +
                       [str(ipaddress.IPv4Interface(lo["address"]).network) for n in EDGE_NAMES if EDGE_ROUTERS[n]["role"] == "partner" for lo in EXTRA_LOOPBACKS[n] if lo.get("advertise", True)])
NAT = {n: intent_mod.nat(_I, n) for n in ALL_ROUTERS if intent_mod.nat(_I, n)}
NAT_ROUTER = next(iter(NAT), None)
OVERLAPS = NAT[NAT_ROUTER]["overlaps"] if NAT_ROUTER else []
_OVERLAPPING = {ov["prefix"] for ov in OVERLAPS}                              # translated by the DCI, never advertised across it
ACQUISITION_PREFIXES = [p for p in _ACQ_PREFIXES if p not in _OVERLAPPING]    # what the acquired company originates into the VPN
ACQUISITION_IPS = [str(ipaddress.IPv4Network(p)[1]) for p in ACQUISITION_PREFIXES]   # the .1 of each: what a branch pings
# VyOS firewalls: one per headend, between the headend (eth1) and its spokes (eth2..)
LINKS = _I["links"]                                        # every WAN link of the intent (a, a_port, b, b_port, prefix)
FIREWALLS = {d["name"]: {"host": d["mgmt_ip"], "hub": d["hub"], "region": d.get("region"), "site": d.get("site"), "bandwidth_mbps": int(d.get("bandwidth_mbps") or 0)} for d in _I["devices"] if d["role"] == "firewall"}
# both headend constraints as the intent computes them (tunnels per headend, firewall bandwidth); the portal must agree
HEADEND_CAPACITY = {h: intent_mod.headend_capacity(_I, h) for h in HUBS}
FIREWALL_OF = {v["hub"]: k for k, v in FIREWALLS.items()}
VYOS_USERNAME = os.environ.get("VYOS_USERNAME", "vyos"); VYOS_PASSWORD = os.environ.get("VYOS_PASSWORD", "vyos")
ROUTER_GQL = ", ".join(f'"{n}"' for n in ROUTER_NAMES)   # for GraphQL device:[...] filters

# One point-to-point WAN link and one IPsec VTI per (hub, spoke) pair: TunnelN exists on both ends.
TUNNEL_LIST = []
for _t in _I["tunnels"]:
    _fw = FIREWALL_OF.get(_t["hub"])
    _sl = next(l for l in _I["links"] if {l["a"], l["b"]} == {_fw or _t["hub"], _t["spoke"]})           # spoke's WAN link (to the firewall, or the hub directly)
    _hl = next(l for l in _I["links"] if {l["a"], l["b"]} == {_fw, _t["hub"]}) if _fw else _sl          # hub's WAN link (to the firewall)
    _spoke_port = _sl["b_port"] if _sl["b"] == _t["spoke"] else _sl["a_port"]; _fw_port = _sl["a_port"] if _sl["a"] == _fw else _sl["b_port"]
    _hub_port = _hl["b_port"] if _hl["b"] == _t["hub"] else _hl["a_port"]
    _sw = list(ipaddress.IPv4Network(_sl["prefix"]).hosts()); _hw = list(ipaddress.IPv4Network(_hl["prefix"]).hosts()); _tun = list(ipaddress.IPv4Network(_t["prefix"]).hosts())
    _spoke_wan = _sw[1] if _sl["b"] == _t["spoke"] else _sw[0]; _spoke_gw = _sw[0] if _sl["b"] == _t["spoke"] else _sw[1]
    _hub_wan = _hw[1] if _hl["b"] == _t["hub"] else _hw[0]; _hub_gw = _hw[0] if _hl["b"] == _t["hub"] else _hw[1]
    TUNNEL_LIST.append({"id": str(_t["id"]), "hub": _t["hub"], "spoke": _t["spoke"], "firewall": _fw,
                        "hub_if": f"GigabitEthernet{_hub_port}", "hub_wan": str(_hub_wan), "hub_gw": str(_hub_gw), "hub_link": _hl["prefix"],
                        "spoke_if": f"GigabitEthernet{_spoke_port}", "spoke_wan": str(_spoke_wan), "spoke_gw": str(_spoke_gw), "wan_prefix": _sl["prefix"],
                        "fw_spoke_if": f"eth{_fw_port}" if _fw else None, "fw_hub_if": f"eth{_hl['a_port'] if _hl['a'] == _fw else _hl['b_port']}" if _fw else None,
                        "hub_ip": str(_tun[0]), "spoke_ip": str(_tun[1]), "prefix": _t["prefix"]})
TUNNEL_LIST.sort(key=lambda t: int(t["id"]))
TUNNELS = {t["spoke"]: t for t in TUNNEL_LIST if t["hub"] == HUB}   # first hub's tunnels keyed by spoke (legacy helpers)
HUB_TUNNELS = {h: [t for t in TUNNEL_LIST if t["hub"] == h] for h in HUBS}
SPOKE_TUNNELS = {s: [t for t in TUNNEL_LIST if t["spoke"] == s] for s in SPOKES}

OOB_GATEWAY = _I["oob"]["gateway"]
DOMAIN_NAME = _I["domain_name"]
# IKE authentication is chosen per spoke (device ike_authentication, else the lab default profile.ike.authentication): "psk" (its own key) or
# "certificate" (enrolled with the lab CA — pki/, nautobot/pki.py). A headend serves one IKEv2 / IPsec profile per method its spokes use.
IKE_AUTH = intent_mod.default_auth(_I)                                        # the lab default
SPOKE_AUTH = {s: intent_mod.spoke_auth(_I, s) for s in SPOKES}
for _t in TUNNEL_LIST: _t["auth"] = SPOKE_AUTH[_t["spoke"]]; _t["auth_show"] = "RSA" if _t["auth"] == "certificate" else "PSK"
ROUTER_AUTHS = {r: sorted(intent_mod.router_auths(_I, r)) for r in ROUTER_NAMES}   # the methods each router's tunnels use
CERT_ROUTERS = intent_mod.cert_routers(_I)                                    # routers holding a certificate (any certificate-authenticated tunnel)
PSK_ROUTERS = sorted(r for r in ROUTER_NAMES if "psk" in ROUTER_AUTHS[r])       # routers holding a keyring
PROFILE_NAMES = {a: intent_mod.profile_names(_I, a) for a in ("psk", "certificate")}   # Cisco / Nautobot names per method
# internet breakout: enabled?, the firewalls' uplink port, and per spoke the headends in preference order (nearest first)
INTERNET = intent_mod.internet(_I)
INTERNET_UPLINK = f"eth{INTERNET['uplink_port']}"
BREAKOUT_PREF = INTERNET["preference"]
PKI = {**{"trustpoint": "LAB-CA", "keypair": "LAB-VPN", "certificate_map": "LAB-CERT-MAP", "validity_days": 365, "renew_before_days": 30}, **(_I["profile"].get("pki") or {})}
IKE_AUTH_SHOW = "RSA" if IKE_AUTH == "certificate" else "PSK"                 # as `show crypto ikev2 sa detail` prints Auth sign / verify (lab default)
IKE_AUTH_METHOD = "rsa-sig" if IKE_AUTH == "certificate" else "pre-share"     # as `show crypto ikev2 profile` prints the authentication method (lab default)
MGMT_ACL = _I["oob"]["acl"]
IKEV2_PROFILE = _I["profile"]["ios"]["ikev2_profile"]
PROFILE_NAME = _I["profile"]["name"]
IPSEC_PROFILE = _I["profile"]["ios"]["ipsec_profile"]
VPN_PROFILE = _I["profile"]["name"]
VPN_NAME = _I["vpn"]["name"]
IKE = _I["profile"]["ike"]
IPSEC = _I["profile"]["ipsec"]
DPD = _I["profile"]["dpd"]
NAUTOBOT_LOCATION = _I["site"]["name"]
BANNER_TEXT = "C8000v IPsec VTI lab"
# "show crypto ikev2 sa" / "show crypto ikev2 proposal" spellings of the modelled algorithms
IKE_SA_ENCR = {"AES-128-CBC": "AES-CBC, keysize: 128", "AES-192-CBC": "AES-CBC, keysize: 192", "AES-256-CBC": "AES-CBC, keysize: 256",
               "AES-128-GCM": "AES-GCM, keysize: 128", "AES-256-GCM": "AES-GCM, keysize: 256"}[IKE["encryption"]]
IKE_PROPOSAL_ENCR = {"AES-128-CBC": "AES-CBC-128", "AES-192-CBC": "AES-CBC-192", "AES-256-CBC": "AES-CBC-256", "AES-128-GCM": "AES-GCM-128", "AES-256-GCM": "AES-GCM-256"}[IKE["encryption"]]
ESP_TRANSFORM = ({"AES-128-CBC": "esp-aes", "AES-192-CBC": "esp-192-aes", "AES-256-CBC": "esp-256-aes", "AES-128-GCM": "esp-gcm", "AES-256-GCM": "esp-gcm 256"}[IPSEC["encryption"]]
                 + " " + {"SHA1": "esp-sha-hmac", "SHA256": "esp-sha256-hmac", "SHA384": "esp-sha384-hmac", "SHA512": "esp-sha512-hmac", "MD5": "esp-md5-hmac"}[IPSEC["integrity"]])
# customers: every branch is a customer of ACME (the provider owning the headends) — a Nautobot tenant; the design pattern follows the tunnel count
PROVIDER = _I.get("provider") or intent_mod.PROVIDER
CUSTOMERS = {s: intent_mod.customer(_I, s) for s in SPOKES}
CUSTOMERS_ALL = {n: intent_mod.customer(_I, n) for n in ALL_ROUTERS if intent_mod.customer(_I, n)}
PATTERNS = {r: intent_mod.design_pattern(_I, r) for r in ALL_ROUTERS}
ADDRESSES = {r: (CUSTOMERS[r]["address"] if r in CUSTOMERS else next(d.get("address") for d in _I["devices"] if d["name"] == r)) for r in ROUTER_NAMES}
PATTERN_CODES = sorted(p["code"] for p in intent_mod.PATTERNS.values())

# A WAN address no branch may reach: the WAN /30s are never advertised, and a headend holds static routes only to the WAN links of
# its own spokes — so a branch can reach the WAN addresses of its own headends' firewalls and nothing else. Two branches that share
# a headend DO reach each other's WAN there (that headend routes both /30s and the firewalls pass ICMP), so the negative test has to
# pick a branch pair with no headend in common; empty when every pair shares one (then suite 02 skips that check).
UNROUTED_WAN = {}
for _s in SPOKES:
    _mine = {_t["hub"] for _t in SPOKE_TUNNELS[_s]}
    for _o in SPOKES:
        if _o == _s or UNROUTED_WAN: continue
        for _t in SPOKE_TUNNELS[_o]:
            if _t["hub"] not in _mine:
                UNROUTED_WAN = {"spoke": _s, "spoke_if": SPOKE_TUNNELS[_s][0]["spoke_if"], "target": _t["spoke_wan"],
                                "target_spoke": _o, "via_hub": _t["hub"]}
                break

# the DCI chain hangs off one headend: its name (and the interconnect router), so a host behind it is expected to break out there
DCI_UPLINK = next((p["b"] for p in DIRECT_PEERINGS if ALL_ROUTERS.get(p["a"], {}).get("role") == "hub"), None)
DCI_UPLINK_HUB = next((p["a"] for p in DIRECT_PEERINGS if ALL_ROUTERS.get(p["a"], {}).get("role") == "hub"), None)

# the DCI's twice-NAT: where the overlapping prefix is answered from on each side
DNS_SERVER = next((n for n in ALL_ROUTERS if intent_mod.dns(_I, n)), None)
DNS_ZONE = intent_mod.dns(_I, DNS_SERVER) if DNS_SERVER else {}
DNS_CLIENT = {n: intent_mod.dns_client(_I, n) for n in ALL_ROUTERS if intent_mod.dns_client(_I, n)}

INTENT_FILE = str(intent_mod.INTENT_FILE)   # the document every run round-trips through the API

# the scale set: 100 prefixes that exist on both sides at once, and the zones each side answers for
SCALE = (NAT[NAT_ROUTER] or {}).get("scale") if NAT_ROUTER else None
SCALE_ENTRIES = intent_mod.nat_scale(NAT[NAT_ROUTER]) if NAT_ROUTER else []
SCALE_AGGREGATES = intent_mod.nat_scale_aggregates(NAT[NAT_ROUTER]) if NAT_ROUTER else None   # what BGP carries instead of 100 routes
DNS_ZONES = {n: intent_mod.dns(_I, n) for n in ALL_ROUTERS if intent_mod.dns(_I, n)}
HOST_RESOLVERS = {n: h["dns_client"] for n, h in
                  {d["name"]: d for d in _I["devices"] if d["role"] == "host" and d.get("dns_client")}.items()}
