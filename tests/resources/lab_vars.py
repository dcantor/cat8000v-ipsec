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
ROUTERS = {d["name"]: {"role": d["role"], "host": d["mgmt_ip"], "asn": str(d["asn"]), "router_id": d["router_id"], "lan": d["lan"],
                       "lan_ip": str(ipaddress.IPv4Network(d["lan"])[1]), "region": d.get("region"), "site": d.get("site"),
                       "site_code": d.get("site_code", ""), "psk": d.get("psk")} for d in _I["devices"] if d["role"] in ("hub", "spoke")}
REGIONS = _I.get("regions", [])
ROUTER_NAMES = list(ROUTERS)
# VyOS firewalls: one per headend, between the headend (eth1) and its spokes (eth2..)
FIREWALLS = {d["name"]: {"host": d["mgmt_ip"], "hub": d["hub"], "region": d.get("region"), "site": d.get("site")} for d in _I["devices"] if d["role"] == "firewall"}
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
MGMT_ACL = _I["oob"]["acl"]
IKEV2_PROFILE = _I["profile"]["ios"]["ikev2_profile"]
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
