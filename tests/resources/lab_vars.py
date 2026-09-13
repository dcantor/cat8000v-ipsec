"""Robot Framework variable file: inventory and expected state of the C8000v IPsec VTI + eBGP lab,
derived from ../../lab-intent.json (the document the web app edits; generated from lab.conf by default)."""
import ipaddress, os, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "nautobot"))
import intent as intent_mod  # noqa: E402

USERNAME = os.environ.get("IOSXE_USERNAME", "admin")
PASSWORD = os.environ.get("IOSXE_PASSWORD", "admin")

_I = intent_mod.load()
HUB = next(d["name"] for d in _I["devices"] if d["role"] == "hub")
SPOKES = sorted(d["name"] for d in _I["devices"] if d["role"] == "spoke")
ROUTERS = {d["name"]: {"role": d["role"], "host": d["mgmt_ip"], "asn": str(d["asn"]), "router_id": d["router_id"], "lan": d["lan"],
                       "lan_ip": str(ipaddress.IPv4Network(d["lan"])[1])} for d in _I["devices"]}
ROUTER_NAMES = list(ROUTERS)
ROUTER_GQL = ", ".join(f'"{n}"' for n in ROUTER_NAMES)   # for GraphQL device:[...] filters

# One point-to-point WAN link and one IPsec VTI per spoke (TunnelN exists on the hub and on that spoke).
TUNNELS = {}
for _t in _I["tunnels"]:
    _l = next(l for l in _I["links"] if {l["a"], l["b"]} == {HUB, _t["spoke"]})
    _hub_port, _spoke_port = (_l["a_port"], _l["b_port"]) if _l["a"] == HUB else (_l["b_port"], _l["a_port"])
    _wan = list(ipaddress.IPv4Network(_l["prefix"]).hosts()); _tun = list(ipaddress.IPv4Network(_t["prefix"]).hosts())
    _hub_wan, _spoke_wan = (_wan[0], _wan[1]) if _l["a"] == HUB else (_wan[1], _wan[0])
    TUNNELS[_t["spoke"]] = {"id": str(_t["id"]), "hub_if": f"GigabitEthernet{_hub_port}", "hub_wan": str(_hub_wan),
                            "spoke_if": f"GigabitEthernet{_spoke_port}", "spoke_wan": str(_spoke_wan), "wan_prefix": _l["prefix"],
                            "hub_ip": str(_tun[0]), "spoke_ip": str(_tun[1]), "prefix": _t["prefix"]}

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
