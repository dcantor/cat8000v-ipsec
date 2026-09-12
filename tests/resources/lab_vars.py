"""Robot Framework variable file: C8000v IPsec VTI + eBGP lab inventory and expected state (mirrors ../../lab.conf)."""
import os

USERNAME = os.environ.get("IOSXE_USERNAME", "admin")
PASSWORD = os.environ.get("IOSXE_PASSWORD", "admin")

HUB = "hub"
SPOKES = ["spoke1", "spoke2"]
ROUTERS = {
    "hub":    {"role": "hub",   "host": "10.2.0.11", "asn": "65200", "router_id": "10.255.1.1", "lan": "192.168.11.0/24", "lan_ip": "192.168.11.1"},
    "spoke1": {"role": "spoke", "host": "10.2.0.12", "asn": "65201", "router_id": "10.255.1.2", "lan": "192.168.12.0/24", "lan_ip": "192.168.12.1"},
    "spoke2": {"role": "spoke", "host": "10.2.0.13", "asn": "65202", "router_id": "10.255.1.3", "lan": "192.168.13.0/24", "lan_ip": "192.168.13.1"},
}
ROUTER_NAMES = list(ROUTERS)

# One point-to-point WAN link and one IPsec VTI per spoke (TunnelN exists on the hub and on that spoke).
TUNNELS = {
    "spoke1": {"id": "1", "hub_if": "GigabitEthernet2", "hub_wan": "100.65.1.1", "spoke_if": "GigabitEthernet2", "spoke_wan": "100.65.1.2",
               "wan_prefix": "100.65.1.0/30", "hub_ip": "172.17.1.1", "spoke_ip": "172.17.1.2", "prefix": "172.17.1.0/30"},
    "spoke2": {"id": "2", "hub_if": "GigabitEthernet3", "hub_wan": "100.65.2.1", "spoke_if": "GigabitEthernet2", "spoke_wan": "100.65.2.2",
               "wan_prefix": "100.65.2.0/30", "hub_ip": "172.17.2.1", "spoke_ip": "172.17.2.2", "prefix": "172.17.2.0/30"},
}

OOB_GATEWAY = "10.2.0.1"
DOMAIN_NAME = "lab.local"
MGMT_ACL = "MGMT-ACCESS"
IKEV2_PROFILE = "VPN-IKEV2"
IPSEC_PROFILE = "VPN-IPSEC"
NAUTOBOT_LOCATION = "c8000v-ipsec-lab"
BANNER_TEXT = "C8000v IPsec VTI lab"
