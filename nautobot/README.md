# The IPsec VTI lab in Nautobot

This lab lives in the **shared Nautobot** of the cat9000v lab (http://10.0.0.10:8080,
from the LAN http://192.168.50.231:8080, `admin`/`admin`) under location
`c8000v-ipsec-lab`. The NMS VM has a NIC on this lab's OOB network (`10.2.0.10`),
so onboarding, Golden Config and the tests reach the routers directly.

```
 routers ──(onboard.py: SSH discovery)──▶ Nautobot ◀──(seed.py: VTI/eBGP intent)── lab.conf
                                            │
                                            └──(render_nac.py)──▶ nac/data/devices.nac.yaml ──▶ terraform ──▶ routers
```

| Command | What it does |
|---|---|
| `./lab.sh nautobot onboard` | location `c8000v-ipsec-lab`, *Sync Devices From Network* for 10.2.0.11-13 (model, serial, platform, mgmt IP from the routers) |
| `./lab.sh nautobot seed` | idempotent intent: roles `vpn-hub`/`vpn-spoke`, prefix roles (`oob-management`, `wan-p2p`, `vpn-tunnel`, `site-lan`, `loopback`), `Mgmt-vrf` on Gi1, **p2p WAN links as cables** between hub GiN and spoke Gi2 with /30 addresses (unwired ports disabled), Loopback0/Loopback10, TunnelN interfaces, **the VPN in the core VPN app** (below), config context `c8000v-ipsec` (OOB, domain), AS 65200/65201/65202, routing instances and **eBGP peerings** over the tunnel addresses, `bgp:advertise` tags, saved GraphQL query `nac-c8000v-ipsec-model` |
| `./lab.sh nautobot render [--check]` | regenerates `nac/data/devices.nac.yaml` from the saved query (`--check` diffs only) |
| `./lab.sh nautobot golden` | Golden Config setting `c8000v-ipsec` (scope = location), template `c8000v-ipsec.j2` in Gitea, `wan-interface` feature, then backup → intended → compliance |
| `./lab.sh nautobot token` | API token |

## How the VPN is modelled

Nautobot 3.2 ships a core **VPN** app (Networking → VPN in the GUI). The lab uses
it as-is — no custom fields, relationships or third-party apps:

```
 VPN Phase 1 Policy  VPN-IKEV2   IKEv2 · AES-256-CBC · SHA256 · DH 14 · 86400 s · PSK
 VPN Phase 2 Policy  VPN-TS      AES-256-CBC · SHA256 · 3600 s
        └──────────────┬───────────────┘
 VPN Profile         VPN-IPSEC   DPD 30 s × 5, extra_options.ios = Cisco object names
        │
 VPN                 IPSEC_VPN   service type IPSec, status Active
        ├── VPN Tunnel  hub-spoke1  id 1, IPsec-Tunnel   A: hub Gi2 (100.65.1.1)  ── Z: spoke1 Gi2 (100.65.1.2)
        └── VPN Tunnel  hub-spoke2  id 2, IPsec-Tunnel   A: hub Gi3 (100.65.2.1)  ── Z: spoke2 Gi2 (100.65.2.2)
 VPN Tunnel Endpoint (per router end): role hub/spoke, source interface + address, tunnel interface
                                       TunnelN (type "tunnel"), protected prefixes = site LAN + loopback
```

| Cisco config | Comes from |
|---|---|
| `tunnel source GigabitEthernetN` | endpoint `source_interface` |
| `tunnel destination x.x.x.x` | the *other* endpoint's `source_ipaddress` (A↔Z on the VPN Tunnel) |
| `tunnel mode ipsec ipv4` | VPN Tunnel `encapsulation` = IPsec-Tunnel |
| `crypto ikev2 proposal/policy/keyring/profile`, `dpd 30 5 on-demand` | Phase 1 policy + profile keepalive; names from `extra_options.ios` |
| `crypto ipsec transform-set`, `crypto ipsec profile` | Phase 2 policy; names from `extra_options.ios` |
| `network` statements (BGP) | prefixes tagged `bgp:advertise` (the same prefixes are the endpoints' *protected prefixes*) |
| pre-shared key | **not in Nautobot** — `vpn_psk` in `nac/data/device_groups.nac.yaml` |

GraphiQL, from an interface: `vpn_tunnel_endpoints_tunnel { source_interface { name }
endpoint_a_vpn_tunnels { encapsulation endpoint_z { source_ipaddress { address } } } vpn_profile { … } }`
— the saved query *nac-c8000v-ipsec-model* (Extensibility → GraphQL Queries) does this for all routers.

Round trip verified: `render` from the VPN objects produced a byte-identical
`devices.nac.yaml` to the earlier interface-based model, `terraform plan` reports
*No changes*, test `06_nautobot` checks every router's `tunnel destination` against
the far endpoint and the crypto against the policies.

Golden Config: 16 features shared with the other labs plus `wan-interface` —
**51/51 compliant**. The shared SoT query `golden-config-lab` was extended with
`vpn_tunnel_endpoints_tunnel` so the template renders the VTIs and the crypto suite
from the same objects.

Nautobot 3.2.4 quirks met on the way (worked around in `seed.py`):
- the VPN-profile ↔ policy assignment endpoints return 500 (`unexpected keyword
  _custom_field_data`) and the profile serializer ignores `vpn_phase1/2_policies` on
  write — the two rows are added through the ORM (`nautobot-server nbshell` on the NMS);
- M2M fields (`protected_prefixes`, policies) are absent from REST *reads* — verified via GraphQL;
- endpoint `tunnel_interface` must be an interface of type `tunnel` (not `virtual`);
- GraphQL renders single-choice fields as enum names (`IPSEC_TUNNEL`, `IKEV2`) but
  JSON-array choice fields raw (`AES-256-CBC`) — the renderer normalises both;
- a custom field created moments earlier is invisible to the per-content-type field cache:
  values written to it are dropped silently until the field is saved again — and pynautobot
  sends nothing for an unchanged `update()`, so `seed.py` nudges a brand-new field with a
  real change of its description (`nudge_cf`); the `cert_*` device fields (certificate mode,
  written by `pki.py`) are created this way.

Gotcha found while seeding: pynautobot diffs an `update()` against the record as
first fetched, so two updates of the same field in one run (e.g. `enabled` False
then True) silently drop the second — `seed.py` therefore decides the wired state
before creating the port.
