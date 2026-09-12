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
| `./lab.sh nautobot seed` | idempotent intent: roles `vpn-hub`/`vpn-spoke`, prefix roles (`oob-management`, `wan-p2p`, `vpn-tunnel`, `site-lan`, `loopback`), `Mgmt-vrf` on Gi1, **p2p WAN links as cables** between hub GiN and spoke Gi2 with /30 addresses (unwired ports disabled), Loopback0/Loopback10, **TunnelN on hub and spoke** with custom fields + relationships (below), config context `c8000v-ipsec` (crypto suite, OOB, domain), AS 65200/65201/65202, routing instances and **eBGP peerings** over the tunnel addresses, `bgp:advertise` tags, saved GraphQL query `nac-c8000v-ipsec-model` |
| `./lab.sh nautobot render [--check]` | regenerates `nac/data/devices.nac.yaml` from the saved query (`--check` diffs only) |
| `./lab.sh nautobot golden` | Golden Config setting `c8000v-ipsec` (scope = location), template `c8000v-ipsec.j2` in Gitea, `wan-interface` feature, then backup → intended → compliance |
| `./lab.sh nautobot token` | API token |

## How the VPN is modelled

The tunnels are objects: the `TunnelN` interface on each router carries the
encapsulation and protection, and two relationships say where it is sourced and
who the other end is. Nothing about the topology is hard-coded in the renderer or
in the Golden Config template.

| Element | Nautobot | Renders |
|---|---|---|
| encapsulation | custom field `tunnel_mode` = `ipsec-ipv4` | `tunnel mode ipsec ipv4` |
| protection | custom field `tunnel_ipsec_profile` = `VPN-IPSEC` | `tunnel protection ipsec profile VPN-IPSEC` |
| tunnel address | IP address on the interface, prefix role `vpn-tunnel` | `ip address 172.17.N.x 255.255.255.252` |
| source | relationship **`tunnel_source`**: TunnelN → GiN (one-to-many) | `tunnel source GigabitEthernetN` |
| destination | relationship **`tunnel_peer`**: hub TunnelN ↔ spoke TunnelN (symmetric one-to-one) — the destination is *derived* by following the peer's own `tunnel_source` to its WAN address | `tunnel destination 100.65.N.x` |
| WAN link | cable GiN ↔ Gi2, prefix role `wan-p2p`, interface `enabled` | `interface GigabitEthernetN` with address / `cdp enable`, unused ports `shutdown` |
| IKEv2/IPsec suite | config context **`crypto`** (proposal, policy, keyring peer, profile, transform-set, IPsec profile — names and algorithms, no secrets) | the NAC `crypto:` model; the pre-shared key stays in `device_groups.nac.yaml` |
| BGP | nautobot-bgp-models: one `AutonomousSystem` per site, routing instance per router (router-id = Loopback0), peering hub↔spoke with endpoints on the tunnel IPs; `remote-as` = the peer endpoint's AS | complete `router bgp` block, `network` statements from prefixes tagged `bgp:advertise` |

GraphiQL: `rel_tunnel_peer { device { name } rel_tunnel_source_source { ip_addresses { address } } }`
on an interface gives you the far end and its tunnel-destination address in one query
(the saved query *nac-c8000v-ipsec-model* is in Extensibility → GraphQL Queries).

Round trip verified: after `render`, `terraform plan` reports *No changes*; test
`06_nautobot` fails if the committed file drifts from Nautobot, and checks that every
router's `tunnel destination` equals its peer's tunnel-source address in the model.

Golden Config: 16 features shared with the other labs plus `wan-interface`
(`interface GigabitEthernet2` / `3`) — **51/51 compliant**. The shared SoT query
`golden-config-lab` was extended with `rel_tunnel_peer` so the template can
render the destination.

Gotcha found while seeding: pynautobot diffs an `update()` against the record as
first fetched, so two updates of the same field in one run (e.g. `enabled` False
then True) silently drop the second — `seed.py` therefore decides the wired state
before creating the port.
