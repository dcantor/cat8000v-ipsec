# Catalyst 8000v IPsec VTI + eBGP lab (libvirt/KVM)

Headends and spokes on Cisco Catalyst 8000v (17.15.06) — initially one hub and two spokes, grown
from the portal to three headends (east/central/west) and five spokes — joined by **static point-to-point IPsec VTIs** (`tunnel mode ipsec ipv4`, IKEv2 with pre-shared key)
and **eBGP, one AS per site**. Built and configured as code: libvirt VMs (`lab.sh`),
Cisco Network-as-Code / Terraform (`nac/`), Robot Framework validation (`tests/`),
and modelled in the shared Nautobot (`nautobot/`).

```
 host 10.2.0.1 ══════════ ipsec-oob  10.2.0.0/24  (OOB management, Mgmt-vrf on Gi1) ═════════
                 │ .11                        │ .12                         │ .13
             ┌───┴───┐                    ┌───┴───┐                     ┌───┴───┐
             │  hub  │ AS 65200           │spoke1 │ AS 65201            │spoke2 │ AS 65202
             │ Lo10 192.168.11.1/24       │ Lo10 192.168.12.1/24        │ Lo10 192.168.13.1/24
             └─┬───┬─┘                    └───┬───┘                     └───┬───┘
        Gi2 .1 │   │ Gi3 .1              Gi2 .2                        Gi2 .2
   100.65.1.0/30   100.65.2.0/30  ┐          │                             │
               └───│──────────────┼──────────┘  p2p WAN link (UDP tunnel)  │
                   └──────────────┴────────────────────────────────────────┘

   Tunnel1  hub 172.17.1.1 ═══ IPsec VTI (IKEv2 PSK, AES-256/SHA256/G14) ═══ 172.17.1.2 spoke1
   Tunnel2  hub 172.17.2.1 ═══ IPsec VTI                                  ═══ 172.17.2.2 spoke2
   routing: eBGP over the tunnel addresses; each site originates its LAN and loopback;
            spoke↔spoke traffic transits the hub (AS path 65200 65202 / 65200 65201)
```

## Quick start

The **VPN provisioning portal** (http://192.168.50.231:8090, [webapp/README.md](webapp/README.md))
does all of the below from a web form: edit site / router / tunnel / crypto metadata, press
*Deploy*, watch Nautobot → NAC → Terraform → tests run, read the test report; the *Inventory*
page reports every tunnel against the headend capacity (50), and the *Add spoke* wizard /
*Remove* action provision or decommission spoke VMs with the hub configured in the same run.

```bash
./lab.sh up               # define networks + routers, start them
./lab.sh bootstrap        # first boot only: day-0, SSH keys, license level (auto-reload), RESTCONF (~6 min)
./lab.sh nautobot onboard && ./lab.sh nautobot seed && ./lab.sh nautobot render
./lab.sh nac init && ./lab.sh nac apply -parallelism=1   # push the model rendered from Nautobot
./lab.sh nautobot golden  # Golden Config backup / intended / compliance
./lab.sh test             # 26 Robot tests -> results/<date>_<time>/
./lab.sh ssh spoke1       # admin / admin
./lab.sh console hub      # serial console (exit: Ctrl-] then q)
./lab.sh down
```

## What is where

| Path | Purpose |
|---|---|
| `lab.conf` | inventory: roles, OOB IPs, AS numbers, LANs, p2p links (`LINKS`), tunnels (`TUNNELS`), console ports |
| `lab.sh` | libvirt controller: `up down status console ssh bootstrap wait log nac test nautobot rebuild clean` |
| `networks/ipsec-oob.xml` | libvirt OOB network (host = 10.2.0.1); the WAN links are libvirt UDP tunnels between VM NICs, no bridge |
| `nodes/<r>/iosxe_config.txt` | day-0 (CVAC ISO): hostname, Mgmt-vrf + Gi1, AAA, SSH, NETCONF/RESTCONF, `license boot level network-advantage addon dna-advantage` |
| `nac/data/global.nac.yaml` | baseline: domain, SSH/AAA/VTY hardening, management ACL, banner |
| `nac/data/device_groups.nac.yaml` | group `IPSEC_VPN`: only the pre-shared key (`vpn_psk`) |
| `nac/data/devices.nac.yaml` | **GENERATED from Nautobot**: WAN interfaces, loopbacks, VTI templates, crypto suite, full eBGP block per router |
| `nautobot/` | onboarding, seed, renderer, Golden Config setup + `c8000v-ipsec.j2`, saved GraphQL query `nac-c8000v-ipsec-model` |
| `lab-intent.json` | the VPN service intent (site, hostnames, metadata, tunnels, crypto, PSK) — created from `lab.conf` by `./lab.sh intent init`, edited by the portal, read by seed/render/tests |
| `webapp/` | VPN provisioning portal: FastAPI backend + single-page UI (`./lab.sh webapp`, systemd user unit) |
| `tests/suites/` | `01_management`, `02_underlay`, `03_ipsec_vti`, `04_routing`, `05_nac_compliance`, `06_nautobot` |
| `results/` | one folder per run: `configs/pre-run`, `configs/post-run`, diff, Robot report/log; `results/latest` symlink |

## Nautobot

Modelled in the shared Nautobot of the cat9000v lab (http://10.0.0.10:8080,
from the LAN http://192.168.50.231:8080, `admin`/`admin`); the NMS has a fourth
NIC on `ipsec-oob` (10.2.0.10). The VPN is modelled in Nautobot's **core VPN app**
(VPN → tunnels → hub/spoke endpoints, profile with Phase 1/2 policies) and BGP in
nautobot-bgp-models; see [nautobot/README.md](nautobot/README.md) for the mapping
and how `devices.nac.yaml` is rendered from it.

## Design notes

- **VTI, not DMVPN**: each tunnel is a plain point-to-point `Tunnel` with `tunnel
  destination` and `tunnel mode ipsec ipv4` — no GRE, no NHRP. The IPsec SA
  selector is any/any; routing decides what is encrypted.
- **Dedicated WAN links**: the hub has one p2p /30 to each spoke (Gi2 → spoke1,
  Gi3 → spoke2); the spokes cannot reach each other's WAN address, so all
  spoke-to-spoke traffic goes hub-and-spoke through the tunnels (test `04_routing`
  proves the traceroute hops hub-tunnel → spoke-tunnel).
- **eBGP**: hub 65200, spoke1 65201, spoke2 65202; neighbours over the tunnel /30s,
  `network` statements for Loopback0 (/32 with mask) and the LAN (classful /24),
  no route reflection needed. `log-neighbor-changes`, router-id = Loopback0.
- **Crypto**: IKEv2 proposal AES-CBC-256 / SHA256 / group 14, keyring `VPN-KEYRING`
  (any peer, PSK), profile `VPN-IKEV2` (DPD 30/5 on-demand), transform-set `VPN-TS`
  (esp-aes 256, esp-sha256-hmac), IPsec profile `VPN-IPSEC`. The suite is a VPN
  Profile with Phase 1 / Phase 2 policies in Nautobot's core VPN app; only the PSK
  lives in NAC data.
- **NAC quirks** (same as the DMVPN lab): provider `CiscoDevNet/iosxe` 0.15 over
  RESTCONF, `save_config=false` + a `cisco-ia:save-config` RPC from `lab.sh nac`,
  VTIs as native `interfaces.tunnels` (only `ip tcp adjust-mss` needs a CLI template),
  `cdp: true` on the C8000v ethernets, `-parallelism=1` to avoid 409 lock races,
  unwired hub ports rendered as explicit `shutdown` so Terraform owns their state.
- **Golden Config**: 17 compliance features (`wan-interface` added by this lab) —
  51/51 compliant; the template renders unused Gi ports as `shutdown` too.
