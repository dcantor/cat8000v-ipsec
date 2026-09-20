# Catalyst 8000v IPsec VTI + eBGP lab — with a VPN provisioning portal

A hub-and-spoke IPsec VPN built and operated **entirely as code**: Cisco Catalyst 8000v routers on
libvirt/KVM, **Nautobot as the source of truth**, **Cisco Network-as-Code (Terraform)** for delivery,
**Robot Framework** for proof, and a **web portal** that provisions spokes and headends end to end.

It started as one hub and two spokes; everything since — a third, fourth and fifth spoke, a second and
third headend, renames, per-spoke keys, a site hierarchy — was done through the portal, and the lab is
the state the portal left it in.

```
                    east-headend            central-headend          west-headend
   headends         AS 65200 · East         AS 65204 · Central       AS 65206 · West
                    Gi2 = WAN 100.64.1.2    Gi2 = WAN 100.64.2.2     Gi2 = WAN 100.64.3.2
                        │ eth1                  │ eth1                   │ eth1
   firewalls        fw-east (VyOS)          fw-central (VyOS)        fw-west (VyOS)
   (one per hub)    forward filter: only IKEv2 udp/500+4500, ESP, ICMP and established/related cross; rest dropped + logged
                        │ eth2..                │ eth2..                 │ eth2..
   13 IPsec VTIs        │ │ │   one p2p /30 link per (firewall, spoke); one TunnelN per (headend, spoke) through the firewall
                        │ │ │                  │ │ │ │ │                │ │ │ │ │
   spokes           spoke1 (East)  spoke2 (Central)  spoke3 (West)  spoke4 (Central)  spoke5 (West)
                    → all three    → all three       → all three    → central + west  → central + west
                    AS 65201       AS 65202          AS 65203       AS 65205          AS 65207

   OOB: 10.2.0.0/24 (Mgmt-vrf, Gi1) shared with the NMS (Nautobot) at 10.2.0.10 · host 10.2.0.1
   crypto: IKEv2 AES-256-CBC / SHA256 / DH14, ESP AES-256-CBC / SHA256, DPD · one PSK per spoke
   routing: eBGP over the tunnel /30s, one AS per site; spoke↔spoke via a headend (lowest router-id wins)
```

## Quick start

```bash
./lab.sh up && ./lab.sh bootstrap        # VMs (first boot: day-0, license reload, RESTCONF ≈ 6 min each)
./lab.sh nautobot onboard && ./lab.sh nautobot seed && ./lab.sh nautobot render
./lab.sh nac init && ./lab.sh nac apply -parallelism=1
./lab.sh nautobot golden                 # Golden Config: backup → intended → compliance
./lab.sh test                            # 27 Robot tests → results/<date>_<time>/
./lab.sh webapp                          # the portal on :8090 (or the systemd user unit, see below)
```

Everyday operation happens in the portal: **http://192.168.50.231:8090** (LAN) / http://localhost:8090.
Nautobot: **http://192.168.50.231:8080** (admin / admin).

### The firewalls
Each headend sits behind a **VyOS** firewall (1 vCPU / 1 GB, built once from the rolling ISO by
`tools/vyos_install.py` into `images/vyos-base.qcow2`, overlays per node, day-0 over the serial console).
The headend's single WAN interface faces its firewall; every spoke link terminates on the firewall's
eth2–eth8; static routes on both sides go through it (rendered from Nautobot like everything else). The
firewalls are Nautobot devices too (platform `vyos`, cables, addresses) and their configuration —
interfaces plus the forward-filter policy from the config context — is rendered and pushed by
`nautobot/render_vyos.py` (`./lab.sh nautobot vyos [--check]`) as a pipeline step before Terraform.
Robot suite 07 proves they filter: ESP counters move, and an SSH attempt from a spoke to a headend is dropped.

## The VPN provisioning portal

One form, one button, a source of truth kept honest. Every change goes
**intent → Nautobot seed → NAC data rendered *from Nautobot* → Terraform plan/apply → Golden Config → Robot tests**,
and the portal streams each step's status and log.

![Provision page](docs/screenshots/portal-provision.png)

### Provision page
- **Site / Routers / VPN service / Crypto profile** — the whole intent is a form: site metadata, every
  router (hostname, region, branch site, AS, router-id, LAN, **its own pre-shared key** for spokes,
  comments), the VPN service (name, change ticket, owner) and its tunnels, the IKEv2/IPsec suite.
- **Deploy configuration**, **Dry run** (through `terraform plan`, nothing pushed), **Run tests only**.
- **Deployment status**: steps with results, live log, parsed test report with links to the Robot
  report, log, per-router config backups and the pre/post diff. Runs are kept and a failed or
  interrupted run can be **resumed from the failed step**.

![Deployment status](docs/screenshots/portal-run.png)

### Add a spoke — guided wizard
1. **Identity & metadata** — hostname, management IP, **region** (picks the nearest headends), branch
   site, site code, contact, generated PSK, change ticket; **Connect to headends** (at least two).
2. **Addressing, all auto-suggested** — per selected headend: hub port, spoke port, WAN /30, tunnel
   number, tunnel /30; plus router-id, LAN, AS. Everything is editable and re-validated.
3. **Review** — what the spoke gets and what **each headend** gets (WAN interface + address, TunnelN
   + destination, eBGP neighbour, Nautobot cable / tunnel / peering, capacity after).

*Provision spoke* creates and boots the VM, bootstraps it, onboards it into Nautobot, adds it to the
intent, then runs the pipeline — **headends and the new spoke are configured in one Terraform apply**.

| Step 1 | Step 2 | Step 3 |
|---|---|---|
| ![](docs/screenshots/portal-wizard-1.png) | ![](docs/screenshots/portal-wizard-2.png) | ![](docs/screenshots/portal-wizard-3.png) |

### Add a headend / remove a spoke
- A new headend (`POST /api/runs {"mode":"hub"}`) is linked to every existing spoke — the run
  re-defines the spokes for their new WAN port, brings the headend up, and applies both sides.
- **Remove…** on a spoke shows exactly what is released and what every headend loses, then powers
  off, cleans Nautobot, drops the router from the intent / `lab.conf` / Terraform state, destroys the
  headend-side tunnel and BGP neighbour, deletes the VM, and re-tests.

![Remove spoke](docs/screenshots/portal-remove.png)

### Inventory page
KPIs, a **rendered topology** (headends on top, spokes grouped by region, one line per tunnel coloured
by live health, tooltips, links into Nautobot), **headend capacity** with two constraints per headend —
tunnels terminated (50, custom field `vpn_tunnel_capacity` on the hub) and the **bandwidth of the firewall
in front of it** (custom field `firewall_bandwidth_mbps`: fw-east 40, fw-central 50, fw-west 90 Mbps; every
tunnel commits `capacity.bandwidth_per_tunnel_mbps` = 8 Mbps) — plus the live **control-plane CPU** of each
headend (`show platform resources`, against the platform's warning threshold; data-plane QFP CPU and DRAM
alongside) — with an **aggregate** bar showing the tightest of the three and the effective free slots (the
model constraints set the slots, the wizard and deploy validation check them; a headend at its CPU threshold
has none), and a
per-tunnel report joining the Nautobot model with live IKEv2 / VTI / eBGP / ESP state collected from the
headends; **Export CSV** (tunnels plus a headend-capacity block).

![Inventory](docs/screenshots/portal-inventory.png)
![Topology](docs/screenshots/portal-topology.png)
![Headend capacity](docs/screenshots/portal-capacity.png)
![Tunnel report](docs/screenshots/portal-tunnels.png)

### REST API
Everything the UI does is an API call — typed and documented with Swagger at **`/docs`** (ReDoc at
`/redoc`): intent, inventory, spoke/headend suggestions and validation, removal plans, runs and resume.

![Swagger](docs/screenshots/portal-swagger.png)

### Demos and documentation
- `webapp/demo/portal-demo.mp4` / `.gif` — a 90-second tour of the portal (`webapp/demo/record.py` re-records it).
- `webapp/demo/nautobot-nac-demo.gif` — where the data lives in Nautobot and how NaC consumes it.
- **`docs/workflows.pdf`** — workflows, system-to-system data flows and decision trees, in detail
  (28 pages, 25 diagrams; source `docs/workflows.html`).
- `webapp/README.md` — portal internals, run modes, resuming, platform quirks.

### Monitoring (Prometheus + Grafana on the NMS)
The portal's `/metrics` is scraped by the shared monitoring stack ([lab-portal/monitoring](https://github.com/dcantor/lab-portal)).
Besides the VM / run gauges it exports the **live tunnel inventory** while the headends run: per tunnel `lab_tunnel_health`
(2 up = IKEv2 READY + VTI up + eBGP Established, 1 degraded, 0 down), IKE SA age, prefixes from the spoke, ESP encaps /
decaps / error counters and VTI rates; per headend tunnels modelled / up, capacity and free slots after every constraint,
utilisation of the binding constraint (`lab_headend_binding{binding=tunnels|bandwidth|cpu}`), control-plane / QFP CPU,
DRAM, IKE sessions, bandwidth committed vs the firewall's. The **C8000v IPsec overview** dashboard
(http://192.168.50.231:3001/d/cat8000v-ipsec-overview) draws all of it; alerts `TunnelDown`, `HeadendUnreachable`,
`HeadendCapacityExhausted` and `HeadendCpuHigh` fire only while the hubs run.

## Nautobot: the source of truth

Nothing about the topology is hard-coded in templates: the renderer and the Golden Config template
read everything from Nautobot objects (details in [nautobot/README.md](nautobot/README.md)).

| What | Where in Nautobot |
|---|---|
| Sites | location hierarchy **lab site → Region (East/Central/West) → Branch** (`east-hq`, `branch-1`…) with `site_code` / `contact` custom fields; regions are ordered so the wizard can pick the nearest headends |
| Routers | devices discovered by the Device Onboarding app (model, serial, platform, mgmt IP); roles `vpn-hub` / `vpn-spoke` / `vpn-firewall`; `vpn_tunnel_capacity` custom field on headends, `firewall_bandwidth_mbps` on firewalls |
| Physical | interfaces (spoke-facing ports, loopbacks, `TunnelN` of type *tunnel*), **cables** for the p2p WAN links, prefixes with roles (`wan-p2p`, `vpn-tunnel`, `site-lan`, `loopback`), `bgp:advertise` tags |
| VPN | the **core VPN app**: Phase 1 / Phase 2 policies → profile `VPN-IPSEC` → VPN `IPSEC_VPN` → one **VPN Tunnel per (headend, spoke)** with hub/spoke **endpoints** (source interface + address, tunnel interface, protected prefixes); Cisco object names in the profile's `extra_options` |
| Routing | nautobot-bgp-models: one AS per site, a routing instance per router, an eBGP peering per tunnel |
| Config | config context (OOB VRF/gateway/ACL, domain), the saved GraphQL query `nac-c8000v-ipsec-model`, Golden Config setting + Jinja template + compliance (136/136) |
| Not in Nautobot | pre-shared keys (one per spoke, in `lab-intent.json` → NAC variables) and device credentials (secrets group from NMS environment variables) |

| Devices at the lab location | Location hierarchy |
|---|---|
| ![](docs/screenshots/nautobot-devices.png) | ![](docs/screenshots/nautobot-locations.png) |

| The VPN service | Its tunnels |
|---|---|
| ![](docs/screenshots/nautobot-vpn.png) | ![](docs/screenshots/nautobot-tunnels.png) |

| A tunnel with its endpoints | The crypto profile (Phase 1 / Phase 2) |
|---|---|
| ![](docs/screenshots/nautobot-tunnel.png) | ![](docs/screenshots/nautobot-profile.png) |

| eBGP peerings | Golden Config compliance |
|---|---|
| ![](docs/screenshots/nautobot-bgp.png) | ![](docs/screenshots/nautobot-compliance.png) |

## Network-as-Code

- `nac/data/global.nac.yaml` — the hand-written baseline (AAA, SSH/VTY hardening, management ACL, banner).
- `nac/data/devices.nac.yaml` — **generated from Nautobot** by `nautobot/render_nac.py`: WAN
  interfaces (unused ports explicitly shut), loopbacks, **native VTI tunnel interfaces**, the crypto
  suite with **per-spoke keyring peers**, the full eBGP block per router.
- `nac/data/device_groups.nac.yaml` — generated: the `psk_<spoke>` variables (the only secret).
- Module `netascode/nac-iosxe` 0.1.0, provider `CiscoDevNet/iosxe` 0.15 over RESTCONF, `-parallelism=1`,
  `cisco-ia:save-config` after apply; crypto profiles are applied first on a new router and the apply
  step re-asserts once after an IOS-XE datastore re-sync (see `webapp/README.md`).

## Connecting to the SRv6 core (optional, currently detached)
Each headend's `GigabitEthernet3` can be cabled (a UDP link, like every other link here) to a PE of the
[srv6-core](https://github.com/dcantor/srv6-core) lab and runs eBGP to it inside that core's VRF *tenant-a*
(`172.19.n.0/30`, headend `.1`, PE `.2`, PE AS 65000). The headend announces its site LAN and the branch LANs it learns
over the tunnels; the core hands back the data-centre LANs, so every branch reaches every data-centre host through IPsec
→ headend → SRv6 → PE → CE → host. The attachment is **declared in the SRv6 lab** (`EXT_NODES` / `LINKS` in its
`lab.conf`) and **modelled on the headend by that lab's Nautobot seed** (Gi3 address, cable, BGP peering); this lab's
pipeline then renders and pushes it like anything else — `render_nac.py` turns the enabled, cabled Gi3 and the peering
into NaC data, `./lab.sh nac apply` configures the router, Golden Config stays compliant. Detaching is the reverse: the
SRv6 seed hands Gi3 back as unwired, and the next `render` / `nac apply` here removes the interface address and neighbour
(the routers are currently off, so that apply is pending for the next bring-up). The seed here treats a port
cabled to a device outside this lab as *foreign-wired* and never touches it. Test `04_routing` allows exactly one such
core session per headend; the end-to-end proof lives in the SRv6 lab's suite `12_interconnect`.

## Tests

`./lab.sh test` (or the portal) runs 32 Robot tests: management plane; underlay links and CDP; VTIs,
IKEv2 SAs and real encryption; eBGP sessions, prefixes and spoke↔spoke paths via a headend; **no
Terraform drift**; the firewalls (modelled, in sync with Nautobot, actually filtering); and the Nautobot model — devices and serials, cables, VPN objects (every router's
tunnel destination equals the far endpoint's source address), the location hierarchy, **per-spoke
keys on every router**, BGP model vs live sessions, rendered NAC data == committed, Golden Config
compliant. Each run keeps pre/post config backups and a diff under `results/`.

## What is where

| Path | Purpose |
|---|---|
| `lab.conf`, `lab.sh`, `tools/`, `nodes/` | VM facts and libvirt controller (`up down bootstrap rebuild clean rename status console ssh nac nautobot test intent webapp`), console automation, day-0 template |
| `lab-intent.json`, `nautobot/intent.py` | the VPN service intent (site, regions, devices + PSKs, links, tunnels, crypto, capacity); generated from `lab.conf` once, edited by the portal |
| `nautobot/` | onboarding, seed (intent → Nautobot, idempotent), renderer, Golden Config, rename tool, saved GraphQL query, Jinja template |
| `nac/` | Terraform root and NAC data |
| `tests/` | Robot suites 01–06, keyword library, `lab_vars.py` derived from the intent |
| `webapp/` | the portal (FastAPI + single-page UI), API schemas, spoke/headend provisioning, inventory collector, run records, demo recorders, `lab-webapp.service`, `restart.sh` |
| `docs/` | the workflows/decision-tree PDF and its source, screenshots |
| `results/` | one folder per test run |

The portal's run engine (steps, streamed log, resume, Robot reports) is the shared
[lab-portal](https://github.com/dcantor/lab-portal) package, which also serves the **lab hub** at
http://192.168.50.231:8088 — every lab on the host with its VMs, portal health, last tests and links.

## Running the portal as a service

`webapp/lab-webapp.service` is a systemd *user* unit (`systemctl --user enable --now lab-webapp`,
lingering enabled so it starts at boot). Restart with `webapp/restart.sh` — it refuses while a run is in
progress, because a restart interrupts the run (interrupted runs are marked and can be resumed).

## Design notes and quirks worth knowing

- **Links are anchored on the headend**: each headend has 8 spoke-facing ports and a link's UDP socket
  pair is derived from the headend side, so adding a spoke never touches a headend VM; adding a headend
  re-defines and reboots the spokes once (their new port). Spokes have 4 WAN ports (`SPOKE_PORTS`).
- **Serials follow the VM UUID** on a C8000v: domains get a deterministic UUID derived from the
  management IP, and onboarding refreshes serials over SSH anyway.
- **IOS-XE re-syncs its YANG datastore** after interface deletions or reloads and then elides default
  values — the NAC baseline avoids default-valued attributes and the pipeline converges with one extra
  apply when needed.
- **Nautobot 3.2.4 REST quirks** worked around in the seed: profile↔policy assignments 500 (done via
  `nbshell`), M2M fields absent from reads (verified via GraphQL, PATCHed directly), endpoint tunnel
  interfaces must be of type `tunnel`, deleting a device leaves a half-terminated cable.
- **Host sizing**: Ryzen 5 5600G (6c/12t), 57 GiB; eight C8000v (2 vCPU / 4 GiB) plus the NMS is
  the practical ceiling — first boots then exceed 15 minutes (bootstrap waits up to 30).
