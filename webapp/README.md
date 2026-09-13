# VPN Provisioning Portal

A small web app on the lab host that lets a user describe the IPsec VPN service in a form and
press **Deploy** — behind the scenes it drives Nautobot, Network-as-Code (Terraform) and the
Robot Framework tests, and shows the progress and the test report.

```
./lab.sh webapp            # http://<host>:8090  (also reachable from the LAN at http://192.168.50.231:8090)
```

```
 browser form ──POST /api/runs──▶ FastAPI (webapp/app.py) ──▶ pipeline (one run at a time, background thread)
                                        │
   1. validate intent (nautobot/intent.py)           shape, addressing, links == physical wiring
   2. save lab-intent.json                          the document every other tool reads
   3. ./lab.sh nautobot seed                        Nautobot = source of truth (devices, links, VPN app objects, BGP, metadata)
   4. ./lab.sh nautobot render                      nac/data/devices.nac.yaml (+ PSK group) rendered from Nautobot
   5. ./lab.sh nac plan                             terraform plan  (-detailed-exitcode)
   6. ./lab.sh nac apply                            terraform apply + copy running startup   (skipped when the plan is empty)
   7. ./lab.sh nautobot golden                      Golden Config backup → intended → compliance (optional)
   8. ./lab.sh test                                 Robot Framework, results/<date>_<time>/ (optional)
                                        │
 browser polls GET /api/runs/<id> ◀─────┘  step status · live log · parsed test report (+ links to report.html/log.html/config backups)
```

## What the form edits

| Section | Fields | Lands in |
|---|---|---|
| Site | site code, contact, description | Nautobot location (custom fields `site_code`, `contact`, description) |
| Routers | hostname, AS number, router-id, site LAN, comments (mgmt IP and role are read-only: they come from the VM / wiring) | device name/role/comments, Loopback0/10 + prefixes, BGP AS / routing instance |
| VPN service | name, change ticket, owner, description; per spoke: WAN /30, tunnel id, tunnel /30 (ports read-only) | core VPN app: VPN (`extra_attributes` for ticket/owner), VPN Tunnels, endpoints; cables/prefixes/IPs; eBGP peerings |
| Crypto profile | IKEv2 encryption/integrity/DH/lifetime, ESP encryption/integrity/lifetime, DPD, Cisco object names, **PSK** | Phase 1 / Phase 2 policies + VPN Profile; the PSK only goes to `nac/data/device_groups.nac.yaml` |

Buttons: **Deploy configuration** (full pipeline), **Dry run** (through `terraform plan`, nothing is
pushed), **Run tests only**. Runs are kept in `webapp/runs/<id>.json` (+ the intent that was deployed).

## Files

| Path | Purpose |
|---|---|
| `webapp/app.py` | FastAPI app: `/api/intent`, `/api/inventory`, `/api/validate`, `/api/runs`, `/results/…` (static test reports) |
| `webapp/static/index.html` | the single-page form / status / report UI (no build step) |
| `lab-intent.json` | the intent document (`./lab.sh intent init` creates it from `lab.conf`; the portal overwrites it) |
| `nautobot/intent.py` | load/save/validate the intent, physical-wiring facts from `lab.conf` |

Limits by design: the routers themselves (VM names, management addresses, which ports are cabled)
are fixed by `lab.conf`/libvirt — the portal validates that the links in the form match the wiring.
Renaming a router is allowed (Nautobot devices are matched by management IP) but Terraform then
re-creates that router's resources under the new name.

## Running it as a service

`webapp/lab-webapp.service` is a systemd *user* unit (installed in `~/.config/systemd/user/`,
enabled with `systemctl --user enable --now lab-webapp`; the user has lingering enabled so it
starts at boot). Logs: `journalctl --user -u lab-webapp -f`.

## Inventory page (`#inventory`)

Reporting view of every VPN tunnel — the model from Nautobot's VPN app joined with live state
collected over SSH from each **headend** (hub): IKEv2 SA status and age, VTI line protocol, eBGP
session state / prefixes / up-time, ESP encaps/decaps/error counters, interface rates and last I/O,
plus protected prefixes, crypto profile, change ticket and owner. Health = IKE READY + VTI up +
BGP Established.

**Capacity constraint**: each headend may terminate at most *N* tunnels (default 50). *N* is stored
in Nautobot as the custom field `vpn_tunnel_capacity` on the hub device (seeded from
`capacity.tunnels_per_headend` in the intent); the page shows used / free / utilisation per headend
and the deploy pipeline refuses an intent that exceeds it.

Live data is cached for 30 s; *Refresh live data* re-collects. *Export CSV* downloads the table
(`GET /api/vpn-inventory.csv`; JSON at `GET /api/vpn-inventory`).

## Add-spoke wizard (Provision → *＋ Add spoke…*)

Guided flow to connect a **new spoke router** to the hub. Everything is auto-allocated and shown as
*suggested* (editable, re-validated on every step):

| Step | What the user sees |
|---|---|
| 1 · Identity & metadata | hostname (`spokeN`), management IP (next free in the OOB /24), site / site code / contact (from the site), change ticket, comments |
| 2 · Addressing | hub port (lowest free of Gi2–Gi9 on the hub), WAN p2p /30 (`100.65.N.0/30`), tunnel number (next id), tunnel /30 (`172.17.N.0/30`), router-id (`10.255.1.N`), site LAN (`192.168.N.0/24`), AS number (next after the hub's) — plus the headend capacity check |
| 3 · Review | side by side: what the spoke gets and what the **hub** gets (WAN interface + address, TunnelN + destination, eBGP neighbour, Nautobot cable/tunnel/peering, capacity after) |

*Provision spoke* starts a run (mode `spoke`) with these steps before the normal pipeline:

1. validate the allocation (free hub port, unused prefixes/ids/AS, capacity, free host memory)
2. register the spoke in `lab.conf` (roles, mgmt IP, AS, LAN, console port, node index, `LINKS`, `TUNNELS`) and write `nodes/<spoke>/iosxe_config.txt` from `nodes/_template/`
3. `./lab.sh up <spoke>` — overlay disk, day-0 ISO, libvirt domain, boot
4. `./lab.sh bootstrap <spoke>` — day-0 via console, SSH keys, license boot level (reload), RESTCONF (6–10 min)
5. `./lab.sh nautobot onboard <ip>` — Sync Devices From Network
6. add the device, the hub↔spoke link and the tunnel to `lab-intent.json`
7. seed → render → plan → apply → Golden Config → tests, exactly as for *Deploy* — the hub's new WAN port, TunnelN and BGP neighbour come out of the same Nautobot model, so **hub and spoke are configured in one Terraform apply**.

Why the hub never needs a reboot: the hub VM has 8 spoke-facing ports (`HUB_PORTS` in `lab.conf`) and each
link's UDP socket pair is anchored on the hub side (`port_local`/`port_far` in `lab.sh`), so a new spoke only
has to point at the hub's existing port.

`lab.conf` stays the truth for VM facts (names, management IPs, console ports, wiring); the AS/LAN columns
there only seed the intent — after the portal has edited the intent, `lab-intent.json` wins.
