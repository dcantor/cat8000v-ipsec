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
