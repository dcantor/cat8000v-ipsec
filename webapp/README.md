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

**Capacity constraints**: two modelled per headend plus one live, and the aggregate is the tightest of them.

1. *Tunnels*: each headend may terminate at most *N* tunnels (default 50), stored in Nautobot as the
   custom field `vpn_tunnel_capacity` on the hub device (seeded from `capacity.tunnels_per_headend`).
2. *Firewall bandwidth*: the VyOS firewall in front of the headend carries a static `bandwidth_mbps`
   (intent → custom field `firewall_bandwidth_mbps` on the firewall device; fw-east 40, fw-central 50,
   fw-west 90). Every tunnel commits `capacity.bandwidth_per_tunnel_mbps` (8, stored in the VPN's
   `extra_attributes`), so a firewall bounds the headend at `bandwidth_mbps // 8` tunnels.

3. *CPU* (live): the headend's control-plane CPU from `show platform resources`, measured against the
   platform's own warning threshold (80 %); QFP data-plane CPU and DRAM are shown next to it. It joins the
   aggregate utilisation, and a headend at or above the threshold reports no free slots.

The page shows four bars per headend (tunnels, firewall bandwidth, CPU, aggregate) plus which constraint is
binding and the effective free slots; the wizard uses the effective number, `spokes.validate` and
`intent.validate` refuse a spoke that would overrun either constraint. The computation lives in
`intent.headend_capacity()` and is mirrored by `inventory.py` from the Nautobot data (test 07 checks they agree).

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

### Multiple headends

Any number of hub-role routers can exist; every tunnel is a (hub, spoke) pair with its own link, /30s and
TunnelN number (the same number at both ends). Step 1 of the wizard has **Connect to headend(s)**
checkboxes (**at least two** — every spoke gets redundant headends; enforced in the UI and by the API); step 2 then shows one addressing row per selected hub and the
review one "coordinated configuration" box per hub. Spokes have `SPOKE_PORTS` (2) WAN ports, one per hub.

A new hub is provisioned with `POST /api/runs {"mode":"hub","hub":<GET /api/hubs/suggest>}`: VM → bootstrap →
onboarding → one link + tunnel to every existing spoke (each spoke is re-defined and rebooted once for its new
WAN port) → the normal pipeline. Routing between spokes then has one path per hub (eBGP picks the hub with the
lowest router-id, the other is the backup); every hub is a headend with its own 50-tunnel capacity.

## Remove spoke (Routers table → *Remove…*)

Decommissions a spoke and cleans up the hub. The dialog shows the plan (what is released on the spoke,
what is removed from the hub, capacity after) and whether to keep the VM disk. The run (mode `remove`):

1. validate (must be a spoke known to the intent and to `lab.conf`)
2. power the VM off (`./lab.sh down`)
3. Nautobot clean-up: BGP peering + routing instance, VPN tunnel + both endpoints, the hub's TunnelN interface and
   address, the device (interfaces, cable), every address in its WAN/tunnel/LAN/loopback prefixes, the prefixes, its AS
4. drop it from `lab.conf` and `lab-intent.json`
5. seed → render (the hub's port becomes an explicitly *shut* NAC interface)
6. `terraform state rm` of the spoke's resources (the router no longer exists — nothing to destroy there)
7. plan/apply: Terraform **destroys the hub's TunnelN, BGP neighbour and WAN address** (the VTIs are native
   `iosxe_interface_tunnel` resources now, so destroy really removes them)
8. delete the VM (and, by default, its disk and `nodes/<spoke>/`)
9. Golden Config and tests

Every step is idempotent, so a failed run can simply be started again.

## Platform notes learned the hard way

- A C8000v's serial number follows the VM UUID: `lab.sh` gives every domain a deterministic UUID
  (`uuidgen --sha1`) so rebuilding a domain keeps the serial; onboarding refreshes serials over SSH anyway.
- After an interface deletion or a reload IOS-XE re-syncs its YANG datastore and elides default values
  (`ip ssh version 2`, vty `exec-timeout 10 0`, the transform-set key size…). Default-valued attributes were
  removed from the NAC baseline, and the apply step re-plans and re-asserts once if drift remains.

### Per-spoke actions: Rotate PSK

Every spoke row on the Provision page has **Rotate PSK…** next to **Remove…**. The dialog shows the current key's
fingerprint and rotation date, the tunnels and headends involved, and takes an optional chosen key (else a 24-character one
is generated). The run (`mode: rotate`, `POST /api/runs` with `spoke: {name, psk?}`; plan with `GET /api/spokes/{name}/rotation`):

1. validate — the spoke, its tunnels, its headends
2. new key → `lab-intent.json` (with `psk_rotated`); the key is never logged
3. Nautobot seed — the key stays out of Nautobot; each of the spoke's VPN tunnels gets the custom fields `psk_fingerprint`
   (sha256, first 12 hex) and `psk_rotated`, so the model records which key generation runs
4. NaC render (the key is a group variable) → terraform plan / apply on the spoke **and every headend's keyring**, saved
5. re-key: `clear crypto ikev2 sa` on the spoke, so the tunnels re-authenticate with the new key now instead of at SA lifetime
6. verify: every tunnel of the spoke back with IKEv2 READY on its headend and eBGP Established, within 4 minutes — else the run
   fails (the old key is gone, so this is loud on purpose)
7. Golden Config backup / compliance (default on); the Robot suites optional (default off)

Measured: 4 min 23 s for a spoke with three headends; each tunnel is down for a few seconds.

### Login, roles, audit

The portal requires a sign-in (`auth.py`). Users are local — `users.json` (salted scrypt hashes; not committed) managed with
`python3 auth.py add NAME --role viewer|operator|approver`, `del`, `list`, `token NAME` (a bearer token for machine access,
`Authorization: Bearer …`, same role). Lab defaults: **admin / admin** (approver), **operator / operator**, **viewer / viewer**.
A sign-in sets a signed session cookie (12 h; the secret is generated on first start in `.secret`). Roles are ordered:

| role | may |
|---|---|
| viewer | read everything: inventory, runs, tools (with the lab credentials), audit |
| operator | + start and resume runs that build or change: deploy, plan, test, spoke, hub, rotate, rehome; manage the intent |
| approver | + the destructive run (**remove** a spoke) and user management (`/api/users`) |

What stays open without a login: `/metrics` and `/api/sd` (Prometheus), `GET /api/vpn-inventory` and `GET /api/runs*` (the lab
hub and the Robot suites poll them), `/api/intent`, `/api/cities`, the static files and `/docs`. Every other request answers 401
(the page then shows the sign-in dialog) or 403 with the role it needs; the page disables what the signed-in role may not do.

The **audit trail** (`runs/audit.jsonl`, append-only, `GET /api/audit`, the Audit tab) records logins (and failed ones),
sign-outs, every write request — who, from where, method and path, the run mode, the spec with secrets redacted (a PSK
becomes its fingerprint), the options, the HTTP result and the run id it produced — and every denied request with the role it
lacked. A run record also carries `user`, the person who started it; a resume keeps that and is itself audited.

OIDC: the middleware only needs `request.state.user = {name, role}`; an OIDC login (e.g. authlib with the provider's
callback) would set the same session cookie and map groups to the three roles — nothing else changes.

### Per-spoke actions: Re-home

**Re-home…** on a spoke row changes the set of headends the branch connects to — e.g. after capacity moved. The dialog lists every
headend with its region, tunnels, bandwidth and free slots (the current ones ticked); ticking / unticking shows the plan
(`GET /api/spokes/{name}/rehome?hubs=a,b`): for a headend to **add**, the allocation (the spoke's next free WAN port, the
firewall's / hub's next free port, WAN and tunnel /30s, tunnel id, capacity after); for one to **drop**, what is released.
At least two headends must remain. The run (`mode: rehome`, `spoke: {name, hubs}`):

1. validate — headends exist, capacity and free ports for the additions, allocations made
2. intent + `lab.conf` — new links / tunnels appended, dropped ones removed (the spoke stays; `lab.conf` first, the intent
   validator checks the wiring there)
3. Nautobot clean-up of dropped links — peering, VPN tunnel and endpoints, both TunnelN interfaces and addresses, WAN
   addresses and cable, the two /30 prefixes
4. **only when a headend is added**: the spoke VM is redefined with the new WAN NIC pair and rebooted (≈5 minutes; every tunnel
   of the spoke is down meanwhile). Dropping a headend never touches the VM.
5. seed → render → firewalls (the firewall port gains / loses its address and policy) → terraform plan / apply: tunnels, WAN
   interfaces and eBGP created on the new hub and the spoke, destroyed on the dropped one
6. verify — every new tunnel IKEv2 READY with eBGP Established on its headend, no SA left on a dropped headend (5-minute limit)
7. Golden Config (default on); Robot suites optional (default off). Resumable at any step.

Measured: drop east from spoke2 — 6 min, no reboot, 11 Nautobot objects and 11 terraform resources removed; add east to spoke4
— 13 min including the reboot, Tunnel12 up on east-headend.

### Firewalls page

The **Firewalls** tab (`GET /api/firewalls?hours=3&refresh=`) shows, per VyOS firewall (the one in front of each headend):
its interfaces (address, state, description — which spoke each port faces), the live **forward filter** rule set as
`show firewall` prints it (rule, action, protocol, packet and byte counters, match conditions) joined with the rule
descriptions from the configuration, and the **firewall log** (`show log firewall`) for the last 1 h – 3 days: every entry
parsed into rule, verdict, in → out interface, source and destination (resolved to the lab's device names from the intent's
links, tunnels and loopbacks), protocol, ports and TCP flags — grouped by flow with hit counts first, every entry underneath.
Collected over SSH from all firewalls in parallel, cached for 60 s; Refresh collects again. Rule 900 is the "log everything
else" drop, so the log is the list of what the policy refused (e.g. the suites' SSH probe from a spoke to its headend).

### Tools page

The **Tools** tab (`GET /api/tools`) lists every shared service with its LAN URL and login (hub, both portals, Nautobot,
Grafana and the IPsec dashboard, Prometheus, VictoriaMetrics, VictoriaLogs, Gitea, GitHub) and, below, how to reach every
router and firewall of the lab: management IP, the SSH command, username / password, RESTCONF / NETCONF for the C8000v,
the serial console (`./lab.sh console <node>` or the raw TCP port on the host). The device list comes from
`lab-intent.json` + `lab.conf`, so a spoke added or removed through the portal shows up at once. The page opens with a
"lab infrastructure — not production" disclaimer: the credentials are the lab defaults (`IOSXE_USERNAME/PASSWORD`,
`VYOS_USERNAME/PASSWORD`, admin/admin and vyos/vyos unless overridden) and are shown for exactly that reason.

### Topology map

The Inventory page starts with a rendered topology in one of two views:

- **map (USA)** — the default: the continental US (state outlines from [us-atlas](https://github.com/topojson/us-atlas),
  pre-projected by `tools/build_usa_map.py` into `static/usa-map.json` with the Albers parameters of d3's `geoAlbersUsa`),
  hubs at their headend cities and spokes at their branches. The position is the Nautobot **Location latitude /
  longitude** (seeded from `city` / `lat` / `lon` on the device in `lab-intent.json`; the city goes into the location's
  description), projected in the browser with the same formula. A site without coordinates (a spoke added through the
  portal before a city was given) is placed approximately in its region and marked "(approx.)". Firewalls are the small
  square beside their hub.
- **schematic** — hub-role routers on the top row, firewalls under them, spokes below, grouped by region.

Both views draw one curved line per IPsec tunnel coloured by live health (green up / amber degraded / red down / grey
no data); hovering a line shows ports, addresses, IKE/VTI/BGP state and ESP counters, clicking a node or a line opens
the object in Nautobot. The **Add spoke** wizard asks for the **city** (a catalogue of US cities, `GET /api/cities`, fills the
coordinates; any other name takes lat / lon typed in); the suggestion picks an unused city of the chosen region, validation
refuses a spoke without one, the run writes it into `lab-intent.json` and the seed into the Nautobot location — so the new
spoke appears on the map at its city as soon as the run's Nautobot step is done. The **spoke filter** (one chip per spoke, plus *all* / *none*) hides spokes and their tunnels
in either view and is remembered per browser. Plain SVG generated in the browser from `GET /api/vpn-inventory`.

### Resuming runs

A failed or interrupted run (the portal was restarted while it ran — runs found "running" at start-up are
marked *interrupted*) shows **Resume from the failed step**: a new run keeps the successful steps and redoes
the rest (`POST /api/runs/<id>/resume`). Use `webapp/restart.sh` to restart the service — it refuses while a
run is in progress.

### Renaming a router

`./lab.sh rename OLD NEW` (VM stopped): renames the libvirt domain, `nodes/<name>/`, every `lab.conf` entry,
the intent, and the Terraform state (`state mv` + the `device` attribute inside each resource), then
`./lab.sh rebuild NEW && ./lab.sh up NEW` (the day-0 ISO re-applies the hostname at boot), `./lab.sh nautobot seed`
(devices are matched by management IP, so the Nautobot device is renamed in place), render, `nac apply`, and
`./lab.sh nautobot onboard <ip>` to refresh the serial. VM UUIDs (→ C8000v serials) are derived from the
management IP so a rename does not change the serial after the one-time rebuild.
