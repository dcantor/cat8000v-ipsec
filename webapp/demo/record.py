#!/usr/bin/env python3
"""Record the portal demo: drives the real portal with Playwright (system Chrome), overlays captions, a cursor and highlight
rings, and writes demo/portal-demo.mp4 (H.264) + demo/portal-demo.gif (downscaled, for the README).
Scenes: sign-in (roles, SSO) -> Provision: intent form, the routers table and its day-2 actions (Change auth, Rotate PSK, Renew
cert, Re-home, Remove), the add-spoke wizard with the customer block, the run queue and a run's live status -> Inventory: KPIs,
topology, headend capacity, tunnel report, the LAN hosts' ping mesh (live) -> Branches: customers, ACME design patterns, filters
-> a router's page: customer box, tunnels, firewall rules, live show commands, configuration with the dark toggle and history
-> Firewalls -> Compliance: the report, a cell's detail with Remediate / Re-apply, the drift history, a real Golden Config run
-> Tools -> Audit -> dark mode -> the REST API.
Usage: record.py [--url http://localhost:8090] [--out demo/] [--no-runs]   (--no-runs skips the Golden Config run and the ping mesh)"""
import argparse, io, shutil, subprocess, tempfile, time
from pathlib import Path
from PIL import Image
from playwright.sync_api import sync_playwright

p = argparse.ArgumentParser(); p.add_argument("--url", default="http://localhost:8090"); p.add_argument("--out", default=str(Path(__file__).resolve().parent))
p.add_argument("--width", type=int, default=1400); p.add_argument("--height", type=int, default=860); p.add_argument("--no-runs", action="store_true", help="start nothing on the lab (no Golden Config run, no ping mesh)")
p.add_argument("--user", default="admin"); p.add_argument("--password", default="admin")
a = p.parse_args(); OUT = Path(a.out); OUT.mkdir(parents=True, exist_ok=True)
frames = []   # (PIL image, seconds)

OVERLAY = """
() => {
  if (document.getElementById('demo-cap')) return;
  const s = document.createElement('style'); s.textContent = `
    #demo-cap { position:fixed; left:0; right:0; bottom:0; padding:14px 24px 16px; background:rgba(15,23,42,.93); color:#fff; font:600 19px/1.3 system-ui,sans-serif; z-index:99999; display:none; pointer-events:none; box-shadow:0 -4px 20px rgba(0,0,0,.25) }
    #demo-cap small { display:block; font-weight:400; font-size:14.5px; color:#cbd5e1; margin-top:4px }
    #demo-cap .n { display:inline-block; background:#f59e0b; color:#1e293b; font-size:12px; font-weight:700; padding:1px 8px; border-radius:999px; margin-right:10px; vertical-align:middle }
    #demo-cur { position:fixed; width:22px; height:22px; z-index:100000; pointer-events:none; transform:translate(-3px,-2px); transition:left .35s ease, top .35s ease; display:none }
    #demo-note { position:fixed; z-index:99998; background:#f59e0b; color:#1e293b; font:600 13.5px/1.25 system-ui,sans-serif; padding:6px 10px; border-radius:6px; max-width:340px; pointer-events:none; box-shadow:0 2px 10px rgba(0,0,0,.3); display:none }
    #demo-note:after { content:''; position:absolute; left:-8px; top:10px; border:6px solid transparent; border-right-color:#f59e0b; border-left:0 }
    .demo-ring { outline:3px solid #f59e0b !important; outline-offset:2px; border-radius:6px; transition:outline-color .3s }`;
  document.head.appendChild(s);
  const c = document.createElement('div'); c.id = 'demo-cap'; document.body.appendChild(c);
  const n = document.createElement('div'); n.id = 'demo-note'; document.body.appendChild(n);
  const m = document.createElement('div'); m.id = 'demo-cur';
  m.innerHTML = '<svg viewBox="0 0 24 24" width="22" height="22"><path d="M4 2l14 11-6 1 4 7-3 1-4-7-5 4z" fill="#111" stroke="#fff" stroke-width="1.5"/></svg>'; document.body.appendChild(m);
}"""
SCENE = [0]


def overlay(page): page.evaluate(OVERLAY)
def caption(page, title, sub="", numbered=True):
    """The bottom banner: a numbered scene title and one explanatory line."""
    overlay(page)
    if numbered: SCENE[0] += 1
    page.evaluate("([t, s, n]) => { const c = document.getElementById('demo-cap'); c.innerHTML = (n ? '<span class=n>' + n + '</span>' : '') + t + (s ? '<small>' + s + '</small>' : ''); c.style.display = 'block'; }", [title, sub, SCENE[0] if numbered else 0])
def note(page, sel, text):
    """A callout beside an element (points at it); hidden again with note_off."""
    overlay(page); el = page.locator(sel).first; el.scroll_into_view_if_needed(); b = el.bounding_box()
    if not b: return
    x, y = b["x"] + b["width"] + 14, b["y"] + max(0, b["height"] / 2 - 16)
    if x > a.width - 360: x, y = max(10, b["x"] - 360), b["y"] + b["height"] + 10
    page.evaluate("([x, y, t]) => { const n = document.getElementById('demo-note'); n.textContent = t; n.style.left = x + 'px'; n.style.top = y + 'px'; n.style.display = 'block'; }", [x, y, text])
    el.evaluate("e => e.classList.add('demo-ring')")
def note_off(page):
    page.evaluate("() => { const n = document.getElementById('demo-note'); if (n) n.style.display = 'none'; document.querySelectorAll('.demo-ring').forEach(e => e.classList.remove('demo-ring')); }")
def snap(page, seconds=1.0):
    frames.append((Image.open(io.BytesIO(page.screenshot())).convert("RGB"), seconds))
def hold(page, seconds, step=0.5):
    """Several frames over `seconds` (so live updates on the page are captured)."""
    for _ in range(max(1, int(seconds / step))): snap(page, step); time.sleep(step)
def move_to(page, sel):
    el = page.locator(sel).first; el.scroll_into_view_if_needed(); b = el.bounding_box()
    x, y = b["x"] + b["width"] / 2, b["y"] + b["height"] / 2
    page.evaluate("([x, y]) => { const m = document.getElementById('demo-cur'); m.style.display = 'block'; m.style.left = x + 'px'; m.style.top = y + 'px'; }", [x, y])
    el.evaluate("e => e.classList.add('demo-ring')"); time.sleep(0.4); snap(page, 0.7)
    return el
def click(page, sel, settle=0.8):
    el = move_to(page, sel); el.click(); time.sleep(settle); el.evaluate("e => e.classList.remove('demo-ring')"); overlay(page); snap(page, 1.0)
def type_into(page, sel, text):
    el = move_to(page, sel); el.click(); el.fill(""); el.type(text, delay=35); snap(page, 1.0); el.evaluate("e => e.classList.remove('demo-ring')")
def scroll_to(page, sel, block="start", settle=0.6):
    page.evaluate("([s, b]) => { const e = document.querySelector(s); if (e) e.scrollIntoView({block: b}); }", [sel, block]); time.sleep(settle)
def wait_for(page, expr, timeout=120000): page.wait_for_function(expr, timeout=timeout)


with sync_playwright() as pw:
    browser = pw.chromium.launch(channel="chrome", headless=True)
    ctx = browser.new_context(viewport={"width": a.width, "height": a.height})
    page = ctx.new_page(); page.on("dialog", lambda d: d.accept())
    page.goto(a.url + "/#provision"); page.wait_for_selector("#login-form"); time.sleep(0.8)

    # ---- 1. sign in ----------------------------------------------------------------------------------------------------
    caption(page, "VPN Provisioning Portal — the customer-facing front of a Network-as-Code pipeline",
            "Nautobot is the source of truth · Terraform (iosxe NaC) pushes the config · Golden Config proves compliance · Robot Framework proves the network")
    hold(page, 3.5)
    caption(page, "Sign in: local users with roles, or single sign-on", "viewer reads · operator provisions and changes · approver also removes spokes and manages users — SSO via OpenID Connect (Gitea here)")
    note(page, "#login-sso", "OIDC: authorization code + PKCE; the provider's groups map to a role"); hold(page, 2.5); note_off(page)
    type_into(page, "#login-user", a.user); type_into(page, "#login-pass", a.password); click(page, "#login-go", settle=2)
    page.wait_for_selector("#devices tbody tr"); time.sleep(1)

    # ---- 2. provision ---------------------------------------------------------------------------------------------------
    caption(page, "Provision: the whole VPN service is one intent document — edited as a form", "site and service metadata · routers (hostname, AS, router-id, site LAN) · tunnels · the IKEv2 / IPsec profile · internet breakout")
    hold(page, 3)
    scroll_to(page, "#devices")
    caption(page, "The routers table: every headend and branch with its IKE authentication and certificate", "each branch chooses pre-shared key or certificate (lab CA) — at provisioning, or later with one click")
    note(page, "#devices button.auth >> nth=0", "Change auth…: PSK ↔ certificate on a running branch — Nautobot, PKI, staged Terraform, SAs re-authenticated"); hold(page, 3); note_off(page)
    note(page, "#devices button.rm >> nth=-1", "Remove…: decommission (approver role)"); hold(page, 2); note_off(page)
    click(page, "#devices button.auth >> nth=0", settle=1.5)
    caption(page, "Change authentication: the dialog shows what changes on the branch and on each headend", "the run: intent → Nautobot (its tunnels move to the other VPN profile) → NaC render → certificates enrolled or retired → staged Terraform → verified")
    hold(page, 4); click(page, "#auth-cancel")
    page.evaluate("window.scrollTo(0, 0)"); time.sleep(0.4)

    # ---- 3. wizard ------------------------------------------------------------------------------------------------------
    caption(page, "Add a spoke: a guided 3-step wizard", "step 1 — identity, metadata, IKE authentication, the customer, and the headends to connect (at least two)")
    click(page, "#add-spoke", settle=1.8)
    note(page, "#sp\\.city", "a catalogue city places the branch on the map (Nautobot location coordinates)"); hold(page, 2.5); note_off(page)
    scroll_to(page, "#sp\\.customer\\.company", "center")
    note(page, "#sp\\.customer\\.company", "every branch is a customer of ACME: company, address, industry, tier, account — a Nautobot tenant"); hold(page, 3); note_off(page)
    type_into(page, "#sp\\.comments", "branch office 5 - demo")
    caption(page, "Step 2 — every address is auto-suggested", "management IP, headend ports, WAN /30s, tunnel numbers and /30s, router-id, LAN, AS — all editable and re-validated against Nautobot and the lab")
    click(page, "#wiz-next", settle=2.5); hold(page, 4)
    caption(page, "Step 3 — review what happens on the spoke and on each headend", "hub WAN port and address, TunnelN, eBGP neighbour, the Nautobot cable / tunnel / peering, the design pattern, capacity after")
    click(page, "#wiz-next", settle=2.5); hold(page, 4); page.mouse.wheel(0, 400); time.sleep(0.5); hold(page, 2.5)
    caption(page, "Provision spoke would build the VM, bootstrap it, onboard it into Nautobot and configure hub + spoke in one Terraform run", "(cancelled for the demo — a real run takes about 15 minutes and ends with Golden Config and the Robot suites)")
    hold(page, 3); click(page, "#wiz-cancel")

    # ---- 4. runs --------------------------------------------------------------------------------------------------------
    scroll_to(page, "#runcard")
    caption(page, "Runs: every change is a pipeline run with live status, logs and a test report", "runs execute one at a time (one Terraform state, one intent) — a queued run shows its place in line and can be cancelled; a failed one resumes from the failed step")
    runs = page.evaluate("fetch('/api/runs').then(r => r.json())")
    ok = next((r for r in runs if r["status"] == "success" and r["mode"] in ("spoke", "hub", "auth", "deploy")), next((r for r in runs if r["status"] == "success"), runs[0]))
    page.evaluate("id => watchInline(id)", ok["id"]); time.sleep(2.5); hold(page, 4)
    note(page, "#steps", "each step: what it did, in one line — the full log below"); hold(page, 2.5); note_off(page)
    page.mouse.wheel(0, 500); time.sleep(0.5); hold(page, 2.5)
    page.evaluate("window.scrollTo(0, 0)"); time.sleep(0.3)

    # ---- 5. home ---------------------------------------------------------------------------------------------------------
    page.goto(a.url + "/#home"); wait_for(page, "document.querySelectorAll('#inv-kpis .kpi').length > 0", 180000); time.sleep(1)
    caption(page, "Home: the service at a glance", "Nautobot's VPN model joined with IKEv2 SA / VTI / eBGP / ESP state collected from the headends — KPIs, the topology and headend capacity")
    hold(page, 3.5)
    scroll_to(page, "#inv-topo")
    caption(page, "Rendered topology and map: headends on top, branches below, one line per tunnel coloured by health", "hover a tunnel for ports, addresses and counters; click anything to open it in Nautobot")
    hold(page, 2.5); move_to(page, "#inv-topo path.edge"); page.hover("#inv-topo path.edge", force=True); hold(page, 2.5)
    scroll_to(page, "#inv-capacity", "center")
    caption(page, "Headend capacity: tunnel slots and the firewall's bandwidth, live CPU — the binding constraint per headend", "modelled in Nautobot (vpn_tunnel_capacity, firewall_bandwidth_mbps), enforced when a spoke is provisioned")
    hold(page, 3.5)

    # ---- 6. inventory ----------------------------------------------------------------------------------------------------
    page.goto(a.url + "/#inventory"); wait_for(page, "document.querySelectorAll('#brs-table tbody tr').length > 0"); time.sleep(1)
    caption(page, "Inventory: every node in the lab", "headends, customer branches, the DCI chain, the VyOS firewalls and the Alpine LAN hosts — every branch is a customer of ACME Networks, the provider that owns the headends")
    hold(page, 3.5)
    note(page, "#brs-table tbody tr:nth-child(4) td:nth-child(5)", "ACME-DH: two tunnels → dual headend (resilient); ACME-MH: three or more → any-region"); hold(page, 3); note_off(page)
    caption(page, "Filter the list: free text, role, region, design pattern, service tier, industry, IKE auth, health, VM state", "remembered per browser; the pattern legend below the table filters too")
    page.select_option("#bf-tier", "Gold"); page.evaluate("renderBranches()"); time.sleep(0.5); note(page, "#bf-tier", "service tier Gold"); hold(page, 2.5); note_off(page)
    page.select_option("#bf-pattern", "Multi headend (any-region)"); page.evaluate("renderBranches()"); time.sleep(0.5); note(page, "#bf-pattern", "and the multi-headend pattern"); hold(page, 2.5); note_off(page)
    type_into(page, "#bf-q", "Seattle"); hold(page, 2)
    page.evaluate("clearBranchFilters()"); time.sleep(0.5); hold(page, 1.5)
    scroll_to(page, "#inv-tunnels")
    caption(page, "Per-tunnel report: model + live state, IKE authentication per tunnel · Export CSV", "")
    hold(page, 3); page.mouse.wheel(0, 300); time.sleep(0.5); hold(page, 2)
    scroll_to(page, "#inv-hosts")
    caption(page, "LAN hosts: a small Alpine VM behind every router — and the full ping mesh between them", "every host pings every other host over the tunnels, its gateway, and the internet (1.1.1.1 through the nearest headend's breakout)")
    if not a.no_runs:
        click(page, "#hosts-ping", settle=1); wait_for(page, "document.querySelectorAll('#hosts-matrix table tr').length > 2", 180000); time.sleep(0.8); hold(page, 3)
        note(page, "#hosts-live", "▶ Live: one probe per pair every 5 s, round-trip time in the cell — green ok, red loss"); hold(page, 2); note_off(page)
        click(page, "#hosts-live", settle=1); hold(page, 9); click(page, "#hosts-live", settle=0.5)
    else: hold(page, 3)

    # ---- 7. a router's page ---------------------------------------------------------------------------------------------
    page.goto(a.url + "/#branch/spoke3"); wait_for(page, "document.querySelectorAll('#br-tunnels tbody tr').length > 0"); time.sleep(1)
    caption(page, "A branch's page: the customer, identity, authentication and the day-2 actions", "customer box (tenant in Nautobot, address, tier, contract, design pattern) · router-id, LAN, WAN, internet preference · Change auth, Rotate PSK, Re-home, Remove")
    hold(page, 4)
    scroll_to(page, "#br-tunnels")
    caption(page, "Its tunnels with live state, and the firewall rules and log lines that touch it", "IKE SA age, VTI, eBGP prefixes, ESP counters and errors · the VyOS firewalls in front of its headends: rules admitting its WAN addresses, flows, log")
    hold(page, 3); scroll_to(page, "#br-firewalls"); hold(page, 3)
    scroll_to(page, "#br-show-btns")
    caption(page, "Live state: an allow-list of show commands run on the router (IKE, IPsec, BGP, routes, default, interfaces, PKI, platform, log)", "")
    click(page, "#br-show-btns button[data-what='bgp']", settle=1); wait_for(page, "!document.getElementById('br-show').textContent.includes('pick a command') && document.getElementById('br-show').textContent.length > 50", 60000); hold(page, 3)
    scroll_to(page, "#br-config")
    caption(page, "Configuration: the running config over SSH, Nautobot's intended config and last backup, compliance per feature", "a running-vs-intended diff per feature · the backup history from Gitea with per-commit diffs · pre-shared keys redacted for viewers")
    wait_for(page, "document.getElementById('br-config').textContent.includes('hostname')", 120000); hold(page, 3)
    page.evaluate("localStorage.setItem('cfg-theme', 'dark'); applyCodeTheme()"); time.sleep(0.4); note(page, "#br-config", "dark / light toggle for the code panes"); hold(page, 2.5); note_off(page)
    page.evaluate("localStorage.removeItem('cfg-theme'); applyCodeTheme()")
    scroll_to(page, "#br-history"); hold(page, 2.5)

    # ---- 8. firewalls ---------------------------------------------------------------------------------------------------
    page.goto(a.url + "/#firewalls"); wait_for(page, "document.querySelectorAll('#fw-cards .card').length > 0", 180000); time.sleep(1)
    caption(page, "Firewalls: the VyOS firewall in front of each headend, rendered from Nautobot", "interfaces from the model, the forward-filter policy from a config context (IKE / ESP / ICMP between modelled peers only), NAT breakout, the drops it logged")
    hold(page, 4); page.mouse.wheel(0, 500); time.sleep(0.5); hold(page, 3)

    # ---- 9. compliance --------------------------------------------------------------------------------------------------
    page.goto(a.url + "/#compliance"); wait_for(page, "document.querySelectorAll('#cmp-table tbody tr').length > 0"); time.sleep(1)
    caption(page, "Compliance: Nautobot Golden Config's verdict — one row per router, one column per feature", "the running config (last backup) against the configuration rendered from the model; history dots per router; a Golden Config run is scheduled every 6 hours")
    hold(page, 3.5)
    note(page, "#cmp-table tbody tr:nth-child(5) td:nth-last-child(4)", "the verdict over the last runs — a red dot is drift, fixed by the next green"); hold(page, 3); note_off(page)
    page.evaluate("document.querySelector('#cmp-table').parentElement.scrollLeft = 3000"); time.sleep(0.4)
    note(page, "#cmp-table tbody tr:nth-child(5) button.reapply", "Re-apply from the model: NaC render → Terraform targeted at this router → Golden Config"); hold(page, 3); note_off(page)
    page.evaluate("document.querySelector('#cmp-table').parentElement.scrollLeft = 0")
    dev = page.evaluate("CMP.devices[4].name"); feat = page.evaluate("CMP.features.includes('Static routes') ? 'Static routes' : CMP.features[0]")
    page.evaluate("([d, f]) => showCompliance(d, f)", [dev, feat]); time.sleep(0.6); scroll_to(page, "#cmp-detail", "center")
    caption(page, "A cell: the missing and extra lines, the running-vs-intended diff — and, when it drifted, Remediate / Re-apply", "Remediate pushes the remediation lines Nautobot computed (no … for what is extra, the missing lines) and saves; both end with a Golden Config run")
    hold(page, 4)
    scroll_to(page, "#cmp-history")
    caption(page, "Drift history: one line per compliance run — which routers drifted, and when it was fixed", "also exported to Prometheus (lab_config_compliance_ok) — the ConfigDrift alert fires when a router stays non-compliant")
    hold(page, 3.5)
    if not a.no_runs:
        page.evaluate("window.scrollTo(0, 0)"); time.sleep(0.4)
        caption(page, "Run Golden Config now: backup every router → render the intended configuration → compare (nothing is pushed)", "about 20 seconds against 7 routers — the report and the history refresh when it finishes")
        click(page, "#cmp-run", settle=1.5)
        t0 = time.time()
        while time.time() - t0 < 240:
            hold(page, 2, step=1.0)
            if "SUCCESS" in page.evaluate("document.getElementById('cmp-note').textContent") or "FAILED" in page.evaluate("document.getElementById('cmp-note').textContent"): break
        hold(page, 3)

    # ---- 10. tools, audit, dark mode, API --------------------------------------------------------------------------------
    page.goto(a.url + "/#tools"); wait_for(page, "document.querySelectorAll('#tools-table tbody tr').length > 0"); time.sleep(0.8)
    caption(page, "Tools: every system of the lab with its URL and login — Nautobot, Gitea, Grafana, Prometheus, VictoriaLogs — and how to reach each device", "")
    hold(page, 3.5)
    page.goto(a.url + "/#audit"); wait_for(page, "document.querySelectorAll('#audit-table tbody tr').length > 0"); time.sleep(0.8)
    caption(page, "Audit: who did what — logins (local and SSO), every run start / resume / cancel, denied requests, the scheduler's runs", "")
    hold(page, 3.5)
    page.evaluate("localStorage.setItem('portal-theme', 'dark'); applyTheme()"); time.sleep(0.5)
    page.goto(a.url + "/#home"); wait_for(page, "document.querySelectorAll('#inv-kpis .kpi').length > 0", 180000); time.sleep(1)
    caption(page, "Dark mode for the whole portal — from the header, or following the OS setting", "")
    hold(page, 3.5); page.evaluate("localStorage.removeItem('portal-theme'); applyTheme()")
    page.goto(a.url + "/docs"); time.sleep(3)
    caption(page, "Everything the UI does is the REST API: OpenAPI / Swagger at /docs — runs, intent, inventory, branches, compliance, metrics", "Prometheus scrapes /metrics; the shared monitoring alerts on tunnels, capacity, certificates and configuration drift")
    hold(page, 4)
    caption(page, "Nautobot · Network-as-Code · Terraform · Golden Config · Robot Framework", "one form, one button, a source of truth kept honest — github.com/dcantor/cat8000v-ipsec", numbered=False)
    hold(page, 4)
    ctx.close(); browser.close()

# ---- assemble --------------------------------------------------------------------------------------------------------------
try:
    import imageio_ffmpeg; ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
except ImportError:
    ffmpeg = shutil.which("ffmpeg")
if ffmpeg:   # MP4 (H.264, full resolution) from the frames and their durations, via ffmpeg's concat demuxer
    tmp = Path(tempfile.mkdtemp(prefix="demo-frames-")); lines = []
    for i, (f, d) in enumerate(frames):
        f.save(tmp / f"f{i:04d}.png"); lines += [f"file 'f{i:04d}.png'", f"duration {max(0.08, d):.3f}"]
    lines.append(f"file 'f{len(frames) - 1:04d}.png'")   # the concat demuxer needs the last file repeated
    (tmp / "list.txt").write_text("\n".join(lines) + "\n")
    mp4 = OUT / "portal-demo.mp4"
    subprocess.run([ffmpeg, "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(tmp / "list.txt"), "-vf", "fps=15,format=yuv420p,scale=trunc(iw/2)*2:trunc(ih/2)*2",
                    "-c:v", "libx264", "-preset", "slow", "-crf", "21", "-movflags", "+faststart", str(mp4)], check=True)
    shutil.rmtree(tmp); print(f"{mp4} ({mp4.stat().st_size / 1e6:.1f} MB)")
else: print("no ffmpeg: MP4 skipped (webapp/.venv/bin/pip install imageio-ffmpeg)")
# GIF for the README: downscaled, one shared palette
W = 960; imgs = [f.resize((W, int(f.height * W / f.width)), Image.LANCZOS) for f, _ in frames]
durs = [max(80, int(d * 1000)) for _, d in frames]
pal = imgs[0].quantize(colors=256, method=Image.Quantize.MEDIANCUT)
q = [im.quantize(colors=256, palette=pal, dither=Image.Dither.NONE) for im in imgs]
gif = OUT / "portal-demo.gif"; q[0].save(gif, save_all=True, append_images=q[1:], duration=durs, loop=0, optimize=True)
print(f"{gif} ({gif.stat().st_size / 1e6:.1f} MB, {len(q)} frames, {sum(durs) / 1000:.0f}s)")
