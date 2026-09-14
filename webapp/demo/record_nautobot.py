#!/usr/bin/env python3
"""Demo 2: where the data lives (Nautobot) and how Network-as-Code consumes it (code walk-through).
Act 1 drives the real Nautobot GUI; act 2 renders the real source files with highlighted line ranges.
Writes demo/nautobot-nac-demo.gif (+ .webm).   Usage: record_nautobot.py [--nautobot http://10.0.0.10:8080]"""
import argparse, html, io, json, time, urllib.parse
from pathlib import Path
from PIL import Image
from playwright.sync_api import sync_playwright
import requests

p = argparse.ArgumentParser(); p.add_argument("--nautobot", default="http://10.0.0.10:8080"); p.add_argument("--user", default="admin"); p.add_argument("--password", default="admin")
p.add_argument("--out", default=str(Path(__file__).resolve().parent)); p.add_argument("--width", type=int, default=1280); p.add_argument("--height", type=int, default=800)
a = p.parse_args(); OUT = Path(a.out); LAB = Path(__file__).resolve().parents[2]; NB = a.nautobot.rstrip("/")
frames = []
TOKEN = (LAB / "webapp" / ".token").read_text().strip() if (LAB / "webapp" / ".token").exists() else __import__("subprocess").run(["bash", "-c", f"cd {LAB} && ./lab.sh nautobot token"], capture_output=True, text=True).stdout.strip()
H = {"Authorization": f"Token {TOKEN}"}
def api(path, **params): return requests.get(f"{NB}/api/{path}", params=params, headers=H, timeout=30).json()
ids = {
    "loc": api("dcim/locations/", name="c8000v-ipsec-lab")["results"][0]["id"],
    "dev": api("dcim/devices/", name="east-headend")["results"][0]["id"],
    "vpn": api("vpn/vpns/")["results"][0]["id"],
    "tun": api("vpn/vpn-tunnels/", name="east-headend-spoke1")["results"][0]["id"],
    "prof": api("vpn/vpn-profiles/", name="VPN-IPSEC")["results"][0]["id"],
    "gq": api("extras/graphql-queries/", name="nac-c8000v-ipsec-model")["results"][0]["id"],
}
QUERY = api("extras/graphql-queries/", name="nac-c8000v-ipsec-model")["results"][0]["query"]

OVERLAY = """() => {
  if (document.getElementById('demo-cap')) return;
  const s = document.createElement('style'); s.textContent = `
    #demo-cap { position:fixed; left:0; right:0; bottom:0; padding:14px 22px; background:rgba(15,23,42,.93); color:#fff; font:600 18px/1.3 system-ui,sans-serif; z-index:99999; display:none }
    #demo-cap small { display:block; font-weight:400; font-size:14px; color:#cbd5e1; margin-top:3px }
    #demo-badge { position:fixed; top:8px; right:12px; padding:4px 10px; border-radius:6px; background:#0b62d6; color:#fff; font:600 12px system-ui,sans-serif; z-index:99999; display:none }`;
  document.head.appendChild(s); const c = document.createElement('div'); c.id = 'demo-cap'; document.body.appendChild(c);
  const b = document.createElement('div'); b.id = 'demo-badge'; document.body.appendChild(b); }"""
def caption(page, title, sub="", badge=None):
    page.evaluate(OVERLAY)
    page.evaluate("([t, s, b]) => { const c = document.getElementById('demo-cap'); c.innerHTML = t + (s ? '<small>' + s + '</small>' : ''); c.style.display = 'block'; const bd = document.getElementById('demo-badge'); if (b) { bd.textContent = b; bd.style.display = 'block'; } }", [title, sub, badge])
def snap(page, seconds=1.0): frames.append((Image.open(io.BytesIO(page.screenshot())).convert("RGB"), seconds))
def hold(page, seconds, step=0.6):
    for _ in range(max(1, int(seconds / step))): snap(page, step); time.sleep(step)
def goto(page, url, wait="networkidle"):
    page.goto(url, wait_until=wait, timeout=60000); time.sleep(0.8)
def scroll(page, dy, seconds=1.6): page.mouse.wheel(0, dy); time.sleep(0.5); hold(page, seconds)

# ---- title / code cards rendered as local HTML ------------------------------------------------------------
def card_html(title, lines):
    return f"""<html><body style="margin:0;background:#0f172a;color:#fff;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh">
      <div style="max-width:980px"><div style="font-size:40px;font-weight:700;margin-bottom:18px">{html.escape(title)}</div>
      {''.join(f'<div style="font-size:22px;color:#cbd5e1;margin:8px 0">{html.escape(l)}</div>' for l in lines)}</div></body></html>"""
def code_html(path, hl=(), start=1, end=None, title=None):
    src = (LAB / path).read_text().splitlines(); end = end or len(src); rows = []
    for i in range(start, min(end, len(src)) + 1):
        cls = "hl" if any(lo <= i <= hi for lo, hi in hl) else ""
        rows.append(f'<tr class="{cls}"><td class="n">{i}</td><td class="c">{html.escape(src[i-1]) or " "}</td></tr>')
    return f"""<html><head><style>body{{margin:0;background:#0b1220;color:#e2e8f0;font:14px/1.45 ui-monospace,Menlo,Consolas,monospace}}
      .hdr{{background:#1e293b;color:#fff;padding:10px 18px;font:600 15px system-ui,sans-serif;position:sticky;top:0}} .hdr span{{color:#94a3b8;font-weight:400;margin-left:12px}}
      table{{border-collapse:collapse;width:100%}} td{{padding:1px 8px;white-space:pre}} .n{{color:#475569;text-align:right;width:40px;user-select:none}}
      tr.hl td{{background:#1d3557}} tr.hl .n{{color:#fbbf24}}</style></head><body><div class="hdr">{html.escape(title or path)}<span>{html.escape(path)}</span></div><table>{''.join(rows)}</table></body></html>"""
def show_card(page, title, lines, seconds=4):
    page.set_content(card_html(title, lines)); time.sleep(0.3); hold(page, seconds)
def show_code(page, path, hl, cap, sub="", start=1, end=None, seconds=6, title=None):
    page.set_content(code_html(path, hl, start, end, title)); time.sleep(0.3)
    if hl: page.evaluate("() => { const r = document.querySelector('tr.hl'); if (r) r.scrollIntoView({block: 'center'}); }")
    caption(page, cap, sub, "code walk-through"); hold(page, seconds)

with sync_playwright() as pw:
    browser = pw.chromium.launch(channel="chrome", headless=True)
    ctx = browser.new_context(viewport={"width": a.width, "height": a.height}, record_video_dir=str(OUT / "video"), record_video_size={"width": a.width, "height": a.height})
    page = ctx.new_page()
    show_card(page, "Where the data lives", ["Act 1 — Nautobot is the source of truth: devices, links, the VPN app, BGP, prefixes, the saved GraphQL query, Golden Config",
                                            "Act 2 — how Network-as-Code consumes it: intent → seed → GraphQL → renderer → NAC data → Terraform → tests"], 5)

    # ---- act 1: Nautobot ------------------------------------------------------------------------------------
    goto(page, f"{NB}/login/"); page.fill("input[name=username]", a.user); page.fill("input[name=password]", a.password); page.click("button[type=submit]"); page.wait_for_load_state("networkidle")
    goto(page, f"{NB}/dcim/devices/?location={ids['loc']}")
    caption(page, "Devices at location c8000v-ipsec-lab", "discovered by the Device Onboarding app (model, serial, platform, management IP); roles vpn-hub / vpn-spoke set by the seed", "Nautobot")
    hold(page, 4)
    goto(page, f"{NB}/dcim/devices/{ids['dev']}/")
    caption(page, "A headend: east-headend", "custom fields carry metadata (contact, VPN tunnel capacity = 50); config context supplies OOB/domain settings", "Nautobot")
    hold(page, 3.5); scroll(page, 500, 3)
    goto(page, f"{NB}/dcim/devices/{ids['dev']}/interfaces/")
    caption(page, "Interfaces are the physical truth", "Gi2..Gi9 spoke-facing ports (cabled ones carry the WAN /30, unused ones are disabled), Loopbacks, TunnelN of type 'tunnel'", "Nautobot")
    hold(page, 3.5); scroll(page, 450, 3)
    goto(page, f"{NB}/vpn/vpns/{ids['vpn']}/")
    caption(page, "The VPN service, in Nautobot's core VPN app", "VPN IPSEC_VPN: service type IPsec, profile VPN-IPSEC, extra attributes (change ticket, owner, NAC device group)", "Nautobot")
    hold(page, 4)
    goto(page, f"{NB}/vpn/vpn-tunnels/?vpn={ids['vpn']}")
    caption(page, "One VPN Tunnel per headend/spoke pair", "tunnel id = TunnelN on both routers; endpoint A = headend, endpoint Z = spoke; encapsulation IPsec-Tunnel", "Nautobot")
    hold(page, 4)
    goto(page, f"{NB}/vpn/vpn-tunnels/{ids['tun']}/")
    caption(page, "A tunnel's endpoints hold everything the config needs", "source interface + address (tunnel source / the far side's tunnel destination), tunnel interface, protected prefixes", "Nautobot")
    hold(page, 4); scroll(page, 400, 3)
    goto(page, f"{NB}/vpn/vpn-profiles/{ids['prof']}/")
    caption(page, "The crypto suite is a VPN Profile with Phase 1 / Phase 2 policies", "IKEv2 AES-256-CBC / SHA256 / DH14, ESP AES-256-CBC / SHA256, DPD; Cisco object names in extra_options — the PSK is NOT here", "Nautobot")
    hold(page, 4); scroll(page, 400, 2.5)
    goto(page, f"{NB}/plugins/bgp/routing-instances/")
    caption(page, "Routing is modelled too (nautobot-bgp-models)", "one AS per site, a routing instance per router with router-id = Loopback0", "Nautobot")
    hold(page, 3.5)
    goto(page, f"{NB}/plugins/bgp/peerings/")
    caption(page, "eBGP peerings: one per tunnel, endpoints on the tunnel /30 addresses", "the renderer turns these into neighbor statements; remote-as = the peer endpoint's AS", "Nautobot")
    hold(page, 3.5)
    goto(page, f"{NB}/ipam/prefixes/?role=vpn-tunnel")
    caption(page, "IPAM: every /30 and LAN is a prefix with a role", "wan-p2p, vpn-tunnel, site-lan, loopback; prefixes tagged bgp:advertise become 'network' statements", "Nautobot")
    hold(page, 3.5)
    goto(page, f"{NB}/extras/graphql-queries/{ids['gq']}/")
    caption(page, "The contract between Nautobot and NaC: a saved GraphQL query", "nac-c8000v-ipsec-model — everything the renderer needs in one document (devices, interfaces, VPN endpoints, BGP)", "Nautobot")
    hold(page, 4); scroll(page, 500, 3)
    goto(page, f"{NB}/graphql/", wait="load"); time.sleep(4)
    try:   # paste the saved query into the GraphiQL editor and run it
        ed = page.locator(".graphiql-query-editor .CodeMirror, .query-editor .CodeMirror, .CodeMirror").first; ed.click(); page.keyboard.press("Control+A"); page.keyboard.insert_text(QUERY); time.sleep(1)
        page.locator("button.execute-button, button[title*='Execute'], .graphiql-execute-button").first.click(); time.sleep(5)
    except Exception as e: print("graphiql:", e)
    caption(page, "GraphiQL: the same query, live", "the JSON on the right is exactly what nautobot/render_nac.py consumes", "Nautobot")
    hold(page, 5)
    goto(page, f"{NB}/plugins/golden-config/config-compliance/")
    caption(page, "Golden Config closes the loop", "intended config rendered from the same objects (Jinja2 in Gitea) vs the running config: 136/136 compliant", "Nautobot")
    hold(page, 4)

    # ---- act 2: the codebase, NaC focus ---------------------------------------------------------------------
    show_card(page, "How Network-as-Code consumes it", ["lab-intent.json  →  nautobot/seed.py  →  Nautobot  →  saved GraphQL query  →  nautobot/render_nac.py",
                                                       "→  nac/data/*.nac.yaml  →  Terraform (netascode/nac-iosxe module, CiscoDevNet/iosxe provider, RESTCONF)  →  routers",
                                                       "→  Robot Framework: no drift, rendered model == committed model, Golden Config compliant"], 6)
    show_code(page, "lab-intent.json", [(2, 8), (40, 52)], "The intent: one JSON document the portal edits", "site metadata, VPN service, crypto profile, PSK, devices, links, tunnels — the input to the seed", end=60, seconds=6)
    show_code(page, "nautobot/seed.py", [(92, 100)], "seed.py: the intent becomes Nautobot objects (idempotently)", "Phase 1/2 policies, the VPN profile, the VPN — Cisco object names ride along in extra_options", start=84, end=118, seconds=6)
    show_code(page, "nautobot/seed.py", [(206, 222)], "seed.py: tunnels", "for every (hub, spoke): TunnelN on both routers, a VPN Tunnel with A/Z endpoints (source interface + address, protected prefixes)", start=196, end=230, seconds=6)
    show_code(page, "nautobot/nac-c8000v-ipsec-model.graphql", [(10, 24)], "The saved GraphQL query", "per interface: its VPN tunnel endpoint → profile (policies) → the tunnel → the far endpoint's source address", seconds=6)
    show_code(page, "nautobot/render_nac.py", [(47, 54)], "render_nac.py: a TunnelN interface becomes a native NAC tunnel", "tunnel_source from the endpoint, tunnel_destination from the far endpoint, mode ipsec ipv4, protection profile", start=36, end=72, seconds=6)
    show_code(page, "nautobot/render_nac.py", [(58, 70)], "render_nac.py: the crypto block from the VPN profile", "Phase 1 → IKEv2 proposal/policy/keyring/profile; Phase 2 → transform set + IPsec profile; the PSK is a NAC variable", start=52, end=82, seconds=6)
    show_code(page, "nautobot/render_nac.py", [(99, 110)], "render_nac.py: BGP from nautobot-bgp-models", "neighbors from the peerings, remote-as from the peer endpoint, networks from prefixes tagged bgp:advertise", start=88, end=120, seconds=6)
    dev_yaml = (LAB / "nac/data/devices.nac.yaml").read_text().splitlines()
    first_tun = next(i for i, l in enumerate(dev_yaml, 1) if "tunnels:" in l)
    show_code(page, "nac/data/devices.nac.yaml", [(first_tun, first_tun + 20)], "GENERATED: nac/data/devices.nac.yaml", "the NAC data model the Terraform module reads — never edited by hand, always re-rendered from Nautobot", start=max(1, first_tun - 12), end=first_tun + 40, seconds=6)
    show_code(page, "nac/data/device_groups.nac.yaml", [(1, 12)], "The one secret: the pre-shared key", "rendered into a NAC device group variable from the intent — it never enters Nautobot", seconds=4)
    show_code(page, "nac/data/global.nac.yaml", [(1, 30)], "nac/data/global.nac.yaml: the hand-written baseline", "AAA, SSH/VTY hardening, management ACL, banner — applies to every router", end=45, seconds=5)
    show_code(page, "nac/main.tf", [(1, 30)], "nac/main.tf: the Cisco NaC Terraform module", "netascode/nac-iosxe reads the YAML directory; provider CiscoDevNet/iosxe talks RESTCONF to each router", seconds=6)
    show_code(page, "lab.sh", [(260, 271)], "lab.sh nac: terraform with the router credentials, then save-config", "plan / apply with -parallelism=1; a cisco-ia:save-config RPC copies running to startup", start=252, end=280, seconds=5)
    show_code(page, "nautobot/golden-config-templates/c8000v-ipsec.j2", [(50, 72)], "Golden Config template: the same objects, rendered as CLI", "so compliance proves the routers match Nautobot, independently of Terraform", start=44, end=84, seconds=5)
    show_code(page, "tests/suites/05_nac_compliance.robot", [(1, 12)], "Robot: no drift", "terraform plan must return exit code 0", seconds=4)
    show_code(page, "tests/suites/06_nautobot.robot", [(153, 157)], "Robot: the committed NAC data equals what Nautobot renders now", "render_nac.py --check; every tunnel destination equals the far endpoint's source address", start=140, end=170, seconds=5)
    show_code(page, "webapp/app.py", [(285, 300)], "The portal just orchestrates these steps", "validate → save intent → seed → render → plan → apply (crypto profiles first, then converge) → Golden Config → tests", start=270, end=312, seconds=6)
    show_card(page, "Nautobot is the source of truth. NaC is the delivery.", ["Change the model → re-render → plan shows exactly the delta → apply → tests prove it.",
                                                                            "github.com/dcantor/cat8000v-ipsec"], 5)
    ctx.close(); browser.close()

W = 960; imgs = [f.resize((W, int(f.height * W / f.width)), Image.LANCZOS) for f, _ in frames]
durs = [max(80, int(d * 1000)) for _, d in frames]
pal = imgs[0].quantize(colors=256, method=Image.Quantize.MEDIANCUT)
q = [im.quantize(colors=256, palette=pal, dither=Image.Dither.NONE) for im in imgs]
gif = OUT / "nautobot-nac-demo.gif"; q[0].save(gif, save_all=True, append_images=q[1:], duration=durs, loop=0, optimize=True)
vids = sorted((OUT / "video").glob("*.webm"), key=lambda v: v.stat().st_mtime)
if vids: vids[-1].rename(OUT / "nautobot-nac-demo.webm")
print(f"{gif} ({gif.stat().st_size / 1e6:.1f} MB, {len(q)} frames, {sum(durs) / 1000:.0f}s)")
