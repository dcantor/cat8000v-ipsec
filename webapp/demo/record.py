#!/usr/bin/env python3
"""Record a demo of the VPN provisioning portal: drives the real portal with Playwright (system Chrome), overlays
captions and a cursor, and writes demo/portal-demo.gif (+ a WebM from Playwright's own recorder).
Scenes: intent form -> add-spoke wizard (3 steps, cancelled) -> dry-run pipeline with live status -> inventory:
KPIs, topology map, headend capacity, tunnel report -> remove-spoke dialog (cancelled).
Usage: record.py [--url http://localhost:8090] [--out demo/]"""
import argparse, io, time
from pathlib import Path
from PIL import Image
from playwright.sync_api import sync_playwright

p = argparse.ArgumentParser(); p.add_argument("--url", default="http://localhost:8090"); p.add_argument("--out", default=str(Path(__file__).resolve().parent))
p.add_argument("--width", type=int, default=1280); p.add_argument("--height", type=int, default=800); p.add_argument("--fast", action="store_true", help="skip the dry run")
a = p.parse_args(); OUT = Path(a.out); OUT.mkdir(parents=True, exist_ok=True)
frames = []   # (PIL image, seconds)

OVERLAY = """
() => {
  if (document.getElementById('demo-cap')) return;
  const s = document.createElement('style'); s.textContent = `
    #demo-cap { position:fixed; left:0; right:0; bottom:0; padding:14px 22px; background:rgba(15,23,42,.92); color:#fff; font:600 18px/1.3 system-ui,sans-serif; z-index:9999; display:none }
    #demo-cap small { display:block; font-weight:400; font-size:14px; color:#cbd5e1; margin-top:3px }
    #demo-cur { position:fixed; width:22px; height:22px; z-index:10000; pointer-events:none; transform:translate(-3px,-2px); transition:left .35s ease, top .35s ease; display:none }
    .demo-ring { outline:3px solid #f59e0b !important; outline-offset:2px; border-radius:6px; transition:outline-color .3s }`;
  document.head.appendChild(s);
  const c = document.createElement('div'); c.id = 'demo-cap'; document.body.appendChild(c);
  const m = document.createElement('div'); m.id = 'demo-cur';
  m.innerHTML = '<svg viewBox="0 0 24 24" width="22" height="22"><path d="M4 2l14 11-6 1 4 7-3 1-4-7-5 4z" fill="#111" stroke="#fff" stroke-width="1.5"/></svg>'; document.body.appendChild(m);
}"""

def overlay(page): page.evaluate(OVERLAY)
def caption(page, title, sub=""):
    overlay(page); page.evaluate("([t, s]) => { const c = document.getElementById('demo-cap'); c.innerHTML = t + (s ? '<small>' + s + '</small>' : ''); c.style.display = 'block'; }", [title, sub])
def snap(page, seconds=1.0):
    frames.append((Image.open(io.BytesIO(page.screenshot())).convert("RGB"), seconds))
def hold(page, seconds, step=0.5):
    """Several frames over `seconds` (so live updates on the page are captured)."""
    n = max(1, int(seconds / step))
    for _ in range(n): snap(page, step); time.sleep(step)
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

with sync_playwright() as pw:
    browser = pw.chromium.launch(channel="chrome", headless=True)
    ctx = browser.new_context(viewport={"width": a.width, "height": a.height}, record_video_dir=str(OUT / "video"), record_video_size={"width": a.width, "height": a.height})
    page = ctx.new_page(); page.on("dialog", lambda d: d.accept())
    page.goto(a.url + "/#provision"); page.wait_for_selector("#devices tbody tr"); time.sleep(1)

    # 1. the intent form
    caption(page, "VPN Provisioning Portal", "Nautobot is the source of truth · Network-as-Code / Terraform pushes the config · Robot Framework proves it")
    hold(page, 3)
    caption(page, "Everything about the VPN service is a form", "site metadata · routers (hostname, AS, router-id, LAN) · VPN service and tunnels · crypto profile and PSK")
    hold(page, 2); page.mouse.wheel(0, 420); time.sleep(0.6); hold(page, 2.5); page.mouse.wheel(0, 500); time.sleep(0.6); hold(page, 2.5)
    page.evaluate("window.scrollTo(0, 0)"); time.sleep(0.5)

    # 2. add-spoke wizard
    caption(page, "Add a spoke: a guided 3-step wizard", "step 1 — identity & metadata; the headends to connect to (at least two)")
    click(page, "#add-spoke", settle=1.5)
    type_into(page, "#sp\\.comments", "branch office 6 - demo")
    hold(page, 2)
    caption(page, "Step 2 — every address is auto-suggested", "management IP, hub ports, WAN /30s, tunnel numbers, tunnel /30s, router-id, LAN, AS — all editable and re-validated")
    click(page, "#wiz-next", settle=2.5); hold(page, 4)
    caption(page, "Step 3 — review what happens on the spoke and on each headend", "hub WAN port and address, TunnelN, eBGP neighbour, Nautobot cable / tunnel / peering, capacity after")
    click(page, "#wiz-next", settle=2.5); hold(page, 5)
    caption(page, "Provision spoke would now build the VM, bootstrap it, onboard it and configure hub + spoke in one Terraform run", "(cancelled for the demo — a real run takes ~15 minutes)")
    hold(page, 3); click(page, "#wiz-cancel")

    # 3. dry run with live status
    if not a.fast:
        caption(page, "Deploy / Dry run: the pipeline runs behind the scenes and streams its progress", "validate → save intent → Nautobot seed → render NAC data → terraform plan (→ apply → Golden Config → tests)")
        click(page, "#plan", settle=2)
        page.evaluate("document.getElementById('runcard').scrollIntoView({block: 'start'})"); time.sleep(0.5)
        # time-lapse: a frame whenever a step changes state (plus a heartbeat every ~12 s), not real time
        t0 = time.time(); last = ""; beat = time.time()
        while time.time() - t0 < 900:
            time.sleep(1.5)
            sig = page.evaluate("[...document.querySelectorAll('#steps .dot')].map(d => d.className).join()")
            st = page.evaluate("document.querySelector('#run-head .status') && document.querySelector('#run-head .status').textContent")
            if sig != last or time.time() - beat > 40: snap(page, 0.9); last = sig; beat = time.time()
            if st in ("SUCCESS", "FAILED"): snap(page, 2.5); break
        caption(page, "Each step reports its result; the log is live; runs are kept and can be resumed from a failed step", "")
        hold(page, 4)

    # 4. inventory
    page.goto(a.url + "/#inventory"); page.wait_for_function("document.querySelectorAll('#inv-tunnels tbody tr').length > 0", timeout=120000); time.sleep(1)
    caption(page, "Inventory: every tunnel, live", "KPIs from Nautobot's VPN model joined with IKEv2 / VTI / eBGP / ESP state collected from the headends")
    hold(page, 3.5)
    page.evaluate("document.getElementById('inv-topo').scrollIntoView({block: 'start'})"); time.sleep(0.6)
    caption(page, "Rendered topology: headends on top, spokes below, one line per tunnel coloured by health", "hover a tunnel for ports, addresses and counters; click anything to open it in Nautobot")
    hold(page, 3)
    move_to(page, "#inv-topo path.edge"); page.hover("#inv-topo path.edge"); hold(page, 2.5)
    page.evaluate("document.getElementById('inv-capacity').scrollIntoView({block: 'center'})"); time.sleep(0.6)
    caption(page, "Headend capacity: 50 tunnels per headend (modelled in Nautobot, enforced at deploy time)", "")
    hold(page, 3.5)
    page.evaluate("document.getElementById('inv-tunnels').scrollIntoView({block: 'start'})"); time.sleep(0.6)
    caption(page, "Per-tunnel report: model + live state · Export CSV for reporting", "")
    hold(page, 3); page.mouse.wheel(0, 300); time.sleep(0.5); hold(page, 2.5)
    page.evaluate("window.scrollTo(0, 0)"); time.sleep(0.4); move_to(page, "#inv-refresh"); hold(page, 1.5)

    # 5. remove dialog
    page.goto(a.url + "/#provision"); page.wait_for_selector("#devices button.rm"); time.sleep(1)
    caption(page, "Decommission a spoke: Remove… shows exactly what is released and what each headend loses", "power off → Nautobot clean-up → Terraform destroys the hub-side tunnel and BGP neighbour → VM deleted → tests")
    click(page, "#devices button.rm >> nth=-1", settle=2); hold(page, 5); click(page, "#rm-cancel")
    caption(page, "Nautobot · Network-as-Code · Terraform · Robot Framework", "one form, one button, a source of truth kept honest")
    hold(page, 4)
    ctx.close(); browser.close()

# assemble the GIF (downscaled, quantised per frame with a shared-ish palette)
W = 960; imgs = [f.resize((W, int(f.height * W / f.width)), Image.LANCZOS) for f, _ in frames]
durs = [max(80, int(d * 1000)) for _, d in frames]
pal = imgs[0].quantize(colors=256, method=Image.Quantize.MEDIANCUT)
q = [im.quantize(colors=256, palette=pal, dither=Image.Dither.NONE) for im in imgs]
gif = OUT / "portal-demo.gif"; q[0].save(gif, save_all=True, append_images=q[1:], duration=durs, loop=0, optimize=True)
vids = list((OUT / "video").glob("*.webm"))
if vids: vids[0].rename(OUT / "portal-demo.webm")
print(f"{gif} ({gif.stat().st_size / 1e6:.1f} MB, {len(q)} frames, {sum(durs) / 1000:.0f}s)" + (f"; {OUT / 'portal-demo.webm'}" if vids else ""))
