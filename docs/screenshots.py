#!/usr/bin/env python3
"""Capture README screenshots of the portal and of Nautobot (docs/screenshots/*.png)."""
import subprocess, time
from pathlib import Path
from playwright.sync_api import sync_playwright
import requests

LAB = Path(__file__).resolve().parents[1]; OUT = LAB / "docs" / "screenshots"; OUT.mkdir(exist_ok=True)
PORTAL = "http://localhost:8090"; NB = "http://10.0.0.10:8080"
TOKEN = subprocess.run(["bash", "-c", f"cd {LAB} && ./lab.sh nautobot token"], capture_output=True, text=True).stdout.strip(); H = {"Authorization": f"Token {TOKEN}"}
def api(path, **p): return requests.get(f"{NB}/api/{path}", params=p, headers=H, timeout=30).json()
ids = {"loc": api("dcim/locations/", name="c8000v-ipsec-lab")["results"][0]["id"], "vpn": api("vpn/vpns/")["results"][0]["id"],
       "tun": api("vpn/vpn-tunnels/", name="east-headend-spoke1")["results"][0]["id"], "prof": api("vpn/vpn-profiles/", name="VPN-IPSEC")["results"][0]["id"],
       "dev": api("dcim/devices/", name="east-headend")["results"][0]["id"], "spoke": api("dcim/devices/", name="spoke3")["results"][0]["id"]}

with sync_playwright() as pw:
    b = pw.chromium.launch(channel="chrome", headless=True); ctx = b.new_context(viewport={"width": 1400, "height": 900}, device_scale_factor=1)
    page = ctx.new_page()
    # ---- portal ----
    page.goto(f"{PORTAL}/#provision"); page.wait_for_selector("#login-form"); time.sleep(1.0)
    page.screenshot(path=str(OUT / "portal-login.png"), clip={"x": 480, "y": 150, "width": 440, "height": 420})
    page.evaluate("""fetch('/api/login', {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify({username: 'admin', password: 'admin'})})""")   # the lab's default approver (webapp/users.example.json)
    time.sleep(1); page.reload(); page.wait_for_function("document.querySelector('#who b') !== null", timeout=30000); page.wait_for_selector("#devices tbody tr"); time.sleep(1.5)
    page.screenshot(path=str(OUT / "portal-provision.png"))
    page.evaluate("document.getElementById('devices').scrollIntoView({block:'start'})"); time.sleep(0.6); page.screenshot(path=str(OUT / "portal-routers.png"), clip={"x": 0, "y": 0, "width": 1400, "height": 520})
    page.click("#devices button.auth >> nth=0"); time.sleep(1.5); page.screenshot(path=str(OUT / "portal-change-auth.png"), clip={"x": 250, "y": 30, "width": 900, "height": 620}); page.click("#auth-cancel")
    page.click("#add-spoke"); time.sleep(1.2)
    page.screenshot(path=str(OUT / "portal-wizard-1.png"), clip={"x": 150, "y": 30, "width": 1100, "height": 760}); page.click("#wiz-next"); time.sleep(2.5); page.screenshot(path=str(OUT / "portal-wizard-2.png"), clip={"x": 150, "y": 30, "width": 1100, "height": 520})
    page.click("#wiz-next"); time.sleep(2.5); page.screenshot(path=str(OUT / "portal-wizard-3.png"), clip={"x": 150, "y": 30, "width": 1100, "height": 720})
    page.click("#wiz-cancel")
    page.click("#devices button.rm >> nth=-1"); time.sleep(1.5); page.screenshot(path=str(OUT / "portal-remove.png"), clip={"x": 250, "y": 30, "width": 900, "height": 560}); page.click("#rm-cancel")
    page.evaluate("document.getElementById('runcard').scrollIntoView({block:'start'})")
    runs = requests.get(f"{PORTAL}/api/runs").json(); ok = next((r for r in runs if r["status"] == "success" and r["mode"] in ("spoke", "hub")), runs[0])
    page.evaluate("id => watchInline(id)", ok["id"]); time.sleep(3); page.screenshot(path=str(OUT / "portal-run.png"), clip={"x": 760, "y": 0, "width": 640, "height": 900})
    # Jobs: the list of everything the portal has run, and one job's own page (steps, live log, test report)
    page.goto(f"{PORTAL}/#jobs"); page.wait_for_function("document.querySelectorAll('#jobs-table tbody tr').length > 0", timeout=60000); time.sleep(1.0)
    page.screenshot(path=str(OUT / "portal-jobs.png"), clip={"x": 0, "y": 0, "width": 1400, "height": 820})
    job = next((r for r in runs if r.get("tests")), ok)
    page.goto(f"{PORTAL}/#job/{job['id']}"); page.wait_for_function("document.querySelectorAll('#job-steps li').length > 0", timeout=60000); time.sleep(2.5)
    page.screenshot(path=str(OUT / "portal-job.png"), clip={"x": 0, "y": 0, "width": 1400, "height": 980})
    page.goto(f"{PORTAL}/#home"); page.wait_for_function("document.querySelectorAll('#inv-kpis .kpi').length > 0", timeout=180000); time.sleep(1.5)
    page.screenshot(path=str(OUT / "portal-inventory.png"))
    page.evaluate("document.getElementById('inv-topo').scrollIntoView({block:'start'})"); time.sleep(0.8); page.screenshot(path=str(OUT / "portal-topology.png"))
    # the schematic view as well: it shows the DCI chain (interconnect + acquisition edge) as its own row, linked by dashed eBGP lines
    page.evaluate("document.querySelector('input[name=\"topo-view\"][value=\"schematic\"]').checked = true; renderTopologyView(); document.getElementById('inv-topo').scrollIntoView({block:'start'})")
    time.sleep(1.0); page.evaluate("const c = document.getElementById('inv-topo'); c.scrollLeft = c.scrollWidth"); time.sleep(0.5)
    page.screenshot(path=str(OUT / "portal-topology-schematic.png"), clip={"x": 0, "y": 0, "width": 1400, "height": 660})
    page.evaluate("document.querySelector('input[name=\"topo-view\"][value=\"map\"]').checked = true; renderTopologyView()"); time.sleep(0.8)
    page.evaluate("document.getElementById('inv-capacity').parentElement.scrollIntoView({block:'start'})"); time.sleep(0.8); page.screenshot(path=str(OUT / "portal-capacity.png"), clip={"x": 0, "y": 0, "width": 1400, "height": 560})
    # the tunnel report and the LAN hosts live on the Inventory page now
    page.goto(f"{PORTAL}/#inventory"); page.wait_for_function("document.querySelectorAll('#inv-tunnels tbody tr').length > 0", timeout=180000); time.sleep(1.5)
    page.evaluate("document.getElementById('inv-tunnels').scrollIntoView({block:'start'})"); time.sleep(0.8); page.screenshot(path=str(OUT / "portal-tunnels.png"))
    page.evaluate("document.getElementById('inv-hosts').parentElement.parentElement.parentElement.scrollIntoView({block:'start'})"); page.click("#hosts-ping"); page.wait_for_function("document.querySelectorAll('#hosts-matrix table tr').length > 2", timeout=120000); time.sleep(0.8)
    page.screenshot(path=str(OUT / "portal-hosts.png"), clip={"x": 0, "y": 0, "width": 1400, "height": 620})
    page.goto(f"{PORTAL}/#inventory"); page.wait_for_function("document.querySelectorAll('#brs-table tbody tr').length > 0", timeout=120000)
    page.evaluate("window.scrollTo(0, 0)"); time.sleep(1); page.screenshot(path=str(OUT / "portal-branches.png"), clip={"x": 0, "y": 0, "width": 1400, "height": 900})
    page.goto(f"{PORTAL}/#branch/spoke3"); page.wait_for_function("document.querySelectorAll('#br-tunnels tbody tr').length > 0", timeout=120000); page.wait_for_function("document.getElementById('br-show').textContent.includes('READY')", timeout=60000); time.sleep(1)
    page.screenshot(path=str(OUT / "portal-branch.png"))
    page.wait_for_function("document.getElementById('br-config').textContent.includes('hostname')", timeout=120000)
    page.evaluate("localStorage.setItem('cfg-theme', 'dark'); applyCodeTheme(); document.getElementById('br-config').scrollIntoView({block:'start'}); window.scrollBy(0, -150)"); time.sleep(0.8)
    page.screenshot(path=str(OUT / "portal-branch-config.png"), clip={"x": 0, "y": 0, "width": 1400, "height": 760})
    page.evaluate("localStorage.setItem('portal-theme', 'dark'); applyTheme()"); page.goto(f"{PORTAL}/#home"); page.wait_for_function("document.querySelectorAll('#inv-kpis .kpi').length > 0", timeout=180000); time.sleep(1.5)
    page.evaluate("window.scrollTo(0, 0)"); time.sleep(0.5); page.screenshot(path=str(OUT / "portal-dark.png")); page.evaluate("localStorage.removeItem('portal-theme'); applyTheme()")
    page.goto(f"{PORTAL}/#firewalls"); page.wait_for_function("document.querySelectorAll('#fw-cards .card').length > 0", timeout=180000); time.sleep(1); page.screenshot(path=str(OUT / "portal-firewalls.png"))
    page.goto(f"{PORTAL}/#compliance"); page.wait_for_function("document.querySelectorAll('#cmp-table tbody tr').length > 0", timeout=60000); time.sleep(0.8); page.screenshot(path=str(OUT / "portal-compliance.png"), clip={"x": 0, "y": 0, "width": 1400, "height": 900})
    page.goto(f"{PORTAL}/#audit"); page.wait_for_function("document.querySelectorAll('#audit-table tbody tr').length > 0", timeout=60000); time.sleep(0.8); page.screenshot(path=str(OUT / "portal-audit.png"), clip={"x": 0, "y": 0, "width": 1400, "height": 520})
    page.goto(f"{PORTAL}/docs"); time.sleep(3); page.screenshot(path=str(OUT / "portal-swagger.png"))
    # ---- Nautobot ----
    page.goto(f"{NB}/login/"); page.fill("input[name=username]", "admin"); page.fill("input[name=password]", "admin"); page.click("button[type=submit]"); page.wait_for_load_state("networkidle")
    shots = {"nautobot-devices": f"/dcim/devices/?location={ids['loc']}", "nautobot-locations": "/dcim/locations/", "nautobot-vpn": f"/vpn/vpns/{ids['vpn']}/",
             "nautobot-tunnels": f"/vpn/vpn-tunnels/?vpn={ids['vpn']}", "nautobot-tunnel": f"/vpn/vpn-tunnels/{ids['tun']}/", "nautobot-profile": f"/vpn/vpn-profiles/{ids['prof']}/",
             "nautobot-device": f"/dcim/devices/{ids['dev']}/", "nautobot-bgp": "/plugins/bgp/peerings/", "nautobot-compliance": "/plugins/golden-config/config-compliance/",
             "nautobot-tenants": "/tenancy/tenants/?tenant_group=Customers", "nautobot-branch-device": f"/dcim/devices/{ids['spoke']}/"}
    for name, url in shots.items():
        page.goto(NB + url, wait_until="networkidle"); time.sleep(1); page.screenshot(path=str(OUT / f"{name}.png"))
    b.close()
print("\n".join(f"{p.name} {p.stat().st_size // 1024} KB" for p in sorted(OUT.glob("*.png"))))
