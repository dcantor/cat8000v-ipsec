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
       "dev": api("dcim/devices/", name="east-headend")["results"][0]["id"]}

with sync_playwright() as pw:
    b = pw.chromium.launch(channel="chrome", headless=True); ctx = b.new_context(viewport={"width": 1400, "height": 900}, device_scale_factor=1)
    page = ctx.new_page()
    # ---- portal ----
    page.goto(f"{PORTAL}/#provision"); page.wait_for_selector("#devices tbody tr"); time.sleep(1.5)
    page.screenshot(path=str(OUT / "portal-provision.png"))
    page.click("#add-spoke"); time.sleep(1.2); page.screenshot(path=str(OUT / "portal-wizard-1.png"), clip={"x": 150, "y": 30, "width": 1100, "height": 560})
    page.click("#wiz-next"); time.sleep(2.5); page.screenshot(path=str(OUT / "portal-wizard-2.png"), clip={"x": 150, "y": 30, "width": 1100, "height": 520})
    page.click("#wiz-next"); time.sleep(2.5); page.screenshot(path=str(OUT / "portal-wizard-3.png"), clip={"x": 150, "y": 30, "width": 1100, "height": 720})
    page.click("#wiz-cancel")
    page.click("#devices button.rm >> nth=-1"); time.sleep(1.5); page.screenshot(path=str(OUT / "portal-remove.png"), clip={"x": 250, "y": 30, "width": 900, "height": 560}); page.click("#rm-cancel")
    page.evaluate("document.getElementById('runcard').scrollIntoView({block:'start'})")
    runs = requests.get(f"{PORTAL}/api/runs").json(); ok = next((r for r in runs if r["status"] == "success" and r["mode"] in ("spoke", "hub")), runs[0])
    page.evaluate("id => watch(id)", ok["id"]); time.sleep(3); page.screenshot(path=str(OUT / "portal-run.png"), clip={"x": 760, "y": 0, "width": 640, "height": 900})
    page.goto(f"{PORTAL}/#inventory"); page.wait_for_function("document.querySelectorAll('#inv-tunnels tbody tr').length > 0", timeout=180000); time.sleep(1.5)
    page.screenshot(path=str(OUT / "portal-inventory.png"))
    page.evaluate("document.getElementById('inv-topo').scrollIntoView({block:'start'})"); time.sleep(0.8); page.screenshot(path=str(OUT / "portal-topology.png"))
    page.evaluate("document.getElementById('inv-tunnels').scrollIntoView({block:'start'})"); time.sleep(0.8); page.screenshot(path=str(OUT / "portal-tunnels.png"))
    page.goto(f"{PORTAL}/docs"); time.sleep(3); page.screenshot(path=str(OUT / "portal-swagger.png"))
    # ---- Nautobot ----
    page.goto(f"{NB}/login/"); page.fill("input[name=username]", "admin"); page.fill("input[name=password]", "admin"); page.click("button[type=submit]"); page.wait_for_load_state("networkidle")
    shots = {"nautobot-devices": f"/dcim/devices/?location={ids['loc']}", "nautobot-locations": "/dcim/locations/", "nautobot-vpn": f"/vpn/vpns/{ids['vpn']}/",
             "nautobot-tunnels": f"/vpn/vpn-tunnels/?vpn={ids['vpn']}", "nautobot-tunnel": f"/vpn/vpn-tunnels/{ids['tun']}/", "nautobot-profile": f"/vpn/vpn-profiles/{ids['prof']}/",
             "nautobot-device": f"/dcim/devices/{ids['dev']}/", "nautobot-bgp": "/plugins/bgp/peerings/", "nautobot-compliance": "/plugins/golden-config/config-compliance/"}
    for name, url in shots.items():
        page.goto(NB + url, wait_until="networkidle"); time.sleep(1); page.screenshot(path=str(OUT / f"{name}.png"))
    b.close()
print("\n".join(f"{p.name} {p.stat().st_size // 1024} KB" for p in sorted(OUT.glob("*.png"))))
