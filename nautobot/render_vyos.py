#!/usr/bin/env python3
"""Render and push the VyOS firewalls' configuration from Nautobot.

Per firewall (role vpn-firewall at the lab location): interface addresses/descriptions from the model (eth1 = headend
side, eth2.. = spokes; eth0 = management, left alone), the forward-filter policy from the config context `firewall`
(IKE udp/500+4500, ESP, ICMP and established/related may cross; everything else is dropped and logged), LLDP.
The managed sections are deleted and re-set inside ONE commit, so VyOS itself applies only the difference.
Usage: NAUTOBOT_TOKEN=... render_vyos.py [--check] [--dry-run] [firewall ...]"""
import argparse, os, sys
from pathlib import Path
import requests
sys.path.insert(0, str(Path(__file__).resolve().parent)); import intent as intent_mod   # noqa: E402

p = argparse.ArgumentParser()
p.add_argument("--url", default=os.environ.get("NAUTOBOT_URL", "http://10.0.0.10:8080")); p.add_argument("--token", default=os.environ.get("NAUTOBOT_TOKEN"))
p.add_argument("--user", default=os.environ.get("VYOS_USERNAME", "vyos")); p.add_argument("--password", default=os.environ.get("VYOS_PASSWORD", "vyos"))
p.add_argument("--dry-run", action="store_true", help="print the commands, do not push"); p.add_argument("--check", action="store_true", help="exit 1 if a firewall's running config differs")
p.add_argument("names", nargs="*")
a = p.parse_args(); H = {"Authorization": f"Token {a.token}"}
SITE = intent_mod.load()["site"]["name"]
Q = """{ devices(location: ["%s"], role: ["vpn-firewall"]) { name primary_ip4 { address } config_context
          interfaces { name enabled description mgmt_only ip_addresses { address } connected_interface { name device { name role { name } } } } } }""" % SITE
r = requests.post(f"{a.url}/api/graphql/", json={"query": Q}, headers=H, timeout=60); r.raise_for_status()
fws = [d for d in r.json()["data"]["devices"] if not a.names or d["name"] in a.names]

def commands(dev):
    fw = (dev["config_context"] or {}).get("firewall") or {}; fwd = fw.get("forward") or {}; allow = fwd.get("allow") or []
    out = []
    for i in sorted(dev["interfaces"], key=lambda x: int(x["name"][3:]) if x["name"].startswith("eth") and x["name"][3:].isdigit() else 999):
        if not i["name"].startswith("eth") or i["mgmt_only"] or i["name"] == "eth0": continue
        out.append(f"delete interfaces ethernet {i['name']}")
        if i["enabled"] and i["ip_addresses"]:
            ci = i.get("connected_interface") or {}
            out += [f"set interfaces ethernet {i['name']} address {i['ip_addresses'][0]['address']}",
                    f"set interfaces ethernet {i['name']} description '{i['description'] or ('to ' + (ci.get('device') or {}).get('name', '?'))}'"]
        else:
            out += [f"set interfaces ethernet {i['name']} description 'unwired'", f"set interfaces ethernet {i['name']} disable"]
    out.append("delete firewall")
    out.append(f"set firewall ipv4 forward filter default-action {fwd.get('default_action', 'drop')}")
    out += ["set firewall ipv4 forward filter rule 5 action accept", "set firewall ipv4 forward filter rule 5 state established", "set firewall ipv4 forward filter rule 5 state related",
            "set firewall ipv4 forward filter rule 5 description 'established / related'"]
    n = 10
    for what in allow:
        if what == "ike": out += [f"set firewall ipv4 forward filter rule {n} action accept", f"set firewall ipv4 forward filter rule {n} protocol udp", f"set firewall ipv4 forward filter rule {n} destination port 500,4500", f"set firewall ipv4 forward filter rule {n} description 'IKEv2 / NAT-T'"]
        elif what == "esp": out += [f"set firewall ipv4 forward filter rule {n} action accept", f"set firewall ipv4 forward filter rule {n} protocol esp", f"set firewall ipv4 forward filter rule {n} description 'IPsec ESP'"]
        elif what == "icmp": out += [f"set firewall ipv4 forward filter rule {n} action accept", f"set firewall ipv4 forward filter rule {n} protocol icmp", f"set firewall ipv4 forward filter rule {n} description 'ICMP (underlay reachability tests)'"]
        n += 10
    if fwd.get("log_drops", True): out += ["set firewall ipv4 forward filter rule 900 action drop", "set firewall ipv4 forward filter rule 900 log", "set firewall ipv4 forward filter rule 900 description 'log everything else'"]
    mgmt = fw.get("management") or {}
    if mgmt.get("lldp", True): out += ["delete service lldp", "set service lldp interface all"]
    return out

def push(dev, cmds):
    from netmiko import ConnectHandler
    host = dev["primary_ip4"]["address"].split("/")[0]
    c = ConnectHandler(device_type="vyos", host=host, username=a.user, password=a.password)
    try:
        out = c.send_config_set(cmds + ["commit", "save"], exit_config_mode=True, cmd_verify=False, read_timeout=120)
        bad = [l for l in out.splitlines() if "Invalid" in l or "failed" in l.lower() or "is not valid" in l or "Error" in l]
        if bad: raise RuntimeError(f"{dev['name']}: " + " | ".join(bad)[:400])
        return "no changes" if "No configuration changes to commit" in out else "committed"
    finally: c.disconnect()

def running(dev):
    from netmiko import ConnectHandler
    host = dev["primary_ip4"]["address"].split("/")[0]
    c = ConnectHandler(device_type="vyos", host=host, username=a.user, password=a.password)
    try: return c.send_command("show configuration commands", read_timeout=60)
    finally: c.disconnect()

rc = 0
for dev in fws:
    cmds = commands(dev)
    if a.dry_run: print(f"### {dev['name']}\n" + "\n".join(cmds)); continue
    if a.check:
        have = set(running(dev).splitlines()); want = {c for c in cmds if c.startswith("set ")}
        missing = sorted(w for w in want if w.replace("'", "") not in {h.replace("'", "") for h in have})
        print(f"{dev['name']}: {'in sync' if not missing else str(len(missing)) + ' lines missing: ' + '; '.join(missing[:3])}"); rc |= bool(missing); continue
    print(f"{dev['name']}: {push(dev, cmds)} ({len(cmds)} commands)")
sys.exit(rc)
