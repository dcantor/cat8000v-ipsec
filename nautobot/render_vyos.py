#!/usr/bin/env python3
"""Render and push the VyOS firewalls' configuration from Nautobot.

Per firewall (role vpn-firewall at the lab location): interface addresses/descriptions from the model (eth1 = headend
side, eth2.. = spokes; eth0 = management, left alone), the forward-filter policy from the config context `firewall`
(IKE udp/500+4500, ESP, ICMP and established/related may cross; everything else is dropped and logged), LLDP, and the
remote syslog target from the config context `firewall.management.syslog` (VictoriaLogs on the NMS).
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
          interfaces { name enabled description mgmt_only mac_address ip_addresses { address } connected_interface { name device { name role { name } } ip_addresses { address } } } } }""" % SITE
r = requests.post(f"{a.url}/api/graphql/", json={"query": Q}, headers=H, timeout=60); r.raise_for_status()
fws = [d for d in r.json()["data"]["devices"] if not a.names or d["name"] in a.names]

def commands(dev):
    fw = (dev["config_context"] or {}).get("firewall") or {}; fwd = fw.get("forward") or {}; allow = fwd.get("allow") or []
    inet = (dev["config_context"] or {}).get("internet") or {}; uplink = inet.get("uplink") if inet.get("enabled") else None
    out = []
    for i in sorted(dev["interfaces"], key=lambda x: int(x["name"][3:]) if x["name"].startswith("eth") and x["name"][3:].isdigit() else 999):
        if not i["name"].startswith("eth") or i["mgmt_only"] or i["name"] == "eth0": continue
        out.append(f"delete interfaces ethernet {i['name']}")
        if i.get("mac_address"): out.append(f"set interfaces ethernet {i['name']} hw-id {i['mac_address'].lower()}")   # pins the name to the NIC across reboots (VyOS renames unmatched NICs)
        if i["name"] == uplink:   # the internet uplink: DHCP on the libvirt NAT network, no modelled address
            out += [f"set interfaces ethernet {i['name']} address dhcp", f"set interfaces ethernet {i['name']} description '{i['description'] or 'internet uplink'}'"]; continue
        if i["name"] == inet.get("uplink"):   # breakout disabled: the port stays down
            out += [f"set interfaces ethernet {i['name']} description 'internet uplink (breakout disabled)'", f"set interfaces ethernet {i['name']} disable"]; continue
        if i["enabled"] and i["ip_addresses"]:
            ci = i.get("connected_interface") or {}
            out += [f"set interfaces ethernet {i['name']} address {i['ip_addresses'][0]['address']}",
                    f"set interfaces ethernet {i['name']} description '{i['description'] or ('to ' + (ci.get('device') or {}).get('name', '?'))}'"]
        else:
            out += [f"set interfaces ethernet {i['name']} description 'unwired'", f"set interfaces ethernet {i['name']} disable"]
    out.append("delete firewall")
    # the modelled peers: the headend's WAN address (the far end of eth1) and every spoke's WAN address (the far ends of the spoke ports),
    # from Nautobot's cables — IKE and ESP are admitted only between them when the policy says peers_only
    peers = {"hub": [], "spoke": []}
    for i in dev["interfaces"]:
        ci = i.get("connected_interface") or {}
        if not (i["enabled"] and i["ip_addresses"] and ci.get("ip_addresses")): continue
        role = ((ci.get("device") or {}).get("role") or {}).get("name", "")
        if role in ("vpn-hub", "vpn-spoke"): peers["hub" if role == "vpn-hub" else "spoke"].append((ci["ip_addresses"][0]["address"].split("/")[0], (ci.get("device") or {}).get("name", "?")))
    peers_only = bool(fwd.get("peers_only")) and peers["hub"] and peers["spoke"]
    if peers_only:
        out += [f"set firewall group address-group HEADEND-WAN description 'WAN address of the headend behind this firewall'"] + [f"set firewall group address-group HEADEND-WAN address {ip}" for ip, _ in sorted(peers["hub"])]
        out += [f"set firewall group address-group SPOKE-WAN description 'WAN addresses of the spokes cabled to this firewall'"] + [f"set firewall group address-group SPOKE-WAN address {ip}" for ip, _ in sorted(peers["spoke"])]
    out.append(f"set firewall ipv4 forward filter default-action {fwd.get('default_action', 'drop')}")
    out += ["set firewall ipv4 forward filter rule 5 action accept", "set firewall ipv4 forward filter rule 5 state established", "set firewall ipv4 forward filter rule 5 state related",
            "set firewall ipv4 forward filter rule 5 description 'established / related'"]
    n = 10
    log_accepts = bool(fwd.get("log_accepts"))   # the accept rules log their first packet per flow (the rest match rule 5, which never logs)
    def between(rule, src, dst, proto, desc, port=None):
        out.extend([f"set firewall ipv4 forward filter rule {rule} action accept", f"set firewall ipv4 forward filter rule {rule} protocol {proto}"] + ([f"set firewall ipv4 forward filter rule {rule} destination port {port}"] if port else []) +
                   ([f"set firewall ipv4 forward filter rule {rule} source group address-group {src}", f"set firewall ipv4 forward filter rule {rule} destination group address-group {dst}"] if peers_only else []) +
                   ([f"set firewall ipv4 forward filter rule {rule} log"] if log_accepts else []) +
                   [f"set firewall ipv4 forward filter rule {rule} description '{desc}'"])
    for what in allow:
        if what == "ike":
            between(n, "SPOKE-WAN", "HEADEND-WAN", "udp", "IKEv2 / NAT-T, spoke -> headend" if peers_only else "IKEv2 / NAT-T", "500,4500")
            if peers_only: between(n + 1, "HEADEND-WAN", "SPOKE-WAN", "udp", "IKEv2 / NAT-T, headend -> spoke", "500,4500")
        elif what == "esp":
            between(n, "SPOKE-WAN", "HEADEND-WAN", "esp", "IPsec ESP, spoke -> headend" if peers_only else "IPsec ESP")
            if peers_only: between(n + 1, "HEADEND-WAN", "SPOKE-WAN", "esp", "IPsec ESP, headend -> spoke")
        elif what == "icmp": out += [f"set firewall ipv4 forward filter rule {n} action accept", f"set firewall ipv4 forward filter rule {n} protocol icmp"] + ([f"set firewall ipv4 forward filter rule {n} log"] if log_accepts else []) + [f"set firewall ipv4 forward filter rule {n} description 'ICMP (underlay reachability tests)'"]
        n += 10
    # internet breakout: the site LANs (a network group from the config context) may leave through the uplink from the headend side and
    # nothing may come in from it; source NAT (masquerade) on the uplink. The NAT block is replaced whole like the firewall.
    out += ["delete nat source", "delete protocols static route"]
    if uplink and inet.get("nat_sources"):
        out += ["set firewall group network-group SITE-LANS description 'site LANs behind the headend and its spokes (internet breakout)'"] + [f"set firewall group network-group SITE-LANS network {p}" for p in inet["nat_sources"]]
        out += ["set firewall ipv4 forward filter rule 50 action accept", "set firewall ipv4 forward filter rule 50 inbound-interface name eth1", f"set firewall ipv4 forward filter rule 50 outbound-interface name {uplink}",
                "set firewall ipv4 forward filter rule 50 source group network-group SITE-LANS"] + (["set firewall ipv4 forward filter rule 50 log"] if log_accepts else []) + ["set firewall ipv4 forward filter rule 50 description 'internet breakout: site LANs -> uplink (NAT)'"]
        out += [f"set nat source rule 100 outbound-interface name {uplink}", "set nat source rule 100 source group network-group SITE-LANS", "set nat source rule 100 translation address masquerade",
                "set nat source rule 100 description 'internet breakout: masquerade the site LANs'"]
        # the return path: every site LAN sits behind the headend (the far end of eth1) — replies from the internet go back that way
        if peers["hub"]: out += [f"set protocols static route {p} next-hop {peers['hub'][0][0]}" for p in inet["nat_sources"]]   # (no description leaf on VyOS static routes)
    if fwd.get("log_drops", True): out += ["set firewall ipv4 forward filter rule 900 action drop", "set firewall ipv4 forward filter rule 900 log", "set firewall ipv4 forward filter rule 900 description 'log everything else'"]
    mgmt = fw.get("management") or {}
    if mgmt.get("lldp", True): out += ["delete service lldp", "set service lldp interface all"]
    # remote syslog (VictoriaLogs on the NMS): the kernel's firewall log travels with everything else at `level` and up. The remote
    # block is replaced whole so a changed collector address never leaves the old one behind; the local syslog settings are untouched.
    sl = mgmt.get("syslog") or {}
    out.append("delete system syslog remote")
    if sl.get("host"):
        out += [f"set system syslog remote {sl['host']} port {sl.get('port', 514)}", f"set system syslog remote {sl['host']} protocol {sl.get('protocol', 'udp')}",
                f"set system syslog remote {sl['host']} facility all level {sl.get('level', 'info')}"]
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
