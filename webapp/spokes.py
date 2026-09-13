"""Spoke provisioning: allocate everything a new spoke needs (VM identity, hub port, addressing), validate it,
and materialise it (lab.conf, day-0 config, intent).  The VM/bootstrap/onboarding/pipeline steps are run by app.py."""
import ipaddress, re, shutil, subprocess, sys
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "nautobot")); import intent as intent_mod   # noqa: E402

RAM_MIB = 4096


def facts():
    """Current allocations from lab.conf + the intent."""
    C = intent_mod.lab_conf("ROLE", "MGMT_IP", "BGP_AS", "LAN", "NODE_IDX", "CONSOLE_PORT")
    sc = intent_mod.scalars("OOB_GATEWAY", "HUB_PORTS", "SPOKE_PORTS", "C8000V_RAM_MIB")
    I = intent_mod.load(); hub = next(d for d in I["devices"] if d["role"] == "hub")
    wiring = intent_mod.wiring()
    return {"C": C, "sc": sc, "I": I, "hub": hub, "wiring": wiring,
            "hub_ports_used": {w["a_port"] for w in wiring if w["a"] == hub["name"]} | {w["b_port"] for w in wiring if w["b"] == hub["name"]},
            "capacity": int((I.get("capacity") or {}).get("tunnels_per_headend") or 50)}


def _next_free(cands, used):
    for c in cands:
        if c not in used: return c
    return None


def suggest():
    """Auto-allocated values for the next spoke (all editable in the wizard)."""
    f = facts(); C, I, hub = f["C"], f["I"], f["hub"]
    idx = max(int(v) for v in C["NODE_IDX"].values()) + 1
    n = 1
    while f"spoke{n}" in C["ROLE"] or f"spoke{n}" in {d["name"] for d in I["devices"]}: n += 1
    oob = ipaddress.IPv4Network(I["oob"]["prefix"]); used_ips = set(C["MGMT_IP"].values()) | {I["oob"]["gateway"], "10.2.0.10"}
    mgmt_ip = _next_free((str(h) for h in list(oob.hosts())[10:]), used_ips)
    hub_ports = range(2, 2 + int(f["sc"]["HUB_PORTS"] or 2)); hub_port = _next_free(hub_ports, f["hub_ports_used"])
    tids = {int(t["id"]) for t in I["tunnels"]}; tid = _next_free(range(1, 10000), tids)
    used_pfx = {ipaddress.IPv4Network(l["prefix"]) for l in I["links"]} | {ipaddress.IPv4Network(t["prefix"]) for t in I["tunnels"]}
    wan = _next_free((ipaddress.IPv4Network(f"100.65.{k}.0/30") for k in range(1, 255)), used_pfx)
    tun = _next_free((ipaddress.IPv4Network(f"172.17.{k}.0/30") for k in range(1, 255)), used_pfx | {wan})
    rids = {d["router_id"] for d in I["devices"]}; rid = _next_free((f"10.255.1.{k}" for k in range(1, 255)), rids)
    lans = {ipaddress.IPv4Network(d["lan"]) for d in I["devices"]}; lan = _next_free((ipaddress.IPv4Network(f"192.168.{k}.0/24") for k in range(11, 255)), lans)
    asns = {int(d["asn"]) for d in I["devices"]}; asn = _next_free(range(int(hub["asn"]) + 1, int(hub["asn"]) + 1000), asns)
    console = max(int(v) for v in C["CONSOLE_PORT"].values()) + 1
    return {"name": f"spoke{n}", "mgmt_ip": mgmt_ip, "node_idx": idx, "console_port": console, "hub": hub["name"], "hub_port": hub_port, "spoke_port": 2,
            "tunnel_id": tid, "wan_prefix": str(wan), "tunnel_prefix": str(tun), "router_id": rid, "lan": str(lan), "asn": asn, "comments": "",
            "site_code": I["site"].get("site_code", ""), "contact": I["site"].get("contact", ""), "change_ticket": I["vpn"].get("change_ticket", ""),
            "ram_mib": int(f["sc"]["C8000V_RAM_MIB"] or RAM_MIB),
            "context": {"hub": hub["name"], "hub_ports_free": sorted(set(hub_ports) - f["hub_ports_used"]), "tunnels": len(I["tunnels"]), "capacity": f["capacity"],
                        "hub_wan_ip": str(list(wan.hosts())[0]) if wan else None, "spoke_wan_ip": str(list(wan.hosts())[1]) if wan else None,
                        "hub_tunnel_ip": str(list(tun.hosts())[0]) if tun else None, "spoke_tunnel_ip": str(list(tun.hosts())[1]) if tun else None}}


def validate(spec):
    """Problems with a spoke spec against the current lab (empty list = OK)."""
    f = facts(); C, I, hub = f["C"], f["I"], f["hub"]; errs = []
    name = spec.get("name", "")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,30}", name): errs.append("hostname: letters/digits/hyphen, must start with a letter")
    if name in C["ROLE"] or name in {d["name"] for d in I["devices"]}: errs.append(f"{name} already exists")
    try:
        ip = ipaddress.IPv4Address(spec.get("mgmt_ip", ""))
        if ip not in ipaddress.IPv4Network(I["oob"]["prefix"]): errs.append(f"management IP must be in {I['oob']['prefix']}")
        if str(ip) in set(C["MGMT_IP"].values()) | {I["oob"]["gateway"], "10.2.0.10"}: errs.append(f"management IP {ip} is in use")
    except ValueError: errs.append("management IP is not an IPv4 address")
    hub_ports = range(2, 2 + int(f["sc"]["HUB_PORTS"] or 2))
    if int(spec.get("hub_port") or 0) not in hub_ports: errs.append(f"hub port must be Gi2..Gi{hub_ports[-1]}")
    elif int(spec["hub_port"]) in f["hub_ports_used"]: errs.append(f"hub Gi{spec['hub_port']} is already wired")
    if len(I["tunnels"]) + 1 > f["capacity"]: errs.append(f"headend capacity exceeded: {len(I['tunnels']) + 1} tunnels > {f['capacity']}")
    if int(spec.get("tunnel_id") or 0) in {int(t["id"]) for t in I["tunnels"]} or not (1 <= int(spec.get("tunnel_id") or 0) <= 2147483647): errs.append("tunnel id in use or out of range")
    used_pfx = {ipaddress.IPv4Network(l["prefix"]) for l in I["links"]} | {ipaddress.IPv4Network(t["prefix"]) for t in I["tunnels"]}
    for k, label in (("wan_prefix", "WAN /30"), ("tunnel_prefix", "tunnel /30")):
        try:
            n = ipaddress.IPv4Network(spec.get(k, ""), strict=True)
            if n.prefixlen != 30: errs.append(f"{label} must be a /30")
            if n in used_pfx: errs.append(f"{label} {n} is in use")
        except ValueError: errs.append(f"{label} is not a valid network")
    try:
        if spec.get("wan_prefix") and spec.get("tunnel_prefix") and ipaddress.IPv4Network(spec["wan_prefix"]) == ipaddress.IPv4Network(spec["tunnel_prefix"]): errs.append("WAN and tunnel prefixes must differ")
    except ValueError: pass
    try:
        if ipaddress.IPv4Address(spec.get("router_id", "")) in {ipaddress.IPv4Address(d["router_id"]) for d in I["devices"]}: errs.append("router-id in use")
    except ValueError: errs.append("router-id is not an IPv4 address")
    try:
        lan = ipaddress.IPv4Network(spec.get("lan", ""), strict=True)
        if lan.prefixlen != 24: errs.append("site LAN must be a /24")
        if lan in {ipaddress.IPv4Network(d["lan"]) for d in I["devices"]}: errs.append(f"LAN {lan} in use")
    except ValueError: errs.append("site LAN is not a valid network")
    asn = int(spec.get("asn") or 0)
    if not (1 <= asn <= 4294967295): errs.append("ASN out of range")
    if asn in {int(d["asn"]) for d in I["devices"]}: errs.append(f"AS {asn} is in use (one AS per site)")
    if not intent_mod.INTENT_FILE.exists(): errs.append("lab-intent.json missing (run ./lab.sh intent init)")
    avail = int(re.search(r"MemAvailable:\s+(\d+)", Path("/proc/meminfo").read_text())[1]) // 1024
    if avail < int(spec.get("ram_mib") or RAM_MIB) + 1024: errs.append(f"not enough free memory for a {spec.get('ram_mib', RAM_MIB)} MiB VM ({avail} MiB available)")
    return errs


# ---- materialise ------------------------------------------------------------
def _replace_array(text, name, entries, multiline=False):
    """Append entries to a bash array definition in lab.conf ('declare -A NAME=( ... )' or 'NAME=( ... )')."""
    if multiline:
        m = re.search(rf"^{name}=\(\n(.*?)^\)\n", text, re.M | re.S)
        if not m: raise RuntimeError(f"lab.conf: cannot find {name}=(")
        body = m.group(1) + "".join(f'  "{e}"\n' for e in entries)
        return text[:m.start()] + f"{name}=(\n{body})\n" + text[m.end():]
    m = re.search(rf"^(declare -A {name}=\(|{name}=\()(.*?)\)(\s*(#.*)?)$", text, re.M)
    if not m: raise RuntimeError(f"lab.conf: cannot find {name}")
    body = m.group(2).rstrip() + " " + " ".join(entries) + " "
    return text[:m.start()] + f"{m.group(1)}{body}){m.group(3) or ''}" + text[m.end():]


def add_to_lab_conf(spec):
    p = LAB / "lab.conf"; s = p.read_text(); n = spec["name"]
    shutil.copy(p, LAB / "lab.conf.bak")
    s = _replace_array(s, "ROLE", [f"[{n}]=spoke"])
    s = _replace_array(s, "MGMT_IP", [f"[{n}]={spec['mgmt_ip']}"])
    s = _replace_array(s, "BGP_AS", [f"[{n}]={spec['asn']}"])
    s = _replace_array(s, "LAN", [f"[{n}]={spec['lan']}"])
    s = _replace_array(s, "CONSOLE_PORT", [f"[{n}]={spec['console_port']}"])
    s = _replace_array(s, "NODE_IDX", [f"[{n}]={spec['node_idx']}"])
    s = _replace_array(s, "LINKS", [f"{spec['hub']}:{spec['hub_port']} {n}:{spec['spoke_port']} {spec['wan_prefix']}"], multiline=True)
    s = _replace_array(s, "TUNNELS", [f"{spec['tunnel_id']} {n} {spec['tunnel_prefix']}"], multiline=True)
    s = _replace_array(s, "ROUTERS", [n]); s = _replace_array(s, "ALL_NODES", [n])
    p.write_text(s)
    subprocess.run(["bash", "-n", str(p)], check=True)
    C = intent_mod.lab_conf("ROLE"); assert n in C["ROLE"], "lab.conf update did not take"


def write_day0(spec):
    d = LAB / "nodes" / spec["name"]; d.mkdir(exist_ok=True)
    gw = intent_mod.load()["oob"]["gateway"]
    tpl = (LAB / "nodes" / "_template" / "spoke.iosxe_config.txt").read_text()
    (d / "iosxe_config.txt").write_text(tpl.replace("__HOSTNAME__", spec["name"]).replace("__MGMT_IP__", spec["mgmt_ip"]).replace("__GATEWAY__", gw))
    shutil.copy(LAB / "nodes" / "_template" / "spoke.post-boot.txt", d / "post-boot.txt")
    return d


def add_to_intent(spec):
    I = intent_mod.load()
    I["devices"].append({"name": spec["name"], "mgmt_ip": spec["mgmt_ip"], "role": "spoke", "asn": int(spec["asn"]), "router_id": spec["router_id"],
                         "lan": spec["lan"], "comments": spec.get("comments", "")})
    I["devices"].sort(key=lambda d: (d["role"] != "hub", d["name"]))
    I["links"].append({"a": spec["hub"], "a_port": int(spec["hub_port"]), "b": spec["name"], "b_port": int(spec["spoke_port"]), "prefix": spec["wan_prefix"]})
    I["tunnels"].append({"id": int(spec["tunnel_id"]), "spoke": spec["name"], "prefix": spec["tunnel_prefix"]})
    if spec.get("change_ticket"): I["vpn"]["change_ticket"] = spec["change_ticket"]
    problems = intent_mod.validate(I)
    if problems: raise RuntimeError("intent invalid after adding the spoke: " + "; ".join(problems))
    intent_mod.save(I); return I


def hub_changes(spec):
    """What the pipeline will configure on the hub for this spoke (for the review step)."""
    wan = list(ipaddress.IPv4Network(spec["wan_prefix"]).hosts()); tun = list(ipaddress.IPv4Network(spec["tunnel_prefix"]).hosts())
    hub_asn = next(d["asn"] for d in intent_mod.load()["devices"] if d["name"] == spec["hub"])
    return {"hub": spec["hub"], "interface": f"GigabitEthernet{spec['hub_port']}", "wan_ip": f"{wan[0]}/30", "tunnel": f"Tunnel{spec['tunnel_id']}", "tunnel_ip": f"{tun[0]}/30",
            "tunnel_destination": str(wan[1]), "bgp_neighbor": f"{tun[1]} remote-as {spec['asn']}",
            "spoke": {"interface": f"GigabitEthernet{spec['spoke_port']}", "wan_ip": f"{wan[1]}/30", "tunnel": f"Tunnel{spec['tunnel_id']}", "tunnel_ip": f"{tun[1]}/30",
                      "tunnel_destination": str(wan[0]), "bgp_neighbor": f"{tun[0]} remote-as {hub_asn}",
                      "loopbacks": f"Loopback0 {spec['router_id']}/32, Loopback10 {str(list(ipaddress.IPv4Network(spec['lan']).hosts())[0])}/24"}}
