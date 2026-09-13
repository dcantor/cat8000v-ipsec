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
    I = intent_mod.load(); hubs = [d for d in I["devices"] if d["role"] == "hub"]
    wiring = intent_mod.wiring()
    def ports_used(n): return {w["a_port"] for w in wiring if w["a"] == n} | {w["b_port"] for w in wiring if w["b"] == n}
    return {"C": C, "sc": sc, "I": I, "hubs": hubs, "hub": hubs[0], "wiring": wiring, "ports_used": ports_used,
            "hub_ports": range(2, 2 + int(sc["HUB_PORTS"] or 2)), "spoke_ports": range(2, 2 + int(sc["SPOKE_PORTS"] or 2)),
            "capacity": int((I.get("capacity") or {}).get("tunnels_per_headend") or 50)}


def _next_free(cands, used):
    for c in cands:
        if c not in used: return c
    return None


def _used_prefixes(I):
    return {ipaddress.IPv4Network(l["prefix"]) for l in I["links"]} | {ipaddress.IPv4Network(t["prefix"]) for t in I["tunnels"]}


def suggest_links(I, f, spoke_name, hubs, spoke_ports_taken=()):
    """One link + tunnel allocation per hub: hub port, spoke port, WAN /30, tunnel id, tunnel /30."""
    used_pfx = _used_prefixes(I); tids = {int(t["id"]) for t in I["tunnels"]}; sports = set(spoke_ports_taken); out = []
    for h in hubs:
        hub_port = _next_free(f["hub_ports"], f["ports_used"](h)); spoke_port = _next_free(f["spoke_ports"], sports); sports.add(spoke_port)
        tid = _next_free(range(1, 10000), tids); tids.add(tid)
        wan = _next_free((ipaddress.IPv4Network(f"100.65.{k}.0/30") for k in range(1, 255)), used_pfx); used_pfx.add(wan)
        tun = _next_free((ipaddress.IPv4Network(f"172.17.{k}.0/30") for k in range(1, 255)), used_pfx); used_pfx.add(tun)
        out.append({"hub": h, "hub_port": hub_port, "spoke_port": spoke_port, "tunnel_id": tid, "wan_prefix": str(wan), "tunnel_prefix": str(tun),
                    "hub_wan_ip": str(list(wan.hosts())[0]), "spoke_wan_ip": str(list(wan.hosts())[1]), "hub_tunnel_ip": str(list(tun.hosts())[0]), "spoke_tunnel_ip": str(list(tun.hosts())[1]),
                    "hub_ports_free": sorted(set(f["hub_ports"]) - f["ports_used"](h)), "hub_tunnels": sum(1 for t in I["tunnels"] if t["hub"] == h)})
    return out


def suggest_identity(I, C, role):
    idx = max(int(v) for v in C["NODE_IDX"].values()) + 1
    n = 1
    while f"{role}{n}" in C["ROLE"] or f"{role}{n}" in {d["name"] for d in I["devices"]} or (role == "hub" and n == 1 and "hub" in C["ROLE"]): n += 1
    oob = ipaddress.IPv4Network(I["oob"]["prefix"]); used_ips = set(C["MGMT_IP"].values()) | {I["oob"]["gateway"], "10.2.0.10"}
    mgmt_ip = _next_free((str(h) for h in list(oob.hosts())[10:]), used_ips)
    rids = {d["router_id"] for d in I["devices"]}; rid = _next_free((f"10.255.1.{k}" for k in range(1, 255)), rids)
    lans = {ipaddress.IPv4Network(d["lan"]) for d in I["devices"]}; lan = _next_free((ipaddress.IPv4Network(f"192.168.{k}.0/24") for k in range(11, 255)), lans)
    asns = {int(d["asn"]) for d in I["devices"]}; base = min(int(d["asn"]) for d in I["devices"]); asn = _next_free(range(base + 1, base + 1000), asns)
    return {"name": f"{role}{n}", "mgmt_ip": mgmt_ip, "node_idx": idx, "console_port": max(int(v) for v in C["CONSOLE_PORT"].values()) + 1,
            "router_id": rid, "lan": str(lan), "asn": asn}


def suggest(hubs=None):
    """Auto-allocated values for the next spoke (all editable in the wizard); `hubs` = names to connect to (default: all)."""
    f = facts(); C, I = f["C"], f["I"]
    hub_names = [h["name"] for h in f["hubs"]]; chosen = [h for h in (hubs or hub_names) if h in hub_names]
    ident = suggest_identity(I, C, "spoke")
    return {**ident, "role": "spoke", "comments": "", "site_code": I["site"].get("site_code", ""), "contact": I["site"].get("contact", ""),
            "change_ticket": I["vpn"].get("change_ticket", ""), "ram_mib": int(f["sc"]["C8000V_RAM_MIB"] or RAM_MIB),
            "links": suggest_links(I, f, ident["name"], chosen),
            "context": {"hubs": [{"name": h["name"], "tunnels": sum(1 for t in I["tunnels"] if t["hub"] == h["name"]), "capacity": f["capacity"],
                                  "ports_free": sorted(set(f["hub_ports"]) - f["ports_used"](h["name"]))} for h in f["hubs"]],
                        "capacity": f["capacity"], "spoke_ports": list(f["spoke_ports"])}}


def suggest_hub():
    """A new headend: identity only; it gets a link + tunnel to every existing spoke (allocated in add_hub_links)."""
    f = facts(); C, I = f["C"], f["I"]; ident = suggest_identity(I, C, "hub")
    spokes = [d["name"] for d in I["devices"] if d["role"] == "spoke"]
    return {**ident, "role": "hub", "comments": "", "change_ticket": I["vpn"].get("change_ticket", ""), "ram_mib": int(f["sc"]["C8000V_RAM_MIB"] or RAM_MIB),
            "connect_spokes": spokes, "context": {"spokes": spokes, "capacity": f["capacity"]}}


def validate(spec):
    """Problems with a spoke spec (with per-hub `links`) against the current lab (empty list = OK)."""
    f = facts(); C, I = f["C"], f["I"]; errs = []
    name = spec.get("name", "")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,30}", name): errs.append("hostname: letters/digits/hyphen, must start with a letter")
    if name in C["ROLE"] or name in {d["name"] for d in I["devices"]}: errs.append(f"{name} already exists")
    try:
        ip = ipaddress.IPv4Address(spec.get("mgmt_ip", ""))
        if ip not in ipaddress.IPv4Network(I["oob"]["prefix"]): errs.append(f"management IP must be in {I['oob']['prefix']}")
        if str(ip) in set(C["MGMT_IP"].values()) | {I["oob"]["gateway"], "10.2.0.10"}: errs.append(f"management IP {ip} is in use")
    except ValueError: errs.append("management IP is not an IPv4 address")
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
    if spec.get("role", "spoke") == "spoke":
        errs += validate_links(spec.get("links") or [], I, f, spec.get("name", ""))
    return errs


def validate_links(links, I, f, name):
    errs = []; hub_names = {h["name"] for h in f["hubs"]}
    if not links: errs.append("connect to at least one hub")
    if len({l.get("hub") for l in links}) != len(links): errs.append("one link per hub")
    used_pfx = _used_prefixes(I); tids = {int(t["id"]) for t in I["tunnels"]}; sports = set()
    for l in links:
        h = l.get("hub")
        if h not in hub_names: errs.append(f"{h!r} is not a hub"); continue
        if int(l.get("hub_port") or 0) not in f["hub_ports"]: errs.append(f"{h}: hub port must be Gi{f['hub_ports'][0]}..Gi{f['hub_ports'][-1]}")
        elif int(l["hub_port"]) in f["ports_used"](h): errs.append(f"{h} Gi{l['hub_port']} is already wired")
        sp = int(l.get("spoke_port") or 0)
        if sp not in f["spoke_ports"]: errs.append(f"{h}: spoke port must be Gi{f['spoke_ports'][0]}..Gi{f['spoke_ports'][-1]}")
        elif sp in sports: errs.append(f"spoke port Gi{sp} used for two hubs")
        sports.add(sp)
        if sum(1 for t in I["tunnels"] if t["hub"] == h) + 1 > f["capacity"]: errs.append(f"headend capacity exceeded on {h}")
        tid = int(l.get("tunnel_id") or 0)
        if tid in tids or not (1 <= tid <= 2147483647): errs.append(f"{h}: tunnel id {tid} in use or out of range")
        tids.add(tid)
        for k, label in (("wan_prefix", "WAN /30"), ("tunnel_prefix", "tunnel /30")):
            try:
                n = ipaddress.IPv4Network(l.get(k, ""), strict=True)
                if n.prefixlen != 30: errs.append(f"{h}: {label} must be a /30")
                if n in used_pfx: errs.append(f"{h}: {label} {n} is in use")
                used_pfx.add(n)
            except ValueError: errs.append(f"{h}: {label} is not a valid network")
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
    p = LAB / "lab.conf"; s = p.read_text(); n = spec["name"]; role = spec.get("role", "spoke")
    shutil.copy(p, LAB / "lab.conf.bak")
    s = _replace_array(s, "ROLE", [f"[{n}]={role}"])
    s = _replace_array(s, "MGMT_IP", [f"[{n}]={spec['mgmt_ip']}"])
    s = _replace_array(s, "BGP_AS", [f"[{n}]={spec['asn']}"])
    s = _replace_array(s, "LAN", [f"[{n}]={spec['lan']}"])
    s = _replace_array(s, "CONSOLE_PORT", [f"[{n}]={spec['console_port']}"])
    s = _replace_array(s, "NODE_IDX", [f"[{n}]={spec['node_idx']}"])
    links = spec.get("links") or []   # the hub is always the first (anchoring) end of a link
    if links:
        s = _replace_array(s, "LINKS", [f"{l['hub']}:{l['hub_port']} {l['spoke']}:{l['spoke_port']} {l['wan_prefix']}" for l in links], multiline=True)
        s = _replace_array(s, "TUNNELS", [f"{l['tunnel_id']} {l['hub']} {l['spoke']} {l['tunnel_prefix']}" for l in links], multiline=True)
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
    I["devices"].append({"name": spec["name"], "mgmt_ip": spec["mgmt_ip"], "role": spec.get("role", "spoke"), "asn": int(spec["asn"]), "router_id": spec["router_id"],
                         "lan": spec["lan"], "comments": spec.get("comments", "")})
    I["devices"].sort(key=lambda d: (d["role"] != "hub", d["name"]))
    for l in spec.get("links") or []:
        I["links"].append({"a": l["hub"], "a_port": int(l["hub_port"]), "b": l["spoke"], "b_port": int(l["spoke_port"]), "prefix": l["wan_prefix"]})
        I["tunnels"].append({"id": int(l["tunnel_id"]), "hub": l["hub"], "spoke": l["spoke"], "prefix": l["tunnel_prefix"]})
    if spec.get("change_ticket"): I["vpn"]["change_ticket"] = spec["change_ticket"]
    problems = intent_mod.validate(I)
    if problems: raise RuntimeError("intent invalid after adding the spoke: " + "; ".join(problems))
    intent_mod.save(I); return I


def hub_changes(spec):
    """What the pipeline will configure on each hub and on the spoke (for the review step)."""
    I = intent_mod.load(); asn_of = {d["name"]: d["asn"] for d in I["devices"]}; out = []
    for l in spec.get("links") or []:
        wan = list(ipaddress.IPv4Network(l["wan_prefix"]).hosts()); tun = list(ipaddress.IPv4Network(l["tunnel_prefix"]).hosts())
        out.append({"hub": l["hub"], "interface": f"GigabitEthernet{l['hub_port']}", "wan_ip": f"{wan[0]}/30", "tunnel": f"Tunnel{l['tunnel_id']}", "tunnel_ip": f"{tun[0]}/30",
                    "tunnel_destination": str(wan[1]), "bgp_neighbor": f"{tun[1]} remote-as {spec['asn']}",
                    "spoke": {"interface": f"GigabitEthernet{l['spoke_port']}", "wan_ip": f"{wan[1]}/30", "tunnel": f"Tunnel{l['tunnel_id']}", "tunnel_ip": f"{tun[1]}/30",
                              "tunnel_destination": str(wan[0]), "bgp_neighbor": f"{tun[0]} remote-as {asn_of.get(l['hub'], '?')}"},
                    "tunnels_after": sum(1 for t in I["tunnels"] if t["hub"] == l["hub"]) + 1, "capacity": int((I.get("capacity") or {}).get("tunnels_per_headend") or 50)})
    return {"links": out, "loopbacks": f"Loopback0 {spec['router_id']}/32, Loopback10 {str(list(ipaddress.IPv4Network(spec['lan']).hosts())[0])}/24"}


def hub_links(hub_name, spokes):
    """Links + tunnels from a new hub to the given existing spokes (each spoke's next free port)."""
    f = facts(); I = f["I"]; out = []
    for sp in spokes:
        used = f["ports_used"](sp)
        alloc = suggest_links(I, f, sp, [hub_name])[0]; alloc["spoke_port"] = _next_free(f["spoke_ports"], used)
        if alloc["spoke_port"] is None: raise RuntimeError(f"{sp} has no free WAN port for {hub_name}")
        alloc["spoke"] = sp; out.append(alloc)
        I["links"].append({"a": hub_name, "a_port": alloc["hub_port"], "b": sp, "b_port": alloc["spoke_port"], "prefix": alloc["wan_prefix"]})
        I["tunnels"].append({"id": alloc["tunnel_id"], "hub": hub_name, "spoke": sp, "prefix": alloc["tunnel_prefix"]})
        f["wiring"].append({"a": hub_name, "a_port": alloc["hub_port"], "b": sp, "b_port": alloc["spoke_port"]})   # so the next allocation sees the port as used
    return out


# ---- removal --------------------------------------------------------------------
def removal_plan(name):
    """What removing a spoke entails (also the validation): returns (problems, details)."""
    I = intent_mod.load(); C = intent_mod.lab_conf("ROLE", "MGMT_IP"); errs = []
    dev = next((d for d in I["devices"] if d["name"] == name), None)
    if dev is None: errs.append(f"{name} is not in the intent")
    elif dev["role"] != "spoke": errs.append("only spokes can be removed")
    if name not in C["ROLE"]: errs.append(f"{name} is not a VM in lab.conf")
    if errs: return errs, None
    cap = int((I.get("capacity") or {}).get("tunnels_per_headend") or 50); links = []
    for t in (t for t in I["tunnels"] if t["spoke"] == name):
        link = next((l for l in I["links"] if {l["a"], l["b"]} == {t["hub"], name}), None)
        hub_port = (link["a_port"] if link["a"] == t["hub"] else link["b_port"]) if link else None
        links.append({"hub": t["hub"], "hub_port": hub_port, "hub_interface": f"GigabitEthernet{hub_port}" if hub_port else None, "wan_prefix": link["prefix"] if link else None,
                      "tunnel_id": t["id"], "tunnel": f"Tunnel{t['id']}", "tunnel_prefix": t["prefix"], "tunnels_after": sum(1 for x in I["tunnels"] if x["hub"] == t["hub"]) - 1, "capacity": cap})
    return [], {"name": name, "mgmt_ip": dev["mgmt_ip"], "asn": dev["asn"], "lan": dev["lan"], "router_id": dev["router_id"], "links": links}


def remove_from_intent(name):
    I = intent_mod.load()
    I["devices"] = [d for d in I["devices"] if d["name"] != name]
    I["links"] = [l for l in I["links"] if name not in (l["a"], l["b"])]
    I["tunnels"] = [t for t in I["tunnels"] if t["spoke"] != name]
    return I   # not saved yet: lab.conf must lose the VM first, or validate() complains about the wiring


def remove_from_lab_conf(name):
    p = LAB / "lab.conf"; s = p.read_text(); shutil.copy(p, LAB / "lab.conf.bak")
    for arr in ("ROLE", "MGMT_IP", "BGP_AS", "LAN", "CONSOLE_PORT", "NODE_IDX"):
        s = re.sub(rf"(\[{re.escape(name)}\]=\S+)\s*", "", s, count=1)
    s = re.sub(rf'^\s*"[^"\n]*\b{re.escape(name)}:\d+[^"\n]*"\n', "", s, flags=re.M)      # LINKS
    s = re.sub(rf'^\s*"\d+ (\S+ )?{re.escape(name)} [^"\n]*"\n', "", s, flags=re.M)         # TUNNELS (3- or 4-field)
    s = re.sub(rf"^(ROUTERS|ALL_NODES)=\((.*?)\)", lambda m: f"{m.group(1)}=({' '.join(x for x in m.group(2).split() if x != name)})", s, flags=re.M)
    p.write_text(s); subprocess.run(["bash", "-n", str(p)], check=True)
    assert name not in intent_mod.lab_conf("ROLE")["ROLE"], "lab.conf update did not take"


def remove_from_nautobot(name, url, token, prefixes=()):
    """Delete the spoke's objects: VPN tunnel + endpoints, BGP peering/instance, device (cascades interfaces), its
    addresses and prefixes, the hub's TunnelN interface + address, the hub WAN port's address; unused AS."""
    import requests
    H = {"Authorization": f"Token {token}", "Accept": "application/json"}; done = []
    def get(path, **params):
        r = requests.get(f"{url}/api/{path}", params=params, headers=H, timeout=60); r.raise_for_status(); return r.json().get("results", [])
    def delete(path, what):
        r = requests.delete(f"{url}/api/{path}", headers=H, timeout=60)
        if r.status_code not in (204, 404): raise RuntimeError(f"delete {what}: {r.status_code} {r.text[:200]}")
        if r.status_code == 204: done.append(what)
    def gql(q):
        r = requests.post(f"{url}/api/graphql/", json={"query": q}, headers=H, timeout=60); r.raise_for_status(); return r.json()["data"]
    devs = get("dcim/devices/", name=name)
    dev = devs[0] if devs else None
    if dev is None: done.append("device already gone from Nautobot")
    # BGP first: the peering references the tunnel addresses on both sides (the spoke's routing instance cascades its endpoint)
    for ri in (get("plugins/bgp/routing-instances/", device=dev["id"]) if dev else []):
        for ep in get("plugins/bgp/peer-endpoints/", routing_instance=ri["id"]):
            pid = (ep.get("peering") or {}).get("id")
            if pid: delete(f"plugins/bgp/peerings/{pid}/", "BGP peering (both endpoints)")
        delete(f"plugins/bgp/routing-instances/{ri['id']}/", "BGP routing instance")
    # the VPN tunnel(s) this spoke terminates, its endpoints, and the hub-side tunnel interface + address
    eps = [] if not dev else gql('{ vpn_tunnel_endpoints(device: ["%s"]) { id endpoint_a_vpn_tunnels { id name endpoint_z { id tunnel_interface { id name device { name } ip_addresses { id } } } } endpoint_z_vpn_tunnels { id name endpoint_a { id tunnel_interface { id name device { name } ip_addresses { id } } } } } }' % name)["vpn_tunnel_endpoints"]
    for ep in eps:
        for t in ep["endpoint_a_vpn_tunnels"] + ep["endpoint_z_vpn_tunnels"]:
            far = t.get("endpoint_z") or t.get("endpoint_a")
            delete(f"vpn/vpn-tunnels/{t['id']}/", f"VPN tunnel {t['name']}")
            if far:
                delete(f"vpn/vpn-tunnel-endpoints/{far['id']}/", "hub tunnel endpoint")
                ti = far.get("tunnel_interface") or {}
                for ip in ti.get("ip_addresses") or []: delete(f"ipam/ip-addresses/{ip['id']}/", f"hub tunnel address")
                if ti.get("id"): delete(f"dcim/interfaces/{ti['id']}/", f"{ti['device']['name']}/{ti['name']}")
        delete(f"vpn/vpn-tunnel-endpoints/{ep['id']}/", "spoke tunnel endpoint")
    # the hub's WAN address on the port facing this spoke (the cable goes with the spoke's interface)
    for itf in (get("dcim/interfaces/", device=name, depth=1) if dev else []):
        for ip in get("ipam/ip-addresses/", interfaces=itf["id"]): delete(f"ipam/ip-addresses/{ip['id']}/", f"address {ip['address']}")
        if itf.get("cable"): delete(f"dcim/cables/{itf['cable']['id']}/", f"cable on {name}/{itf['name']}")   # else it lingers half-terminated on the hub
        ci = itf.get("connected_interface") or {}
        if ci.get("id"):
            for ip in get("ipam/ip-addresses/", interfaces=ci["id"]): delete(f"ipam/ip-addresses/{ip['id']}/", f"hub WAN address {ip['address']}")
    if dev: delete(f"dcim/devices/{dev['id']}/", f"device {name} (interfaces, cable)")
    # its prefixes (WAN /30, tunnel /30, LAN, loopback /32): every address inside them first, then the prefix
    for pfx in prefixes:
        for pf in get("ipam/prefixes/", prefix=pfx):
            for ip in get("ipam/ip-addresses/", parent=pf["id"]): delete(f"ipam/ip-addresses/{ip['id']}/", f"address {ip['address']}")   # parent = prefix UUID
            delete(f"ipam/prefixes/{pf['id']}/", f"prefix {pf['prefix']}")
    for asn in get("plugins/bgp/autonomous-systems/", q=name):
        if re.search(rf"\b{re.escape(name)}\b", asn.get("description") or ""): delete(f"plugins/bgp/autonomous-systems/{asn['id']}/", f"AS {asn['asn']}")
    return done


def forget_in_terraform(name, log):
    """Terraform must not try to talk to a router that no longer exists: drop its resources from the state."""
    env = {**__import__("os").environ, "PATH": f"{Path.home()}/.local/bin:" + __import__("os").environ.get("PATH", "")}
    out = subprocess.run(["terraform", "state", "list"], cwd=LAB / "nac", capture_output=True, text=True, env=env, check=True).stdout.split()
    mine = [r for r in out if f'["{name}/' in r or f'["{name}"]' in r]
    if mine:
        subprocess.run(["terraform", "state", "rm", *mine], cwd=LAB / "nac", check=True, capture_output=True, text=True, env=env)
    log(f"removed {len(mine)} {name} resources from the Terraform state"); return len(mine)


def destroy_vm(name, delete_disk=True):
    subprocess.run([str(LAB / "lab.sh"), "clean" if delete_disk else "down", name], check=True, capture_output=True, text=True)
    if delete_disk: shutil.rmtree(LAB / "nodes" / name, ignore_errors=True)
