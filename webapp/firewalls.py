"""The Firewalls page: the VyOS firewalls' live rule sets (with counters) and their recent firewall log, collected over SSH.

Per firewall (role firewall in the intent, its headend from the wiring): interfaces with addresses and descriptions, the
`forward filter` rule set as `show firewall` prints it (rule, action, protocol, packets, bytes, match conditions) joined with
the rule descriptions from the configuration, and the kernel's firewall log (`show log firewall`) for the last N hours parsed
into fields — rule, verdict, in / out interface, source / destination (resolved to lab device names from the intent's WAN
links), protocol and ports — plus a per-flow summary. Cached for 60 s; `refresh` collects again."""
import concurrent.futures, datetime, ipaddress, os, re, sys, threading, time
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "nautobot")); import intent as intent_mod   # noqa: E402

_cache = {}; _lock = threading.Lock(); TTL = 60
MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
LOG_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d\d:\d\d:\d\d)\s+kernel:\s+\[(?P<tag>[^\]]+)\](?P<rest>.*)$")


def address_names(I):
    """Every WAN / tunnel / LAN address of the lab -> "device (port)" for readable log lines."""
    names = {}
    for l in I.get("links") or []:
        net = ipaddress.IPv4Network(l["prefix"]); hosts = list(net.hosts())
        if len(hosts) >= 2: names[str(hosts[0])] = f"{l['a']} port {l['a_port']}"; names[str(hosts[1])] = f"{l['b']} port {l['b_port']}"
    for t in I.get("tunnels") or []:
        hosts = list(ipaddress.IPv4Network(t["prefix"]).hosts())
        if len(hosts) >= 2: names[str(hosts[0])] = f"{t['hub']} Tunnel{t['id']}"; names[str(hosts[1])] = f"{t['spoke']} Tunnel{t['id']}"
    for d in I.get("devices") or []:
        try:
            if d.get("router_id"): names[str(ipaddress.IPv4Address(d["router_id"]))] = f"{d['name']} Lo0"
            if d.get("lan"): names[str(ipaddress.IPv4Network(d["lan"]).network_address + 1)] = f"{d['name']} Lo10 ({d['lan']})"
        except ValueError: pass   # a firewall carries neither
        names[d["mgmt_ip"]] = f"{d['name']} mgmt"
    return names


def parse_rules(show_fw, config):
    """`show firewall` -> [{ruleset, rule, action, protocol, packets, bytes, conditions, description, log}]."""
    desc = {}; logged = set(); match = {}   # match[(ruleset, rule)] = {"source": {"address", "port"}, "destination": {...}, "state": [...], "inbound", "outbound"}
    groups = {}   # address-group name -> [addresses]
    for line in config.splitlines():
        m = re.match(r"set firewall group address-group (\S+) address '?([^']+)'?$", line)
        if m: groups.setdefault(m[1], []).append(m[2])
    for line in config.splitlines():
        m = re.match(r"set firewall ipv4 (\S+ \S+) rule (\d+) description '(.*)'", line)
        if m: desc[(m[1], m[2])] = m[3]; continue
        m = re.match(r"set firewall ipv4 (\S+ \S+) rule (\d+) log$", line)
        if m: logged.add((m[1], m[2])); continue
        m = re.match(r"set firewall ipv4 (\S+ \S+) rule (\d+) (source|destination) (address|port) '?([^']+)'?$", line)
        if m: match.setdefault((m[1], m[2]), {}).setdefault(m[3], {})[m[4]] = m[5]; continue
        m = re.match(r"set firewall ipv4 (\S+ \S+) rule (\d+) (source|destination) group address-group '?([^']+)'?$", line)
        if m: match.setdefault((m[1], m[2]), {}).setdefault(m[3], {})["address"] = f"{m[4]}: " + ", ".join(groups.get(m[4], ["?"])); continue
        m = re.match(r"set firewall ipv4 (\S+ \S+) rule (\d+) state '?(\w+)'?$", line)
        if m: match.setdefault((m[1], m[2]), {}).setdefault("state", []).append(m[3]); continue
        m = re.match(r"set firewall ipv4 (\S+ \S+) rule (\d+) (inbound|outbound)-interface name '?([^']+)'?$", line)
        if m: match.setdefault((m[1], m[2]), {})[m[3]] = m[4]
    out = []; ruleset = None
    for line in show_fw.splitlines():
        m = re.match(r'^ipv4 Firewall "(.+)"', line)
        if m: ruleset = m[1]; continue
        m = re.match(r"^(\d+|default)\s+(\w+)\s+(\S+)\s+(\d+)\s+(\d+)\s*(.*)$", line)
        if m and ruleset:
            key = (ruleset, m[1])
            mt = match.get(key, {}); src, dst = mt.get("source", {}), mt.get("destination", {})
            out.append({"ruleset": ruleset, "rule": m[1], "action": m[2], "protocol": m[3], "packets": int(m[4]), "bytes": int(m[5]), "conditions": m[6].strip(), "groups": groups,
                        "source": src.get("address", "any"), "source_port": src.get("port", "any"), "destination": dst.get("address", "any"), "destination_port": dst.get("port", "any"),
                        "state": mt.get("state", []), "inbound": mt.get("inbound", "any"), "outbound": mt.get("outbound", "any"),
                        "description": desc.get(key, "default action" if m[1] == "default" else ""), "log": key in logged})
    return out


def parse_log(text, hours, names, now=None):
    """`show log firewall` lines within the last `hours` -> structured entries, newest first."""
    now = now or datetime.datetime.now(); since = now - datetime.timedelta(hours=hours); out = []
    for line in text.splitlines():
        m = LOG_RE.match(line.strip())
        if not m: continue
        try:
            ts = datetime.datetime(now.year, MONTHS[m["mon"]], int(m["day"]), *map(int, m["time"].split(":")))
            if ts > now + datetime.timedelta(days=1): ts = ts.replace(year=now.year - 1)   # a December line read in January
        except (KeyError, ValueError): continue
        if ts < since: continue
        f = dict(re.findall(r"([A-Z]+)=(\S*)", m["rest"])); tag = m["tag"]
        tm = re.match(r"ipv4-(\w+)-filter-(\d+|default)-([A-Z])", tag)
        verdict = {"D": "drop", "A": "accept", "R": "reject"}.get(tm[3], tm[3]) if tm else "?"
        out.append({"time": ts.strftime("%Y-%m-%d %H:%M:%S"), "ts": ts.timestamp(), "tag": tag, "ruleset": (tm[1] + " filter") if tm else None, "rule": tm[2] if tm else None, "verdict": verdict,
                    "in": f.get("IN", ""), "out": f.get("OUT", ""), "src": f.get("SRC", ""), "dst": f.get("DST", ""), "proto": f.get("PROTO", ""), "sport": f.get("SPT", ""), "dport": f.get("DPT", ""),
                    "src_name": names.get(f.get("SRC", "")), "dst_name": names.get(f.get("DST", "")), "len": f.get("LEN", ""), "flags": " ".join(k for k in ("SYN", "ACK", "FIN", "RST") if re.search(rf"\b{k}\b", m["rest"]))})
    out.sort(key=lambda e: e["ts"], reverse=True)
    return out


def summarise(entries):
    """Drops grouped by flow (src -> dst proto/dport), most hits first."""
    flows = {}
    for e in entries:
        k = (e["verdict"], e["src"], e["dst"], e["proto"], e["dport"], e["in"], e["out"])
        f = flows.setdefault(k, {"verdict": e["verdict"], "src": e["src"], "src_name": e["src_name"], "dst": e["dst"], "dst_name": e["dst_name"], "proto": e["proto"], "dport": e["dport"], "in": e["in"], "out": e["out"], "hits": 0, "first": e["time"], "last": e["time"]})
        f["hits"] += 1; f["first"] = min(f["first"], e["time"]); f["last"] = max(f["last"], e["time"])
    return sorted(flows.values(), key=lambda f: -f["hits"])


def collect_one(fw, hours, names, creds):
    from netmiko import ConnectHandler
    c = ConnectHandler(device_type="vyos", host=fw["mgmt_ip"], username=creds[0], password=creds[1], conn_timeout=20)
    try:
        show_fw = c.send_command("show firewall", read_timeout=60); config = c.send_command("show configuration commands | match firewall", read_timeout=60)
        ifs = c.send_command("show interfaces", read_timeout=60); log = c.send_command(f"show log firewall | tail -n 2000", read_timeout=90)
        up = c.send_command("uptime", read_timeout=30)
    finally: c.disconnect()
    interfaces = []
    for line in ifs.splitlines():
        m = re.match(r"^(eth\d+|lo)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s*(.*)$", line)
        if m: interfaces.append({"name": m[1], "address": m[2] if m[2] != "-" else "", "state": m[6], "description": m[7].strip()})
    entries = parse_log(log, hours, names)
    return {**fw, "collected": time.time(), "uptime": up.strip().split("up", 1)[-1].split(",")[0].strip() if "up" in up else "", "interfaces": interfaces,
            "rules": parse_rules(show_fw, config), "log": entries[:500], "log_total": len(entries), "flows": summarise(entries)[:50], "hours": hours}


def collect(hours=3, refresh=False):
    key = hours
    with _lock:
        c = _cache.get(key)
        if c and not refresh and time.time() - c["generated"] < TTL: return c
    I = intent_mod.load(); names = address_names(I)
    fws = [{"name": d["name"], "mgmt_ip": d["mgmt_ip"], "site": d.get("site"), "region": d.get("region"), "city": d.get("city"), "bandwidth_mbps": d.get("bandwidth_mbps"), "hub": intent_mod.hub_of_firewall(I, d["name"]) if hasattr(intent_mod, "hub_of_firewall") else next((h["name"] for h in I["devices"] if h["role"] == "hub" and intent_mod.firewall_of(I, h["name"]) == d["name"]), None)}
           for d in I["devices"] if d["role"] == "firewall"]
    creds = (os.environ.get("VYOS_USERNAME", "vyos"), os.environ.get("VYOS_PASSWORD", "vyos"))
    def one(fw):
        try: return collect_one(fw, hours, names, creds)
        except Exception as e:  # noqa: BLE001
            return {**fw, "error": f"{e.__class__.__name__}: {e}", "interfaces": [], "rules": [], "log": [], "flows": [], "log_total": 0, "hours": hours}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex: result = list(ex.map(one, fws))
    out = {"generated": time.time(), "hours": hours, "firewalls": sorted(result, key=lambda f: f["name"]),
           "policy": (I.get("firewall") or {}) if isinstance(I.get("firewall"), dict) else {}}
    with _lock: _cache[key] = out
    return out
