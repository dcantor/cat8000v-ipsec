"""The lab's *intent* — everything the web app / seed / tests need to know about the VPN service — as one JSON
document (lab-intent.json in the lab root).  The document is generated from lab.conf the first time
(`./lab.sh intent init`) and afterwards edited by the web app; lab.conf stays the truth for what libvirt built
(VM names, console ports, management addresses, physical wiring of the p2p links)."""
import datetime, hashlib, ipaddress, json, re, secrets, string, subprocess
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
INTENT_FILE = LAB / "lab-intent.json"
IOS_NAMES = {"ikev2_proposal": "VPN-PROP", "ikev2_policy": "VPN-POL", "ikev2_keyring": "VPN-KEYRING", "keyring_peer": "ANY",
             "ikev2_profile": "VPN-IKEV2", "transform_set": "VPN-TS", "ipsec_profile": "VPN-IPSEC"}


def lab_conf(*names):
    out = subprocess.run(["bash", "-c", f"source {LAB}/lab.conf; declare -p {' '.join(names)}"], capture_output=True, text=True, check=True).stdout
    return {n: dict(re.findall(r'\[([\w-]+)\]="([^"]*)"', re.search(rf"declare -[aA] {n}=\((.*?)\)\n", out, re.S).group(1))) for n in names}


def wiring():
    """Physical p2p links from lab.conf: [{a, a_port, b, b_port}] — the web app cannot change these."""
    C = lab_conf("LINKS")
    out = []
    for l in C["LINKS"].values():
        a_end, b_end, _ = l.split(); (an, ap), (bn, bp) = a_end.split(":"), b_end.split(":")
        out.append({"a": an, "a_port": int(ap), "b": bn, "b_port": int(bp)})
    return out


def nodes():
    """VM facts from lab.conf keyed by management IP: name, node index (MAC/loopback numbering), role, console port."""
    C = lab_conf("ROLE", "MGMT_IP", "NODE_IDX", "CONSOLE_PORT")
    return {C["MGMT_IP"][n]: {"node": n, "idx": int(C["NODE_IDX"][n]), "role": C["ROLE"][n], "console": int(C["CONSOLE_PORT"][n])} for n in C["ROLE"]}


def scalars(*names):
    out = subprocess.run(["bash", "-c", f"source {LAB}/lab.conf; for v in {' '.join(names)}; do echo \"${{!v}}\"; done"], capture_output=True, text=True, check=True).stdout.splitlines()
    return dict(zip(names, out))


def from_lab_conf():
    C = lab_conf("ROLE", "MGMT_IP", "BGP_AS", "LAN", "LINKS", "TUNNELS", "NODE_IDX")
    devices = []
    for n in sorted(C["ROLE"]):
        if C["ROLE"][n] == "firewall":
            devices.append({"name": n, "mgmt_ip": C["MGMT_IP"][n], "role": "firewall", "hub": None, "comments": ""})   # hub filled in from the links below
        elif C["ROLE"][n] == "host":
            devices.append({"name": n, "mgmt_ip": C["MGMT_IP"][n], "role": "host", "router": None, "comments": ""})   # router filled in from its LAN link below
        else:
            devices.append({"name": n, "mgmt_ip": C["MGMT_IP"][n], "role": C["ROLE"][n], "asn": int(C["BGP_AS"][n]),
                            "router_id": f"10.255.1.{C['NODE_IDX'][n]}", "lan": C["LAN"][n], "comments": ""})
    links = []
    for l in C["LINKS"].values():
        a_end, b_end, pfx = l.split(); (an, ap), (bn, bp) = a_end.split(":"), b_end.split(":")
        links.append({"a": an, "a_port": int(ap), "b": bn, "b_port": int(bp), "prefix": pfx})
    for d in devices:   # a firewall fronts the headend on its eth1 link; a host hangs off its router's LAN port (eth1)
        if d["role"] == "firewall":
            d["hub"] = next((l["b"] for l in links if l["a"] == d["name"] and l["a_port"] == 1), None)
        if d["role"] == "host":
            d["router"] = next((l["a"] for l in links if l["b"] == d["name"] and l["b_port"] == 1), None)
    tunnels = []
    for t in C["TUNNELS"].values():   # "id hub spoke prefix" (older 3-field form: the single hub is implied)
        f = t.split(); hub = f[1] if len(f) == 4 else next(n for n in C["ROLE"] if C["ROLE"][n] == "hub")
        tunnels.append({"id": int(f[0]), "hub": hub, "spoke": f[-2], "prefix": f[-1]})
    return {
        "site": {"name": "c8000v-ipsec-lab", "description": "C8000v IPsec VTI lab (libvirt)", "site_code": "LAB-IPSEC", "contact": "noc@lab.local"},
        "vpn": {"name": "IPSEC_VPN", "description": "Hub-and-spoke IPsec VTIs with eBGP (one AS per site)", "change_ticket": "", "owner": "network team"},
        "profile": {"name": "VPN-IPSEC", "ike": {"encryption": "AES-256-CBC", "integrity": "SHA256", "dh_group": "14", "lifetime": 86400, "authentication": "psk"},
                    # ike.authentication "certificate": every router enrols with the lab CA (pki/ca.py, nautobot/pki.py) and IKEv2 uses rsa-sig; the pre-shared keys stay
                    # in the intent, unused, so the lab can switch back
                    "pki": {"trustpoint": "LAB-CA", "keypair": "LAB-VPN", "key_bits": 2048, "validity_days": 365, "renew_before_days": 30, "certificate_map": "LAB-CERT-MAP"},
                    "ipsec": {"encryption": "AES-256-CBC", "integrity": "SHA256", "lifetime": 3600},
                    "dpd": {"enabled": True, "interval": 30, "retries": 5}, "ios": dict(IOS_NAMES)},
        "regions": list(DEFAULT_REGIONS),
        "devices": devices, "links": links, "tunnels": tunnels,
        "oob": {"vrf": "Mgmt-vrf", "gateway": "10.2.0.1", "acl": "MGMT-ACCESS", "prefix": "10.2.0.0/24"},
        "domain_name": "lab.local",
        "capacity": {"tunnels_per_headend": 50, "bandwidth_per_tunnel_mbps": 8},
    }


DEFAULT_REGIONS = ["East", "Central", "West"]


def new_psk(n=24):
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(n))


def upgrade(I):
    """Bring older documents up to the current shape (multi-hub tunnels, per-spoke PSKs, region/branch per device)."""
    hubs = [d["name"] for d in I.get("devices", []) if d.get("role") == "hub"]
    for t in I.get("tunnels", []):
        t.setdefault("hub", hubs[0] if hubs else None)
    I.setdefault("regions", list(DEFAULT_REGIONS))
    I.setdefault("capacity", {}); I["capacity"].setdefault("tunnels_per_headend", 50); I["capacity"].setdefault("bandwidth_per_tunnel_mbps", 8)
    hub_of = {d["name"]: d for d in I.get("devices", [])}
    for i, d in enumerate(I.get("devices", [])):
        if d.get("role") == "spoke" and not d.get("psk"): d["psk"] = I.get("psk") or new_psk()   # legacy shared key, else a fresh one
        if d.get("role") == "firewall":   # a firewall lives at its headend's site
            h = hub_of.get(d.get("hub")) or {}
            d.setdefault("region", h.get("region", I["regions"][0])); d.setdefault("site", h.get("site", f"{d['name']}-site")); continue
        d.setdefault("region", I["regions"][i % len(I["regions"])])
        d.setdefault("site", f"{d['name']}-site" if d.get("role") == "hub" else f"branch-{re.sub(r'[^0-9]', '', d['name']) or i}")
        d.setdefault("site_code", (I.get("site") or {}).get("site_code", "")); d.setdefault("contact", (I.get("site") or {}).get("contact", ""))
    I.pop("psk", None)
    I.setdefault("provider", dict(PROVIDER))
    for d in I.get("devices", []):
        if d.get("role") == "spoke" and not d.get("customer"): d["customer"] = fake_customer(d["name"], d.get("city"))   # every branch is a customer
        if d.get("role") == "hub" and not d.get("address"): d["address"] = fake_address(d["name"], d.get("city"))   # ACME's regional site
    return I


def load(path=None):
    p = Path(path) if path else INTENT_FILE
    return upgrade(json.loads(p.read_text()) if p.exists() else from_lab_conf())


AUTHS = ("psk", "certificate")
# ---- customers and the provider -------------------------------------------------------------------------------------------------
# Every branch is a customer of ACME, the provider that sells the VPN service and owns the headends and their firewalls. A customer
# (company, address, industry, account, service tier, contract start) lives on the spoke in the intent and becomes a Nautobot tenant;
# the ACME design pattern of a branch is not stored: it follows from how many tunnels (headends) the branch has.
PROVIDER = {"name": "ACME Networks", "group": "Service provider", "address": "1 ACME Plaza, Chicago, IL 60601",
            "description": "sells the managed IPsec VPN service: owns the headends, their firewalls and the LAN hosts behind the headends"}
PATTERNS = {0: {"code": "ACME-NC", "name": "Not connected", "description": "no tunnel yet"},
            1: {"code": "ACME-SH", "name": "Single headend", "description": "one tunnel to the nearest headend; no redundancy"},
            2: {"code": "ACME-DH", "name": "Dual headend (resilient)", "description": "two tunnels to the two nearest headends; either carries the branch"},
            3: {"code": "ACME-MH", "name": "Multi headend (any-region)", "description": "a tunnel to three or more headends; the branch reaches every region directly"}}
TIERS = ("Bronze", "Silver", "Gold")
INDUSTRIES = ("Logistics", "Retail", "Healthcare", "Financial services", "Manufacturing", "Education", "Hospitality", "Legal", "Media", "Energy")
_ADJ = ("Bluewater", "Northwind", "Summit", "Ironwood", "Harbor", "Redstone", "Silverline", "Copperfield", "Pinecrest", "Granite", "Evergreen", "Lakeside", "Meridian", "Cascade", "Beacon")
_NOUN = {"Logistics": ("Logistics", "Freight", "Distribution"), "Retail": ("Retail Group", "Stores", "Outfitters"), "Healthcare": ("Health", "Medical Group", "Clinics"),
         "Financial services": ("Capital", "Financial", "Trust"), "Manufacturing": ("Industries", "Manufacturing", "Works"), "Education": ("Academy", "Learning", "Schools"),
         "Hospitality": ("Hospitality", "Hotels", "Resorts"), "Legal": ("Law Group", "Legal", "Partners"), "Media": ("Media", "Studios", "Publishing"), "Energy": ("Energy", "Power", "Utilities")}
_SUFFIX = ("Inc.", "LLC", "Corp.", "Co.", "Ltd.")
_STREET = ("Main St", "Oak Ave", "Market St", "Commerce Blvd", "Industrial Pkwy", "Harbor Dr", "Lakeshore Rd", "Union Ave", "Maple St", "Enterprise Way")


def _h(*parts):
    return int.from_bytes(hashlib.sha256("|".join(str(p) for p in parts).encode()).digest()[:8], "big")


def fake_address(name, city):
    """A deterministic street address in the device's city (the city carries the state)."""
    h = _h(name, "addr"); c = city or "Springfield, IL"
    return f"{100 + h % 9800} {_STREET[h % len(_STREET)]}, Suite {100 + (h >> 8) % 800}, {c} {10000 + (h >> 16) % 89999}"


def fake_customer(name, city):
    """A deterministic fake customer for a branch: company, address, industry, account id, service tier, contract start."""
    h = _h(name, "cust"); ind = INDUSTRIES[h % len(INDUSTRIES)]
    company = f"{_ADJ[(h >> 4) % len(_ADJ)]} {_NOUN[ind][(h >> 8) % 3]} {_SUFFIX[(h >> 12) % len(_SUFFIX)]}"
    start = datetime.date(2023, 1, 1) + datetime.timedelta(days=(h >> 16) % 1200)
    return {"company": company, "address": fake_address(name, city), "industry": ind, "account_id": f"ACME-{100000 + (h >> 24) % 900000}",
            "service_tier": TIERS[(h >> 32) % len(TIERS)], "contract_start": start.isoformat()}


def customer(I, name):
    """The customer of a branch (stored on the spoke; generated once by upgrade()). Headends have none — they are ACME's."""
    d = next((x for x in I["devices"] if x["name"] == name), None) or {}
    return d.get("customer") if d.get("role") == "spoke" else None


def design_pattern(I, name):
    """The ACME design pattern of a branch: it follows from the number of tunnels (headends) the branch has (1 / 2 / 3+). A headend's
    "pattern" is the number of branches it serves — reported, not a pattern."""
    d = next((x for x in I["devices"] if x["name"] == name), None) or {}
    tuns = [t for t in I.get("tunnels") or [] if name in (t["hub"], t["spoke"])]
    if d.get("role") != "spoke": return {"code": "ACME-HE", "name": "Service headend", "description": f"ACME headend serving {len(tuns)} branch tunnel(s)", "tunnels": len(tuns)}
    return {**PATTERNS[min(len(tuns), 3)], "tunnels": len(tuns)}


def default_auth(I): return ((I.get("profile") or {}).get("ike") or {}).get("authentication", "psk")
def spoke_auth(I, name):
    """How a spoke authenticates IKEv2: its own choice (device ike_authentication — picked in the wizard, changeable later) or the
    lab default (profile.ike.authentication). Headends follow their spokes: one IKEv2 profile per method in use."""
    d = next((x for x in I["devices"] if x["name"] == name), None) or {}
    return d.get("ike_authentication") or default_auth(I)
def auths_in_use(I):
    """The authentication methods any tunnel uses (plus the default, so the primary profile always exists)."""
    return {default_auth(I)} | {spoke_auth(I, t["spoke"]) for t in I.get("tunnels") or []}
def router_auths(I, name):
    """The methods a router's tunnels use: a spoke has one, a headend as many as its spokes chose."""
    return {spoke_auth(I, t["spoke"]) for t in I.get("tunnels") or [] if name in (t["hub"], t["spoke"])}
def tunnel_wans(I):
    """Per tunnel: the WAN addresses IKE runs between — {"id", "hub", "spoke", "hub_wan", "spoke_wan", "auth"}."""
    out = []
    for t in I.get("tunnels") or []:
        sl, fw = wan_path(I, t["hub"], t["spoke"])
        if not sl: continue
        hl = next((l for l in I["links"] if {l["a"], l["b"]} == {fw, t["hub"]}), None) if fw else sl
        sw = list(ipaddress.IPv4Network(sl["prefix"]).hosts()); hw = list(ipaddress.IPv4Network(hl["prefix"]).hosts())
        out.append({"id": int(t["id"]), "hub": t["hub"], "spoke": t["spoke"], "spoke_wan": str(sw[1] if sl["b"] == t["spoke"] else sw[0]),
                    "hub_wan": str(hw[1] if hl["b"] == t["hub"] else hw[0]), "auth": spoke_auth(I, t["spoke"])})
    return out
def cert_routers(I): return sorted(d["name"] for d in I["devices"] if d["role"] in ("hub", "spoke") and "certificate" in router_auths(I, d["name"]))
def profile_names(I, auth):
    """Cisco object names of the IKEv2 / IPsec profile for an authentication method: the intent's names for the default method,
    suffixed -PSK / -CERT for the other one (so a lab can run both at once, and switching the default renames nothing on most routers)."""
    ios = dict((I.get("profile") or {}).get("ios") or {}); suffix = "" if auth == default_auth(I) else ("-CERT" if auth == "certificate" else "-PSK")
    return {**ios, "ikev2_profile": ios["ikev2_profile"] + suffix, "ipsec_profile": ios["ipsec_profile"] + suffix, "profile": (I.get("profile") or {}).get("name", "VPN-IPSEC") + suffix, "auth": auth}

LAN_PORT = {"hub": 9, "spoke": 5}   # the last port of a router is its site LAN (HUB_LAN_PORT / SPOKE_LAN_PORT in lab.conf)
def lan_port(I, router):
    """The router's LAN port number: from lab.conf when present, else the defaults."""
    d = next((x for x in I["devices"] if x["name"] == router), None) or {}
    sc = scalars("HUB_LAN_PORT", "SPOKE_LAN_PORT") if (LAB / "lab.conf").exists() else {}
    return int(sc.get("HUB_LAN_PORT") or LAN_PORT["hub"]) if d.get("role") == "hub" else int(sc.get("SPOKE_LAN_PORT") or LAN_PORT["spoke"])
def host_of(I, router):
    """The LAN host behind a router (device role host with router = it), or None."""
    return next((d["name"] for d in I["devices"] if d.get("role") == "host" and d.get("router") == router), None)
def is_lan_link(I, link):
    """A link is a LAN link when one end is a host (the router's LAN /24, .1 on the router, .2 on the host)."""
    roles = {d["name"]: d.get("role") for d in I["devices"]}
    return "host" in (roles.get(link.get("a")), roles.get(link.get("b")))

def internet(I):
    """The internet breakout settings (intent `internet`): enabled, the firewalls' uplink port, and — per spoke — the headends in the
    order it should prefer for its default route (its own region first, then by region distance)."""
    b = dict(I.get("internet") or {}); b.setdefault("enabled", False); b.setdefault("uplink_port", 9)
    hubs = [d for d in I["devices"] if d["role"] == "hub"]
    b["preference"] = {d["name"]: [h["name"] for h in sorted((h for h in hubs if any(t["hub"] == h["name"] and t["spoke"] == d["name"] for t in I.get("tunnels") or [])),
                                                            key=lambda h: (region_distance(I, d.get("region"), h.get("region")), h["name"]))] for d in I["devices"] if d["role"] == "spoke"}
    return b

def firewall_of(I, hub):
    """The firewall fronting a headend (None when the headend is wired directly)."""
    return next((d["name"] for d in I["devices"] if d.get("role") == "firewall" and d.get("hub") == hub), None)


def wan_path(I, hub, spoke):
    """The link a hub<->spoke tunnel rides on: direct, or via the hub's firewall. Returns (link, via_firewall)."""
    for l in I.get("links") or []:
        if {l.get("a"), l.get("b")} == {hub, spoke}: return l, None
    fw = firewall_of(I, hub)
    if fw:
        for l in I.get("links") or []:
            if {l.get("a"), l.get("b")} == {fw, spoke}: return l, fw
    return None, fw


def headend_capacity(I, hub):
    """Both constraints for a headend: tunnel slots and the bandwidth of its firewall (each tunnel commits a fixed share).
    The aggregate is the binding one — the higher utilisation — and the effective free slots the smaller remainder."""
    cap = I.get("capacity") or {}; slots = int(cap.get("tunnels_per_headend") or 50); per = int(cap.get("bandwidth_per_tunnel_mbps") or 0)
    used = sum(1 for t in I.get("tunnels") or [] if t.get("hub") == hub)
    fw = next((d for d in I["devices"] if d.get("role") == "firewall" and d.get("hub") == hub), None)
    bw = int(fw.get("bandwidth_mbps") or 0) if fw else None
    out = {"tunnels": used, "tunnel_capacity": slots, "tunnel_free": max(slots - used, 0), "tunnel_utilisation": round(100 * used / slots, 1) if slots else None,
           "firewall": fw["name"] if fw else None, "bandwidth_mbps": bw, "bandwidth_per_tunnel_mbps": per, "bandwidth_used_mbps": used * per}
    if bw and per:
        out.update({"bandwidth_free_mbps": max(bw - used * per, 0), "bandwidth_utilisation": round(100 * used * per / bw, 1), "bandwidth_tunnel_capacity": bw // per})
        out["binding"] = "bandwidth" if out["bandwidth_utilisation"] >= out["tunnel_utilisation"] else "tunnels"
        out["aggregate_utilisation"] = max(out["bandwidth_utilisation"], out["tunnel_utilisation"])
        out["effective_capacity"] = min(slots, out["bandwidth_tunnel_capacity"]); out["effective_free"] = min(out["tunnel_free"], (bw - used * per) // per if per else out["tunnel_free"])
    else:
        out.update({"binding": "tunnels", "aggregate_utilisation": out["tunnel_utilisation"], "effective_capacity": slots, "effective_free": out["tunnel_free"]})
    return out


def region_distance(I, a, b):
    """How far apart two regions are (their distance in the ordered regions list)."""
    r = I.get("regions") or DEFAULT_REGIONS
    return abs(r.index(a) - r.index(b)) if a in r and b in r else len(r)


def nearest_hubs(I, region, n=2):
    hubs = [d for d in I["devices"] if d["role"] == "hub"]
    return [h["name"] for h in sorted(hubs, key=lambda h: (region_distance(I, region, h.get("region")), h["name"]))[:n]]


def save(intent, path=None):
    (Path(path) if path else INTENT_FILE).write_text(json.dumps(intent, indent=2) + "\n")


def validate(intent):
    """Return a list of problems (empty = valid).  Checks shape, addressing and that the links match the wiring."""
    errs = []
    devs = intent.get("devices") or []
    names = [d.get("name", "") for d in devs]
    if len(set(names)) != len(names): errs.append("device hostnames must be unique")
    routers = [d for d in devs if d.get("role") in ("hub", "spoke")]
    for d in devs:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,62}", d.get("name", "")): errs.append(f"invalid hostname {d.get('name')!r}")
        if d.get("role") == "firewall":
            try: ipaddress.IPv4Address(d.get("mgmt_ip", ""))
            except ValueError: errs.append(f"{d.get('name')}: mgmt_ip {d.get('mgmt_ip')!r} is not an IPv4 address")
            if d.get("hub") not in {x["name"] for x in devs if x.get("role") == "hub"}: errs.append(f"{d.get('name')}: hub {d.get('hub')!r} is not a headend")
            if not (1 <= int(d.get("bandwidth_mbps") or 0) <= 100000): errs.append(f"{d.get('name')}: bandwidth_mbps must be 1..100000")
            continue
        if d.get("role") == "host":   # a LAN host: management address, the router it hangs off (its LAN link is the router's LAN /24)
            try: ipaddress.IPv4Address(d.get("mgmt_ip", ""))
            except ValueError: errs.append(f"{d.get('name')}: mgmt_ip {d.get('mgmt_ip')!r} is not an IPv4 address")
            r = next((x for x in devs if x.get("name") == d.get("router")), None)
            if not r or r.get("role") not in ("hub", "spoke"): errs.append(f"{d.get('name')}: router {d.get('router')!r} is not a router")
            elif not any({l.get("a"), l.get("b")} == {d["name"], r["name"]} and l.get("prefix") == r.get("lan") for l in intent.get("links") or []):
                errs.append(f"{d.get('name')}: needs a LAN link to {r['name']} with prefix {r.get('lan')}")
            continue
        for f in ("mgmt_ip", "router_id"):
            try: ipaddress.IPv4Address(d.get(f, ""))
            except ValueError: errs.append(f"{d.get('name')}: {f} {d.get(f)!r} is not an IPv4 address")
        try:
            n = ipaddress.IPv4Network(d.get("lan", ""), strict=True)
            if n.prefixlen != 24: errs.append(f"{d.get('name')}: LAN {d.get('lan')} must be a /24 (classful BGP network statement)")
        except ValueError: errs.append(f"{d.get('name')}: LAN {d.get('lan')!r} is not a network")
        if not (1 <= int(d.get("asn") or 0) <= 4294967295): errs.append(f"{d.get('name')}: ASN out of range")
    hubs = [d["name"] for d in devs if d.get("role") == "hub"]
    if not hubs: errs.append("at least one hub is required")
    if len(set(d["router_id"] for d in routers)) != len(routers): errs.append("router-ids must be unique")
    if len(set(d["lan"] for d in routers)) != len(routers): errs.append("LAN prefixes must be unique")
    fw_hubs = [d.get("hub") for d in devs if d.get("role") == "firewall"]
    if len(set(fw_hubs)) != len(fw_hubs): errs.append("at most one firewall per headend")
    known = nodes(); by_ip = {d["mgmt_ip"]: d for d in devs}
    for ip, n in known.items():
        if ip not in by_ip: errs.append(f"VM {n['node']} ({ip}) is missing from the devices")
        elif by_ip[ip].get("role") != n["role"]: errs.append(f"{by_ip[ip]['name']} ({ip}) must be a {n['role']} (wiring)")
    for ip in by_ip:
        if ip not in known: errs.append(f"no VM has management address {ip}")
    # links must be the physical wiring, expressed in the (possibly renamed) hostnames
    rename = {n["node"]: by_ip[ip]["name"] for ip, n in known.items() if ip in by_ip}
    want = sorted((rename.get(w["a"], w["a"]), w["a_port"], rename.get(w["b"], w["b"]), w["b_port"]) for w in wiring())
    have = sorted((l.get("a"), int(l.get("a_port") or 0), l.get("b"), int(l.get("b_port") or 0)) for l in intent.get("links") or [])
    if want != have: errs.append(f"links must match the physical wiring: {want}")
    used = set()
    for l in intent.get("links") or []:
        try:
            n = ipaddress.IPv4Network(l.get("prefix", ""), strict=True)
            if is_lan_link(intent, l):
                if n.prefixlen != 24: errs.append(f"LAN link {l.get('a')}-{l.get('b')}: prefix must be the router's /24")
            elif n.prefixlen != 30: errs.append(f"link {l.get('a')}-{l.get('b')}: prefix must be a /30")
            if n in used: errs.append(f"prefix {n} used twice")
            used.add(n)
        except ValueError: errs.append(f"link {l.get('a')}-{l.get('b')}: bad prefix {l.get('prefix')!r}")
    spokes = {d["name"] for d in devs if d.get("role") == "spoke"}
    tunnels = intent.get("tunnels") or []
    ids = [t.get("id") for t in tunnels]
    if len(set(ids)) != len(ids): errs.append("tunnel ids must be unique")
    pairs = [(t.get("hub"), t.get("spoke")) for t in tunnels]
    if len(set(pairs)) != len(pairs): errs.append("at most one tunnel per hub/spoke pair")
    for t in tunnels:
        if t.get("hub") not in hubs: errs.append(f"tunnel {t.get('id')}: {t.get('hub')!r} is not a hub")
        if t.get("spoke") not in spokes: errs.append(f"tunnel {t.get('id')}: {t.get('spoke')!r} is not a spoke")
        if wan_path(intent, t.get("hub"), t.get("spoke"))[0] is None: errs.append(f"tunnel {t.get('id')}: no link between {t.get('hub')} (or its firewall) and {t.get('spoke')}")
    for sp in spokes:
        if not any(t.get("spoke") == sp for t in tunnels): errs.append(f"spoke {sp} has no tunnel")
    cap = int((intent.get("capacity") or {}).get("tunnels_per_headend") or 50)
    for h in hubs:
        n = sum(1 for t in tunnels if t.get("hub") == h)
        if n > cap: errs.append(f"headend capacity exceeded on {h}: {n} tunnels > {cap}")
        hc = headend_capacity(intent, h)
        if hc.get("bandwidth_mbps") and hc["bandwidth_used_mbps"] > hc["bandwidth_mbps"]:
            errs.append(f"firewall bandwidth exceeded on {h}: {n} tunnels x {hc['bandwidth_per_tunnel_mbps']} Mbps = {hc['bandwidth_used_mbps']} > {hc['bandwidth_mbps']} Mbps ({hc['firewall']})")
    for t in tunnels:
        if not (1 <= int(t.get("id") or 0) <= 2147483647): errs.append(f"tunnel to {t.get('spoke')}: bad id")
        try:
            n = ipaddress.IPv4Network(t.get("prefix", ""), strict=True)
            if n.prefixlen != 30: errs.append(f"tunnel {t.get('id')}: prefix must be a /30")
            if n in used: errs.append(f"prefix {n} used twice")
            used.add(n)
        except ValueError: errs.append(f"tunnel {t.get('id')}: bad prefix {t.get('prefix')!r}")
    pr = intent.get("profile") or {}
    ENC = {"AES-128-CBC", "AES-192-CBC", "AES-256-CBC", "AES-128-GCM", "AES-256-GCM"}; INT = {"SHA1", "SHA256", "SHA384", "SHA512", "MD5"}
    if (pr.get("ike") or {}).get("encryption") not in ENC: errs.append("IKE encryption not supported")
    if (pr.get("ike") or {}).get("integrity") not in INT: errs.append("IKE integrity not supported")
    if str((pr.get("ike") or {}).get("dh_group")) not in {"14", "19", "20", "21", "24"}: errs.append("IKE DH group not supported")
    if (pr.get("ipsec") or {}).get("encryption") not in ENC: errs.append("IPsec encryption not supported")
    if (pr.get("ipsec") or {}).get("integrity") not in INT: errs.append("IPsec integrity not supported")
    if (pr.get("ike") or {}).get("authentication", "psk") not in ("psk", "certificate"): errs.append("IKE authentication: psk or certificate")
    pki = pr.get("pki") or {}
    for k in ("trustpoint", "keypair", "certificate_map"):
        if k in pki and not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", str(pki[k])): errs.append(f"pki {k}: letters/digits/_-")
    if pki and not (int(pki.get("key_bits", 2048)) in (2048, 3072, 4096) and 30 <= int(pki.get("validity_days", 365)) <= 3650 and 1 <= int(pki.get("renew_before_days", 30)) < int(pki.get("validity_days", 365))):
        errs.append("pki: key_bits 2048/3072/4096, validity_days 30-3650, renew_before_days below validity_days")
    dpd = pr.get("dpd") or {}
    if dpd.get("enabled") and not (10 <= int(dpd.get("interval") or 0) <= 3600 and 2 <= int(dpd.get("retries") or 0) <= 60): errs.append("DPD interval 10-3600 s, retries 2-60")
    regions = intent.get("regions") or []
    if not regions: errs.append("at least one region is required")
    sites = {}
    for d in devs:
        if d.get("role") == "spoke" and not re.fullmatch(r"[A-Za-z0-9_.-]{8,64}", d.get("psk") or ""): errs.append(f"{d.get('name')}: pre-shared key must be 8-64 characters, letters/digits/_.-")
        if d.get("ike_authentication") is not None and (d.get("role") != "spoke" or d["ike_authentication"] not in AUTHS): errs.append(f"{d.get('name')}: ike_authentication is psk or certificate, on spokes only")
        if d.get("region") not in regions: errs.append(f"{d.get('name')}: region {d.get('region')!r} is not one of {regions}")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,60}", d.get("site") or ""): errs.append(f"{d.get('name')}: site name missing or invalid")
        if d.get("site") in sites and sites[d["site"]] != d.get("region"): errs.append(f"site {d['site']} is placed in two regions")
        if (d.get("lat") is None) != (d.get("lon") is None): errs.append(f"{d.get('name')}: lat and lon go together")
        if d.get("lat") is not None and not (-90 <= float(d["lat"]) <= 90 and -180 <= float(d["lon"]) <= 180): errs.append(f"{d.get('name')}: lat/lon out of range")
        sites[d.get("site")] = d.get("region")
    inet = intent.get("internet") or {}
    if inet and not isinstance(inet.get("enabled", False), bool): errs.append("internet.enabled: true or false")
    if inet and not (1 <= int(inet.get("uplink_port", 9)) <= 20): errs.append("internet.uplink_port: 1..20")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", (intent.get("vpn") or {}).get("name", "")): errs.append("VPN name: letters/digits/_-")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", pr.get("name", "")): errs.append("profile name: letters/digits/_-")
    return errs


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        if INTENT_FILE.exists() and "--force" not in sys.argv: sys.exit(f"{INTENT_FILE} exists (use --force)")
        save(from_lab_conf()); print(f"wrote {INTENT_FILE}")
    elif len(sys.argv) > 1 and sys.argv[1] == "validate":
        e = validate(load(sys.argv[2] if len(sys.argv) > 2 else None)); print("\n".join(e) or "valid"); sys.exit(1 if e else 0)
    else:
        print(json.dumps(load(), indent=2))
