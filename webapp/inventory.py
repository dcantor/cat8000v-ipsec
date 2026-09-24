"""VPN inventory for the portal: the modelled tunnels from Nautobot (core VPN app) joined with live state
collected from each headend (IKEv2 SA, VTI line protocol, eBGP session, ESP counters), plus the headend
capacity (custom field vpn_tunnel_capacity on the hub device, default 50)."""
import concurrent.futures, os, re, threading, time
import requests

DEFAULT_CAPACITY = 50
QUERY = """
{
  vpns {
    id name description service_type status { name } extra_attributes
    vpn_profile { name keepalive_enabled keepalive_interval keepalive_retries
      vpn_phase1_policies { name ike_version encryption_algorithm integrity_algorithm dh_group lifetime_seconds authentication_method }
      vpn_phase2_policies { name encryption_algorithm integrity_algorithm lifetime } }
    vpn_tunnels {
      id name tunnel_id description encapsulation status { name } last_updated
      endpoint_a { id role { name } device { id name primary_ip4 { address } location { name parent { name } } cf_vpn_tunnel_capacity }
                   source_interface { name } source_ipaddress { address } tunnel_interface { name ip_addresses { address } } protected_prefixes { prefix } }
      endpoint_z { id role { name } device { id name primary_ip4 { address } location { name parent { name } } cf_vpn_tunnel_capacity }
                   source_interface { name } source_ipaddress { address } tunnel_interface { name ip_addresses { address } } protected_prefixes { prefix } }
    }
  }
}"""


def _city_of(desc):
    """The city out of a branch location's description — "<what> of <router> — <city> — <owner>" since every site carries its
    customer (or ACME) as well; the middle segment is the city, and an older two-part description ends with it."""
    parts = [p.strip() for p in (desc or "").split(" — ")]
    return parts[1] if len(parts) >= 3 else (parts[1] if len(parts) == 2 else None)


class Inventory:
    def __init__(self, url, public_url, token_fn, username="admin", password="admin", ttl=30):
        self.url, self.public_url, self.token_fn, self.creds, self.ttl = url, public_url, token_fn, (username, password), ttl
        self._cache, self._lock = None, threading.Lock()

    # ---- Nautobot ----------------------------------------------------------
    def devices(self):
        """VPN routers for the topology map: role, management IP, AS, site LAN (the router's LAN port), serial."""
        q = """{ devices(role: ["vpn-hub", "vpn-spoke", "vpn-firewall", "vpn-dci", "partner-edge"], location: ["%s"]) { id name serial role { name } primary_ip4 { address } location { name description latitude longitude cf_site_code cf_contact parent { name } } cf_firewall_bandwidth_mbps
                 bgp_routing_instances { autonomous_system { asn } router_id { address } }
                 interfaces { name ip_addresses { address parent { prefix role { name } } } } } }"""
        import sys; from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "nautobot")); import intent as intent_mod
        q = q % intent_mod.load()["site"]["name"]
        r = requests.post(f"{self.url}/api/graphql/", json={"query": q}, headers={"Authorization": f"Token {self.token_fn()}"}, timeout=60); r.raise_for_status()
        out = []
        for d in r.json()["data"]["devices"]:
            ri = (d["bgp_routing_instances"] or [{}])[0]
            lo = next((ip for i in (d["interfaces"] or []) for ip in (i.get("ip_addresses") or []) if ((ip.get("parent") or {}).get("role") or {}).get("name") == "site-lan"), {})
            out.append({"name": d["name"], "role": {"vpn-hub": "hub", "vpn-spoke": "spoke", "vpn-firewall": "firewall", "vpn-dci": "dci", "partner-edge": "partner"}[d["role"]["name"]], "mgmt_ip": (d["primary_ip4"] or {}).get("address", "").split("/")[0],
                        "site": (d["location"] or {}).get("name"), "region": ((d["location"] or {}).get("parent") or {}).get("name"),
                        "site_code": (d["location"] or {}).get("cf_site_code"), "contact": (d["location"] or {}).get("cf_contact"), "serial": d["serial"],
                        # where the site is (Nautobot Location latitude / longitude, the city from its description) for the map
                        "lat": float((d["location"] or {}).get("latitude")) if (d["location"] or {}).get("latitude") is not None else None,
                        "lon": float((d["location"] or {}).get("longitude")) if (d["location"] or {}).get("longitude") is not None else None,
                        "city": _city_of((d["location"] or {}).get("description")), "bandwidth_mbps": d.get("cf_firewall_bandwidth_mbps"), "asn": (ri.get("autonomous_system") or {}).get("asn"),
                        "router_id": (ri.get("router_id") or {}).get("address", "").split("/")[0], "lan": (lo.get("parent") or {}).get("prefix"),
                        "url": f"{self.public_url}/dcim/devices/{d['id']}/"})
        # a firewall's headend: the device on the far side of its eth1 (from Nautobot cables)
        q2 = """{ interfaces(device: [%s], name: "eth1") { device { name } connected_interface { device { name } } } }""" % ", ".join('"%s"' % d["name"] for d in out if d["role"] == "firewall")
        if any(d["role"] == "firewall" for d in out):
            r2 = requests.post(f"{self.url}/api/graphql/", json={"query": q2}, headers={"Authorization": f"Token {self.token_fn()}"}, timeout=60).json()
            hub_of = {i["device"]["name"]: (i.get("connected_interface") or {}).get("device", {}).get("name") for i in r2.get("data", {}).get("interfaces", [])}
            for d in out:
                if d["role"] == "firewall": d["hub"] = hub_of.get(d["name"])
        return sorted(out, key=lambda d: ({"hub": 0, "firewall": 1, "spoke": 2, "dci": 3, "partner": 4}.get(d["role"], 9), d["name"]))

    def model(self):
        r = requests.post(f"{self.url}/api/graphql/", json={"query": QUERY}, headers={"Authorization": f"Token {self.token_fn()}"}, timeout=60)
        r.raise_for_status(); data = r.json()
        if data.get("errors"): raise RuntimeError(data["errors"])
        tunnels, headends = [], {}
        for v in data["data"]["vpns"]:
            prof = v["vpn_profile"] or {}; p1 = (prof.get("vpn_phase1_policies") or [{}])[0]; p2 = (prof.get("vpn_phase2_policies") or [{}])[0]
            for t in v["vpn_tunnels"]:
                a, z = t["endpoint_a"] or {}, t["endpoint_z"] or {}
                # the headend is the endpoint with role "hub" (falls back to A)
                hub, spoke = (a, z) if (a.get("role") or {}).get("name") != "spoke" else (z, a)
                hd = hub.get("device") or {}; hname = hd.get("name") or "?"
                headends.setdefault(hname, {"name": hname, "location": (hd.get("location") or {}).get("name"), "region": ((hd.get("location") or {}).get("parent") or {}).get("name"), "mgmt_ip": (hd.get("primary_ip4") or {}).get("address", "").split("/")[0],
                                            "capacity": hd.get("cf_vpn_tunnel_capacity") or DEFAULT_CAPACITY, "tunnels": 0, "url": f"{self.public_url}/dcim/devices/{hd.get('id')}/"})
                headends[hname]["tunnels"] += 1
                tunnels.append({
                    "id": t["id"], "name": t["name"], "tunnel_id": t["tunnel_id"], "description": t["description"], "encapsulation": t["encapsulation"],
                    "model_status": (t["status"] or {}).get("name"), "last_updated": t["last_updated"], "url": f"{self.public_url}/vpn/vpn-tunnels/{t['id']}/",
                    "vpn": v["name"], "vpn_status": (v["status"] or {}).get("name"), "change_ticket": (v["extra_attributes"] or {}).get("change_ticket", ""),
                    "owner": (v["extra_attributes"] or {}).get("owner", ""), "profile": prof.get("name"),
                    "ike": f"IKEv2 {'/'.join(p1.get('encryption_algorithm') or [])} {'/'.join(p1.get('integrity_algorithm') or [])} DH{'/'.join(p1.get('dh_group') or [])}",
                    "ipsec": f"ESP {'/'.join(p2.get('encryption_algorithm') or [])} {'/'.join(p2.get('integrity_algorithm') or [])}",
                    "dpd": f"{prof.get('keepalive_interval')}s x{prof.get('keepalive_retries')}" if prof.get("keepalive_enabled") else "off",
                    "headend": hname, "headend_if": (hub.get("tunnel_interface") or {}).get("name"), "headend_src_if": (hub.get("source_interface") or {}).get("name"),
                    "headend_src_ip": (hub.get("source_ipaddress") or {}).get("address", "").split("/")[0],
                    "headend_tunnel_ip": ((hub.get("tunnel_interface") or {}).get("ip_addresses") or [{}])[0].get("address", ""),
                    "spoke": (spoke.get("device") or {}).get("name"), "spoke_site": ((spoke.get("device") or {}).get("location") or {}).get("name"),
                    "spoke_region": (((spoke.get("device") or {}).get("location") or {}).get("parent") or {}).get("name"),
                    "headend_region": ((hd.get("location") or {}).get("parent") or {}).get("name"),
                    "spoke_mgmt_ip": ((spoke.get("device") or {}).get("primary_ip4") or {}).get("address", "").split("/")[0],
                    "spoke_if": (spoke.get("tunnel_interface") or {}).get("name"), "spoke_src_if": (spoke.get("source_interface") or {}).get("name"),
                    "spoke_src_ip": (spoke.get("source_ipaddress") or {}).get("address", "").split("/")[0],
                    "spoke_tunnel_ip": ((spoke.get("tunnel_interface") or {}).get("ip_addresses") or [{}])[0].get("address", ""),
                    "protected_prefixes": [p["prefix"] for p in spoke.get("protected_prefixes") or []],
                    "live": None})
        devices = self.devices()
        per = max((int((v["extra_attributes"] or {}).get("bandwidth_per_tunnel_mbps") or 0) for v in data["data"]["vpns"]), default=0)
        for h in headends.values():
            h["free"] = max(h["capacity"] - h["tunnels"], 0); h["utilisation"] = round(100 * h["tunnels"] / h["capacity"], 1) if h["capacity"] else None
            # second constraint: the firewall in front of the headend and its bandwidth; each tunnel commits `per` Mbps
            fw = next((d for d in devices if d["role"] == "firewall" and d.get("hub") == h["name"]), None)
            bw = int(fw["bandwidth_mbps"] or 0) if fw and fw.get("bandwidth_mbps") else None
            h.update({"firewall": fw["name"] if fw else None, "bandwidth_mbps": bw, "bandwidth_per_tunnel_mbps": per, "bandwidth_used_mbps": h["tunnels"] * per})
            if bw and per:
                h["bandwidth_free_mbps"] = max(bw - h["tunnels"] * per, 0); h["bandwidth_utilisation"] = round(100 * h["tunnels"] * per / bw, 1); h["bandwidth_tunnel_capacity"] = bw // per
                h["binding"] = "bandwidth" if h["bandwidth_utilisation"] >= (h["utilisation"] or 0) else "tunnels"
                h["aggregate_utilisation"] = max(h["bandwidth_utilisation"], h["utilisation"] or 0)
                h["effective_capacity"] = min(h["capacity"], h["bandwidth_tunnel_capacity"]); h["effective_free"] = min(h["free"], (bw - h["tunnels"] * per) // per)
            else:
                h.update({"binding": "tunnels", "aggregate_utilisation": h["utilisation"], "effective_capacity": h["capacity"], "effective_free": h["free"]})
        # the DCI chain: eBGP over direct links instead of tunnels (west-headend <-> DCI <-> the acquired company's edge) — the
        # topology draws them as plain links, and a branch's route to the acquisition's prefixes arrives over the tunnels above
        import sys as _sys; from pathlib import Path as _Path
        _sys.path.insert(0, str(_Path(__file__).resolve().parents[1] / "nautobot")); import intent as _intent
        _I = _intent.load()
        peerings = [{**p, "a_asn": next((d.get("asn") for d in devices if d["name"] == p["a"]), None),
                     "b_asn": next((d.get("asn") for d in devices if d["name"] == p["b"]), None)} for p in _intent.direct_peerings(_I)]
        return {"tunnels": sorted(tunnels, key=lambda x: (x["headend"], int(x["tunnel_id"] or 0))), "headends": sorted(headends.values(), key=lambda h: h["name"]), "devices": devices,
                "peerings": peerings,
                "vpns": [{"name": v["name"], "status": (v["status"] or {}).get("name"), "tunnels": len(v["vpn_tunnels"]), "profile": (v["vpn_profile"] or {}).get("name"),
                          "url": f"{self.public_url}/vpn/vpns/{v['id']}/"} for v in data["data"]["vpns"]]}

    # ---- live state from the headends -------------------------------------
    def live(self, headends, tunnels):
        out = {}
        def collect(h):
            try: return h["name"], self.collect_headend(h["mgmt_ip"])
            except Exception as e:  # noqa: BLE001
                return h["name"], {"error": str(e)}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            for name, state in ex.map(collect, headends): out[name] = state
        for t in tunnels:
            st = out.get(t["headend"]) or {}
            if "error" in st: t["live"] = {"error": st["error"]}; continue
            ike = st["ike"].get(t["spoke_src_ip"], {}); bgp = st["bgp"].get(t["spoke_tunnel_ip"].split("/")[0], {})
            ifc = st["ifaces"].get(t["headend_if"] or "", {}); sa = st["ipsec"].get(t["headend_if"] or "", {})
            t["live"] = {"ike_status": ike.get("status", "none"), "ike_active_s": ike.get("active"), "line_protocol": ifc.get("proto"), "admin": ifc.get("status"),
                         "bgp_state": bgp.get("state"), "bgp_prefixes": bgp.get("prefixes"), "bgp_updown": bgp.get("updown"),
                         "encaps": sa.get("encaps"), "decaps": sa.get("decaps"), "send_errors": sa.get("send_err"), "recv_errors": sa.get("recv_err"),
                         "in_rate_bps": ifc.get("in_bps"), "out_rate_bps": ifc.get("out_bps"), "last_input": ifc.get("last_input"), "last_output": ifc.get("last_output")}
            up = t["live"]["ike_status"] == "READY" and t["live"]["line_protocol"] == "up" and str(t["live"]["bgp_state"] or "").isdigit()
            t["live"]["health"] = "up" if up else ("degraded" if t["live"]["ike_status"] == "READY" else "down")
        return {h: {"error": s["error"]} if "error" in s else {"collected": s["collected"], "ike_sessions": len(s["ike"]), **s["resources"]} for h, s in out.items()}

    def collect_headend(self, host):
        from netmiko import ConnectHandler
        c = ConnectHandler(device_type="cisco_xe", host=host, username=self.creds[0], password=self.creds[1], fast_cli=False)
        try:
            ike_out = c.send_command("show crypto ikev2 sa", read_timeout=30)
            brief = c.send_command("show ip interface brief | include Tunnel", read_timeout=30)
            bgp_out = c.send_command("show bgp ipv4 unicast summary | begin Neighbor", read_timeout=30)
            ipsec_out = c.send_command("show crypto ipsec sa", read_timeout=60)
            res_out = c.send_command("show platform resources", read_timeout=30)   # control-plane CPU, data-plane (QFP) CPU, DRAM with the platform's own thresholds
            ifaces = {}
            for line in brief.splitlines():
                m = re.match(r"^(Tunnel\d+)\s+\S+\s+YES\s+\S+\s+(\S+(?: \S+)?)\s+(up|down)\s*$", line)
                if m:
                    ifaces[m[1]] = {"status": m[2], "proto": m[3]}
                    detail = c.send_command(f"show interfaces {m[1]}", read_timeout=30)
                    li = re.search(r"Last input (\S+), output (\S+?),", detail); ir = re.search(r"input rate (\d+) bits", detail); orr = re.search(r"output rate (\d+) bits", detail)
                    ifaces[m[1]].update({"last_input": li[1] if li else None, "last_output": li[2] if li else None, "in_bps": int(ir[1]) if ir else None, "out_bps": int(orr[1]) if orr else None})
        finally:
            c.disconnect()
        ike = {}
        for m in re.finditer(r"^\d+\s+(\S+)/\d+\s+(\S+)/\d+\s+\S+\s+(\S+)\s*\n(?:.*\n){0,2}?\s*Life/Active Time: \d+/(\d+) sec", ike_out, re.M):
            ike[m[2]] = {"local": m[1], "status": m[3], "active": int(m[4])}
        bgp = {}
        for line in bgp_out.splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+4\s+(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s*$", line)
            if m: bgp[m[1]] = {"as": m[2], "updown": m[3], "state": m[4], "prefixes": int(m[4]) if m[4].isdigit() else None}
        ipsec = {}
        for block in re.split(r"\n(?=interface: )", ipsec_out):
            m = re.match(r"interface: (\S+)", block)
            if not m: continue
            enc = re.search(r"#pkts encaps: (\d+)", block); dec = re.search(r"#pkts decaps: (\d+)", block)
            se = re.search(r"#send errors (\d+)", block); rcv = re.search(r"#recv errors (\d+)", block)
            ipsec[m[1]] = {"encaps": int(enc[1]) if enc else None, "decaps": int(dec[1]) if dec else None, "send_err": int(se[1]) if se else None, "recv_err": int(rcv[1]) if rcv else None}
        res = {}
        m = re.search(r"^\s*Control Processor\s+([\d.]+)%\s+\S+\s+(\d+)%\s+(\d+)%\s+(\S+)", res_out, re.M)
        if m: res["cpu_pct"] = float(m[1]); res["cpu_warning_pct"] = int(m[2]); res["cpu_critical_pct"] = int(m[3]); res["cpu_state"] = {"H": "healthy", "W": "warning", "C": "critical"}.get(m[4], m[4])
        m = re.search(r"^\s*CPU Utilization\s+([\d.]+)%\s+\S+\s+(\d+)%\s+(\d+)%", res_out, re.M)
        if m: res["qfp_cpu_pct"] = float(m[1]); res["qfp_cpu_warning_pct"] = int(m[2])
        m = re.search(r"^\s*DRAM\s+\d+MB\((\d+)%\)\s+(\d+)MB\s+(\d+)%", res_out, re.M)
        if m: res["dram_pct"] = int(m[1]); res["dram_mb"] = int(m[2]); res["dram_warning_pct"] = int(m[3])
        return {"collected": time.time(), "ike": ike, "ifaces": ifaces, "bgp": bgp, "ipsec": ipsec, "resources": res}

    # ---- public --------------------------------------------------------------
    def cached(self):
        """What the last collection left, without starting one. The metrics endpoint reads this: collecting means SSH to every
        headend, far too slow for a Prometheus scrape — a background thread in the portal keeps it warm instead."""
        return self._cache

    def get(self, refresh=False, with_live=True):
        with self._lock:
            if self._cache and not refresh and time.time() - self._cache["generated"] < self.ttl: return self._cache
            inv = self.model()
            inv["live_sources"] = self.live(inv["headends"], inv["tunnels"]) if with_live else {}
            for h in inv["headends"]:
                h["live"] = inv["live_sources"].get(h["name"])
                h["tunnels_up"] = sum(1 for t in inv["tunnels"] if t["headend"] == h["name"] and (t["live"] or {}).get("health") == "up")
                # third metric, live: control-plane CPU of the headend (show platform resources). It joins the aggregate: a headend above the
                # platform's warning threshold has no free slots whatever the model says; below it the model constraints decide.
                cpu = (h["live"] or {}).get("cpu_pct"); warn = (h["live"] or {}).get("cpu_warning_pct") or 80
                h["cpu_pct"] = cpu; h["cpu_warning_pct"] = warn; h["cpu_utilisation"] = round(100 * cpu / warn, 1) if cpu is not None else None
                h["qfp_cpu_pct"] = (h["live"] or {}).get("qfp_cpu_pct"); h["dram_pct"] = (h["live"] or {}).get("dram_pct")
                if h["cpu_utilisation"] is not None:
                    if h["cpu_utilisation"] > (h["aggregate_utilisation"] or 0): h["binding"] = "cpu"
                    h["aggregate_utilisation"] = max(h["aggregate_utilisation"] or 0, h["cpu_utilisation"])
                    if cpu >= warn: h["effective_free"] = 0
            inv["generated"] = time.time()
            inv["summary"] = {"vpns": len(inv["vpns"]), "tunnels": len(inv["tunnels"]), "headends": len(inv["headends"]),
                              "tunnels_up": sum(1 for t in inv["tunnels"] if (t["live"] or {}).get("health") == "up"),
                              "tunnels_down": sum(1 for t in inv["tunnels"] if (t["live"] or {}).get("health") in ("down", "degraded")),
                              "capacity": sum(h["capacity"] for h in inv["headends"]), "free": sum(h["free"] for h in inv["headends"]),
                              "effective_capacity": sum(h.get("effective_capacity") or 0 for h in inv["headends"]), "effective_free": sum(h.get("effective_free") or 0 for h in inv["headends"]),
                              "bandwidth_mbps": sum(h.get("bandwidth_mbps") or 0 for h in inv["headends"]), "bandwidth_used_mbps": sum(h.get("bandwidth_used_mbps") or 0 for h in inv["headends"]),
                              "cpu_pct_max": max((h["cpu_pct"] for h in inv["headends"] if h.get("cpu_pct") is not None), default=None),
                              "cpu_pct_avg": (lambda v: round(sum(v) / len(v), 1) if v else None)([h["cpu_pct"] for h in inv["headends"] if h.get("cpu_pct") is not None])}
            self._cache = inv
            return inv


CSV_COLUMNS = [("name", "tunnel"), ("tunnel_id", "tunnel_id"), ("vpn", "vpn"), ("model_status", "model_status"), ("headend", "headend"), ("headend_if", "headend_interface"),
               ("headend_src_ip", "headend_wan_ip"), ("headend_tunnel_ip", "headend_tunnel_ip"), ("spoke", "spoke"), ("spoke_region", "spoke_region"), ("spoke_site", "spoke_site"), ("spoke_if", "spoke_interface"),
               ("spoke_src_ip", "spoke_wan_ip"), ("spoke_tunnel_ip", "spoke_tunnel_ip"), ("encapsulation", "encapsulation"), ("profile", "profile"), ("ike", "ike"), ("ipsec", "ipsec"), ("dpd", "dpd"),
               ("protected_prefixes", "protected_prefixes"), ("change_ticket", "change_ticket"), ("owner", "owner"),
               ("live.health", "health"), ("live.ike_status", "ike_sa"), ("live.ike_active_s", "ike_sa_age_s"), ("live.line_protocol", "line_protocol"), ("live.bgp_state", "bgp_state_or_prefixes"),
               ("live.bgp_updown", "bgp_up_down"), ("live.encaps", "esp_encaps_pkts"), ("live.decaps", "esp_decaps_pkts"), ("live.send_errors", "esp_send_errors"), ("live.recv_errors", "esp_recv_errors"),
               ("live.in_rate_bps", "in_bps"), ("live.out_rate_bps", "out_bps"), ("live.last_input", "last_input"), ("live.last_output", "last_output")]


def to_csv(inv):
    import csv, io
    buf = io.StringIO(); w = csv.writer(buf); w.writerow([c[1] for c in CSV_COLUMNS])
    for t in inv["tunnels"]:
        row = []
        for key, _ in CSV_COLUMNS:
            v = t
            for k in key.split("."): v = (v or {}).get(k) if isinstance(v, dict) else None
            row.append(" ".join(v) if isinstance(v, list) else ("" if v is None else v))
        w.writerow(row)
    # headend capacity block: tunnels and firewall bandwidth, and the aggregate (the tighter of the two)
    w.writerow([]); w.writerow(["headend", "tunnels", "tunnel_capacity", "tunnel_free", "tunnel_utilisation_pct", "firewall", "bandwidth_mbps", "bandwidth_per_tunnel_mbps", "bandwidth_used_mbps",
                                "bandwidth_free_mbps", "bandwidth_utilisation_pct", "cpu_pct", "cpu_warning_pct", "qfp_cpu_pct", "dram_pct", "binding_constraint", "aggregate_utilisation_pct", "effective_capacity", "effective_free"])
    for h in inv["headends"]:
        w.writerow([h["name"], h["tunnels"], h["capacity"], h["free"], h["utilisation"], h.get("firewall") or "", h.get("bandwidth_mbps") or "", h.get("bandwidth_per_tunnel_mbps") or "",
                    h.get("bandwidth_used_mbps") or "", h.get("bandwidth_free_mbps", ""), h.get("bandwidth_utilisation", ""), h.get("cpu_pct", ""), h.get("cpu_warning_pct", ""), h.get("qfp_cpu_pct", ""), h.get("dram_pct", ""),
                    h.get("binding") or "", h.get("aggregate_utilisation", ""),
                    h.get("effective_capacity", ""), h.get("effective_free", "")])
    return buf.getvalue()
