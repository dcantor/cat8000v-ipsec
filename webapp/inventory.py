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


class Inventory:
    def __init__(self, url, public_url, token_fn, username="admin", password="admin", ttl=30):
        self.url, self.public_url, self.token_fn, self.creds, self.ttl = url, public_url, token_fn, (username, password), ttl
        self._cache, self._lock = None, threading.Lock()

    # ---- Nautobot ----------------------------------------------------------
    def devices(self):
        """VPN routers for the topology map: role, management IP, AS, site LAN (Loopback10), serial."""
        q = """{ devices(role: ["vpn-hub", "vpn-spoke", "vpn-firewall"], location: ["%s"]) { id name serial role { name } primary_ip4 { address } location { name cf_site_code cf_contact parent { name } }
                 bgp_routing_instances { autonomous_system { asn } router_id { address } }
                 interfaces(name: "Loopback10") { ip_addresses { address parent { prefix } } } } }"""
        import sys; from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "nautobot")); import intent as intent_mod
        q = q % intent_mod.load()["site"]["name"]
        r = requests.post(f"{self.url}/api/graphql/", json={"query": q}, headers={"Authorization": f"Token {self.token_fn()}"}, timeout=60); r.raise_for_status()
        out = []
        for d in r.json()["data"]["devices"]:
            ri = (d["bgp_routing_instances"] or [{}])[0]; lo = ((d["interfaces"] or [{}])[0].get("ip_addresses") or [{}])[0]
            out.append({"name": d["name"], "role": {"vpn-hub": "hub", "vpn-spoke": "spoke", "vpn-firewall": "firewall"}[d["role"]["name"]], "mgmt_ip": (d["primary_ip4"] or {}).get("address", "").split("/")[0],
                        "site": (d["location"] or {}).get("name"), "region": ((d["location"] or {}).get("parent") or {}).get("name"),
                        "site_code": (d["location"] or {}).get("cf_site_code"), "contact": (d["location"] or {}).get("cf_contact"), "serial": d["serial"], "asn": (ri.get("autonomous_system") or {}).get("asn"),
                        "router_id": (ri.get("router_id") or {}).get("address", "").split("/")[0], "lan": (lo.get("parent") or {}).get("prefix"),
                        "url": f"{self.public_url}/dcim/devices/{d['id']}/"})
        # a firewall's headend: the device on the far side of its eth1 (from Nautobot cables)
        q2 = """{ interfaces(device: [%s], name: "eth1") { device { name } connected_interface { device { name } } } }""" % ", ".join('"%s"' % d["name"] for d in out if d["role"] == "firewall")
        if any(d["role"] == "firewall" for d in out):
            r2 = requests.post(f"{self.url}/api/graphql/", json={"query": q2}, headers={"Authorization": f"Token {self.token_fn()}"}, timeout=60).json()
            hub_of = {i["device"]["name"]: (i.get("connected_interface") or {}).get("device", {}).get("name") for i in r2.get("data", {}).get("interfaces", [])}
            for d in out:
                if d["role"] == "firewall": d["hub"] = hub_of.get(d["name"])
        return sorted(out, key=lambda d: ({"hub": 0, "firewall": 1, "spoke": 2}[d["role"]], d["name"]))

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
        for h in headends.values():
            h["free"] = max(h["capacity"] - h["tunnels"], 0); h["utilisation"] = round(100 * h["tunnels"] / h["capacity"], 1) if h["capacity"] else None
        return {"tunnels": sorted(tunnels, key=lambda x: (x["headend"], int(x["tunnel_id"] or 0))), "headends": sorted(headends.values(), key=lambda h: h["name"]), "devices": self.devices(),
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
        return {h: {"error": s["error"]} if "error" in s else {"collected": s["collected"], "ike_sessions": len(s["ike"])} for h, s in out.items()}

    def collect_headend(self, host):
        from netmiko import ConnectHandler
        c = ConnectHandler(device_type="cisco_xe", host=host, username=self.creds[0], password=self.creds[1], fast_cli=False)
        try:
            ike_out = c.send_command("show crypto ikev2 sa", read_timeout=30)
            brief = c.send_command("show ip interface brief | include Tunnel", read_timeout=30)
            bgp_out = c.send_command("show bgp ipv4 unicast summary | begin Neighbor", read_timeout=30)
            ipsec_out = c.send_command("show crypto ipsec sa", read_timeout=60)
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
        return {"collected": time.time(), "ike": ike, "ifaces": ifaces, "bgp": bgp, "ipsec": ipsec}

    # ---- public --------------------------------------------------------------
    def get(self, refresh=False, with_live=True):
        with self._lock:
            if self._cache and not refresh and time.time() - self._cache["generated"] < self.ttl: return self._cache
            inv = self.model()
            inv["live_sources"] = self.live(inv["headends"], inv["tunnels"]) if with_live else {}
            for h in inv["headends"]:
                h["live"] = inv["live_sources"].get(h["name"])
                h["tunnels_up"] = sum(1 for t in inv["tunnels"] if t["headend"] == h["name"] and (t["live"] or {}).get("health") == "up")
            inv["generated"] = time.time()
            inv["summary"] = {"vpns": len(inv["vpns"]), "tunnels": len(inv["tunnels"]), "headends": len(inv["headends"]),
                              "tunnels_up": sum(1 for t in inv["tunnels"] if (t["live"] or {}).get("health") == "up"),
                              "tunnels_down": sum(1 for t in inv["tunnels"] if (t["live"] or {}).get("health") in ("down", "degraded")),
                              "capacity": sum(h["capacity"] for h in inv["headends"]), "free": sum(h["free"] for h in inv["headends"])}
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
    return buf.getvalue()
