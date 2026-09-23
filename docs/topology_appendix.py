#!/usr/bin/env python3
"""Generate the full-topology appendix (Mermaid + the tunnel and router tables) from lab.conf and lab-intent.json."""
import html, json, re, sys
from pathlib import Path
sys.path.insert(0, "/home/dcantor/cat8000v-ipsec/nautobot")
import intent as intent_mod

LAB = Path("/home/dcantor/cat8000v-ipsec")
conf = (LAB / "lab.conf").read_text()


def arr(name):
    m = re.search(rf"^{name}=\((.*?)^\)", conf, re.S | re.M)
    return [l.split("#")[0].strip().strip(chr(34)) for l in m.group(1).splitlines() if l.split("#")[0].strip()]


def amap(name):
    m = re.search(rf"declare -A {name}=\((.*?)\)\n", conf, re.S)
    return dict(re.findall(r"\[([^\]]+)\]=(\S+)", m.group(1)))


ROLE, MGMT, ASN, LAN = amap("ROLE"), amap("MGMT_IP"), amap("BGP_AS"), amap("LAN")
LINKS = [l.split() for l in arr("LINKS")]
TUNNELS = [l.split() for l in arr("TUNNELS")]
I = intent_mod.load()
DEV = {d["name"]: d for d in I["devices"]}

ID = {}
for n in ROLE:
    ID[n] = re.sub(r"[^a-z0-9]", "", n.lower())

# ---- the diagram -------------------------------------------------------------------------------------------------------------
def node(n):
    r = ROLE[n]
    if r == "host":                     # a host is .2 of its router's site LAN
        net = LAN.get(DEV[n].get("router", ""), "")
        ip = net.rsplit(".", 1)[0] + ".2" if net not in ("", "-") else ""
        return f'{ID[n]}(["{n}&lt;br/&gt;{ip}"])'
    if r == "firewall":
        return f'{ID[n]}{{{{"{n}&lt;br/&gt;VyOS"}}}}'
    asn = ASN.get(n, "-")
    lan = LAN.get(n, "-")
    extra = "&lt;br/&gt;" + lan if lan not in ("-", None) else ""
    return f'{ID[n]}["{n}&lt;br/&gt;AS {asn}{extra}"]'


lines = ["flowchart LR"]
lines.append('  subgraph BR["The branches — one customer each"]')
lines.append("    direction TB")
for s in [n for n in ROLE if ROLE[n] == "spoke"]:
    lines.append("    " + node("host-" + s))
    lines.append("    " + node(s))
lines.append("  end")
lines.append('  subgraph FW["The firewalls — every WAN link lands on one"]')
lines.append("    direction TB")
for f in [n for n in ROLE if ROLE[n] == "firewall"]:
    lines.append("    " + node(f))
lines.append("  end")
lines.append('  INET(["internet&lt;br/&gt;libvirt NAT network"])')
lines.append('  subgraph HE["The headends — ACME Networks"]')
lines.append("    direction TB")
for h in [n for n in ROLE if ROLE[n] == "hub"]:
    lines.append("    " + node(h))
    lines.append("    " + node("host-" + h.split("-")[0]))
lines.append("  end")
lines.append('  subgraph DC["The interconnect — no IPsec on it"]')
lines.append("    direction TB")
for n in ("DCI", "ACME-acquisition", "host-acquisition"):
    lines.append("    " + node(n))
lines.append("  end")

for a, b, pfx in LINKS:
    an, ap = a.split(":"); bn, bp = b.split(":")
    if ROLE[bn] == "host" or ROLE[an] == "host":
        lines.append(f'  {ID[an]} --- {ID[bn]}')
    else:
        lines.append(f'  {ID[an]} -- "{pfx}" --- {ID[bn]}')
for f in [n for n in ROLE if ROLE[n] == "firewall"]:
    lines.append(f'  {ID[f]} -. "breakout (NAT)" .-> INET')
for t, hub, spoke, pfx in TUNNELS:          # the ten VTIs, unlabelled: the table below carries each tunnel's detail
    lines.append(f'  {ID[spoke]} -.- {ID[hub]}')
lines += ["  classDef hub fill:#eef2f7,stroke:#0b62d6", "  classDef spoke fill:#f4f7fb,stroke:#5b7fa6",
          "  classDef fw fill:#fdf3e7,stroke:#b26a00", "  classDef host fill:#f3f5f8,stroke:#94a3b8",
          "  classDef dci fill:#e8f1e8,stroke:#15803d",
          "  class " + ",".join(ID[n] for n in ROLE if ROLE[n] == "hub") + " hub",
          "  class " + ",".join(ID[n] for n in ROLE if ROLE[n] == "spoke") + " spoke",
          "  class " + ",".join(ID[n] for n in ROLE if ROLE[n] == "firewall") + " fw",
          "  class " + ",".join(ID[n] for n in ROLE if ROLE[n] == "host") + " host",
          "  class " + ",".join(ID[n] for n in ("DCI", "ACME-acquisition")) + " dci"]
Path("/tmp/topo-mermaid.txt").write_text("\n".join(lines))

# ---- the tables --------------------------------------------------------------------------------------------------------------
wan = {}
for a, b, pfx in LINKS:
    an, _ = a.split(":"); bn, _ = b.split(":")
    wan.setdefault(frozenset((an, bn)), pfx)

rows = []
for t, hub, spoke, pfx in sorted(TUNNELS, key=lambda x: int(x[0])):
    fwname = next((n for n in ROLE if ROLE[n] == "firewall" and frozenset((n, spoke)) in wan and frozenset((n, hub)) in wan), "")
    rows.append(f"<tr><td><code>Tunnel{t}</code></td><td><code>{hub}</code></td><td><code>{spoke}</code></td>"
                f"<td><code>{pfx}</code></td><td><code>{fwname}</code> — {html.escape(wan.get(frozenset((fwname, spoke)), '?'))} to the spoke, "
                f"{html.escape(wan.get(frozenset((fwname, hub)), '?'))} to the headend</td></tr>")
Path("/tmp/topo-tunnels.txt").write_text("\n".join(rows))

rows = []
for n in [x for x in ROLE if ROLE[x] in ("hub", "spoke", "dci", "partner")]:
    d = DEV.get(n, {})
    rows.append(f"<tr><td><code>{n}</code></td><td>{ROLE[n]}</td><td>{ASN.get(n,'')}</td><td><code>{d.get('router_id','')}</code></td>"
                f"<td><code>{LAN.get(n,'')}</code></td><td><code>{MGMT.get(n,'')}</code></td>"
                f"<td>{html.escape(str(d.get('site','')))} · {html.escape(str(d.get('city','')))}</td></tr>")
Path("/tmp/topo-routers.txt").write_text("\n".join(rows))
print("nodes:", len(ID), "links:", len(LINKS), "tunnels:", len(TUNNELS))
