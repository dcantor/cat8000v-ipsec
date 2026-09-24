#!/usr/bin/env python3
"""Capture a DNS lookup on both sides of the DCI and show what the NAT did to it.

The DCI translates the header of a DNS flow and — because the DNS ALG is on — the addresses *inside* the answer as well
(`dns_fixup` in the intent). This proves it on the wire: an Embedded Packet Capture on each of the DCI's two interfaces
while a LAN host resolves a name, then both buffers pulled off the router, written as .pcap files and decoded side by side.

  tools/dns_capture.py [--name acq500.acquisition.local] [--host host-spoke1] [--out docs/captures]

What comes back is one query and one answer seen twice: on GigabitEthernet2 (ACME) with the translated addresses, and on
GigabitEthernet3 (the acquired company) with the real ones — same transaction id, same question, different A record.
The capture points are removed again, so the router is left exactly as it was found.
"""
import argparse
import json
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "nautobot"))
import intent as intent_mod                                    # noqa: E402
from netmiko import ConnectHandler                             # noqa: E402

a = argparse.ArgumentParser(description=__doc__.split("\n")[0], formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
a.add_argument("--name", help="the name to resolve (default: a name from the acquired company's zone)")
a.add_argument("--host", default="host-spoke1", help="the LAN host that resolves it (it must have a dns_client in the intent)")
a.add_argument("--out", default=str(LAB / "docs" / "captures"), help="where the .pcap files are written")
a.add_argument("--keep", action="store_true", help="leave the capture points on the router (default: remove them)")
a = a.parse_args()

I = intent_mod.load()
DEV = {d["name"]: d for d in I["devices"]}
nat_router, nat = next(((d["name"], d["nat"]) for d in I["devices"] if d.get("nat")), (None, None))
if not nat: sys.exit("no NAT (DCI) router in the intent")
SC = nat.get("scale") or {}
ZONE = next((d for d in I["devices"] if (d.get("dns") or {}).get("scale", {}).get("side") == "acquisition"), None)
ENTRIES = intent_mod.nat_scale(nat)


def default_name():
    """A name from the acquired company's zone whose record is one of the overlapping addresses."""
    z = (ZONE or {}).get("dns") or {}
    n = 500 if len(ENTRIES) > 500 else 0
    return f"{z['scale']['name_format'].format(n=n)}.{z['domain']}"


NAME = a.name or default_name()
SIDES = {"acme": {"interface": nat["outside_interface"], "capture": "DNSOUT", "title": "ACME side (outside)"},
         "acquisition": {"interface": nat["inside_interface"], "capture": "DNSIN", "title": "the acquired company's side (inside)"}}


# ---- the router -----------------------------------------------------------------------------------------------------
def router():
    return ConnectHandler(device_type="cisco_xe", host=DEV[nat_router]["mgmt_ip"], username="admin", password="admin", fast_cli=False)


def cmd(c, line, wait=60):
    """An exec command that may print a prompt of its own (redefining a capture point asks for confirmation)."""
    out = c.send_command_timing(line, read_timeout=wait, strip_prompt=False)
    while "[confirm]" in out or "[yes/no]" in out or out.rstrip().endswith("?"):
        out += c.send_command_timing("\n", read_timeout=wait, strip_prompt=False)
    return out


def frames(dump):
    """The hex dump of a capture buffer -> a list of raw Ethernet frames. Each packet is an index line followed by
    `  <offset>:  XXXXXXXX XXXXXXXX ...   ascii` lines; the offset tells us how much of the packet we have so far."""
    out, cur = [], None
    for line in dump.splitlines():
        if re.fullmatch(r"\s*\d+\s*", line):
            if cur: out.append(bytes(cur))
            cur = bytearray(); continue
        m = re.match(r"^\s*([0-9A-Fa-f]{4}):\s{2}(.{0,35})", line)
        if not m or cur is None: continue
        if int(m.group(1), 16) != len(cur): continue            # out of step: skip rather than corrupt the frame
        for g in re.findall(r"[0-9A-Fa-f]{8}", m.group(2))[:4]:
            cur += bytes.fromhex(g)
    if cur: out.append(bytes(cur))
    return [f for f in out if len(f) >= 34]


def stamps(brief):
    """The relative timestamp of each packet, from the brief listing."""
    return [float(m.group(1)) for m in re.finditer(r"^\s*\d+\s+\d+\s+([0-9.]+)\s", brief, re.M)]


def write_pcap(path, frames, times, base):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            t = base + (times[i] if i < len(times) else 0.0)
            f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(fr), len(fr)) + fr)
    return path


# ---- just enough DNS to read a question and its A records -----------------------------------------------------------
def ip_of(b): return ".".join(str(x) for x in b)


def dns_name(buf, off):
    parts = []
    while True:
        n = buf[off]
        if n == 0: return ".".join(parts), off + 1
        if n & 0xC0 == 0xC0:                                    # a pointer back into the message
            p = struct.unpack("!H", buf[off:off + 2])[0] & 0x3FFF
            parts.append(dns_name(buf, p)[0]); return ".".join(parts), off + 2
        parts.append(buf[off + 1:off + 1 + n].decode("ascii", "replace")); off += 1 + n


def decode(frame):
    """An Ethernet frame -> {src, dst, sport, dport, id, qr, question, answers} for UDP/53, else None."""
    if len(frame) < 14 or frame[12:14] != b"\x08\x00": return None
    ip = frame[14:]; ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 17: return None                                  # UDP only
    src, dst = ip_of(ip[12:16]), ip_of(ip[16:20])
    udp = ip[ihl:]; sport, dport = struct.unpack("!HH", udp[0:4])
    if 53 not in (sport, dport): return None
    d = udp[8:]
    if len(d) < 12: return None
    tid, flags, qd, an = struct.unpack("!HHHH", d[0:8])
    off = 12; q = None
    for _ in range(qd):
        q, off = dns_name(d, off); off += 4
    answers = []
    for _ in range(an):
        _, off = dns_name(d, off)
        rtype, _, _, rdlen = struct.unpack("!HHIH", d[off:off + 10]); off += 10
        if rtype == 1 and rdlen == 4: answers.append(ip_of(d[off:off + 4]))
        off += rdlen
    return {"src": src, "dst": dst, "sport": sport, "dport": dport, "id": tid, "qr": bool(flags & 0x8000),
            "question": q, "answers": answers, "bytes": len(frame)}


# ---- run it ---------------------------------------------------------------------------------------------------------
out_dir = Path(a.out); out_dir.mkdir(parents=True, exist_ok=True)
c = router()
print(f"==> {nat_router}: capture on {SIDES['acme']['interface']} (ACME) and {SIDES['acquisition']['interface']} (acquired company)")
for s in SIDES.values():
    cmd(c, f"no monitor capture {s['capture']}")            # a capture point left over from a previous run
    cmd(c, f"monitor capture {s['capture']} interface {s['interface']} both match ipv4 any any buffer size 5 limit packets 400", 90)
    cmd(c, f"monitor capture {s['capture']} start", 90)
base = time.time()
try:
    print(f"==> {a.host}: nslookup {NAME}")
    r = subprocess.run([sys.executable, str(LAB / "tools" / "host_cmd.py"), "run", a.host,
                        f"nslookup -type=a {NAME}; sleep 1"], capture_output=True, text=True, timeout=120)
    print("   " + "\n   ".join(l for l in r.stdout.splitlines() if l.strip())[:600])
    time.sleep(1.5)
finally:
    for s in SIDES.values(): cmd(c, f"monitor capture {s['capture']} stop", 90)

result = {}
for key, s in SIDES.items():
    dump = c.send_command(f"show monitor capture {s['capture']} buffer dump", read_timeout=300)
    brief = c.send_command(f"show monitor capture {s['capture']} buffer brief", read_timeout=180)
    fr = frames(dump)
    path = write_pcap(out_dir / f"dns-{key}-side.pcap", fr, stamps(brief), base)
    dns = [d for d in (decode(f) for f in fr) if d]
    result[key] = {"path": path, "frames": fr, "dns": dns, "interface": s["interface"], "title": s["title"]}
    print(f"==> {path} — {len(fr)} frames, {len(dns)} DNS packets")
if not a.keep:
    for s in SIDES.values(): cmd(c, f"no monitor capture {s['capture']}", 90)
    print("==> capture points removed")
c.disconnect()

# ---- what the two sides say ------------------------------------------------------------------------------------------
print()
for key in ("acme", "acquisition"):
    r = result[key]
    print(f"{r['title']} — {nat_router} {r['interface']} — {r['path'].name}")
    for d in r["dns"]:
        what = "answer" if d["qr"] else "query "
        print(f"   0x{d['id']:04x} {what} {d['src']:>15} -> {d['dst']:<15} {d['question']}"
              + (f"  A {', '.join(d['answers'])}" if d["answers"] else ""))
    print()

pairs = []
for out in [d for d in result["acme"]["dns"] if d["qr"] and d["answers"]]:
    ins = next((d for d in result["acquisition"]["dns"] if d["qr"] and d["id"] == out["id"] and d["answers"]), None)
    if ins: pairs.append((out, ins))
if not pairs:
    sys.exit("no answer was seen on both sides — was the lookup made through the DCI?")
ok = True
records = []
for out, ins in pairs:
    entry = next((e for e in ENTRIES if e["acquisition_ip"] == ins["answers"][0]), None)
    want = entry["acquisition_as_acme_sees_it"] if entry else None
    good = want == out["answers"][0]
    ok &= good
    print(f"{out['question']}: the server answered {ins['answers'][0]} on the inside, ACME received {out['answers'][0]}"
          + (f" — the inside-global form of it ({entry['prefix']} -> {entry['inside_global']})" if good else f" — expected {want}"))
    print(f"   same transaction 0x{out['id']:04x}; the DCI rewrote the header ({ins['src']} -> {out['src']}) and the A record inside the payload")
    records.append({"name": out["question"], "transaction": f"0x{out['id']:04x}", "inside": ins["answers"][0],
                    "outside": out["answers"][0], "expected_outside": want, "ok": bool(good)})
# the verdict, where the portal's /metrics (and so the dashboard and the alerts) can read it
(out_dir / "verdict.json").write_text(json.dumps({"ok": bool(ok), "at": time.time(), "router": nat_router,
                                                  "captures": {k: r["path"].name for k, r in result.items()}, "records": records}, indent=1))
print("\nDNS fix-up proven on the wire" if ok else "\nthe answer was NOT rewritten as the model says it should be")
sys.exit(0 if ok else 1)
