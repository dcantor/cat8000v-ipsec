#!/usr/bin/env python3
"""Certificate enrolment of the C8000v routers against the lab CA (pki/ca.py), and the record of it in Nautobot.

Per router (the IOS-XE devices of the intent, when the VPN profile's IKE authentication is `certificate`):
  1. an RSA key pair on the router (`crypto key generate rsa label KEYPAIR`) — the private key never leaves the box
  2. the trustpoint (enrollment terminal pem, fqdn / subject-name from the device and the intent's domain, revocation-check none,
     the key pair) and the certificate map the IKEv2 profile matches on (issuer = the lab CA)
  3. the CA certificate installed (`crypto pki authenticate`, PEM pasted over SSH, fingerprint confirmed)
  4. a router certificate: `crypto pki enroll` prints the CSR, the CA signs it, `crypto pki import ... certificate` pastes it back;
     done when the router has none, when it is not the one the CA index says, when it expires within `renew_before_days`,
     or on --force (the portal's Renew certificate action)
  5. Nautobot: the device's custom fields cert_serial / cert_subject / cert_expires / cert_renewed follow the router (the seed
     creates the fields and leaves their values alone)
The IKEv2 profile's switch to rsa-sig is NOT done here: it is rendered by render_nac.py and applied by Terraform after this.
Usage: NAUTOBOT_TOKEN=... pki.py [--force] [--check] [--json] [device ...]   (--check: report only, exit 1 if anything is due)
       pki.py --post-apply [device ...]   after Terraform: keyrings off the routers, SAs on PSK cleared, tunnels verified on RSA"""
import argparse, datetime, json, os, re, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent)); import intent as intent_mod   # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pki")); import ca   # noqa: E402

LAB = Path(__file__).resolve().parents[1]
CREDS = (os.environ.get("IOSXE_USERNAME", "admin"), os.environ.get("IOSXE_PASSWORD", "admin"))
YES = r"\[yes/no\]:?\s*$|\[no\]:?\s*$|\[yes\]:?\s*$"


def pki_settings(I):
    """The intent's PKI block with defaults (profile.pki), or None when no tunnel authenticates with certificates (the method is chosen
    per spoke: device ike_authentication, else the lab default profile.ike.authentication)."""
    pr = I.get("profile") or {}
    if "certificate" not in intent_mod.auths_in_use(I): return None
    p = pr.get("pki") or {}
    return {"trustpoint": p.get("trustpoint", "LAB-CA"), "keypair": p.get("keypair", "LAB-VPN"), "key_bits": int(p.get("key_bits", 2048)), "validity_days": int(p.get("validity_days", 365)),
            "renew_before_days": int(p.get("renew_before_days", 30)), "certificate_map": p.get("certificate_map", "LAB-CERT-MAP"), "org": ca.ORG, "ca_cn": ca.CA_CN}


def trustpoint_config(name, domain, pk):
    """The lines the enrolment sets — identical to what the Golden Config template renders for compliance."""
    fqdn = f"{name}.{domain}"; fp = ca.cert_info(ca.CA_CRT.read_text())["fingerprint"]   # pinned: IOS accepts the CA certificate only if it matches, no question asked
    return [f"crypto pki trustpoint {pk['trustpoint']}", " enrollment terminal pem", f" fqdn {fqdn}", f" subject-name CN={fqdn},O={pk['org']}",
            " revocation-check none", f" rsakeypair {pk['keypair']}", f" fingerprint {fp}", " hash sha256",
            f"crypto pki certificate map {pk['certificate_map']} 10", f" issuer-name co {pk['ca_cn'].lower()}"]


def parse_certs(text):
    """`show crypto pki certificates TP` -> {"router": {...}, "ca": {...}}: serial, subject cn, start / end (UTC ISO)."""
    out = {}; cur = None; sect = None
    for line in text.splitlines():
        if re.match(r"^(CA )?Certificate\s*$", line): cur = {"kind": "ca" if line.startswith("CA") else "router"}; out[cur["kind"]] = cur; sect = None; continue
        if cur is None: continue
        if re.match(r"\s+(Issuer|Subject):", line): sect = line.strip().rstrip(":").lower(); continue
        m = re.match(r"\s+Certificate Serial Number \(hex\): (\w+)", line)
        if m: cur["serial"] = m[1].upper().lstrip("0") or "0"
        m = re.match(r"\s+(start|end)\s+date: (.+)$", line)
        if m:
            try: cur[m[1]] = datetime.datetime.strptime(m[2].strip(), "%H:%M:%S %Z %b %d %Y").replace(tzinfo=datetime.timezone.utc).isoformat()
            except ValueError: cur[m[1]] = m[2].strip()
        m = re.match(r"\s+cn=(.+)$", line)
        if m and sect == "subject" and "cn" not in cur: cur["cn"] = m[1].strip()
        m = re.match(r"\s+Status: (\w+)", line)
        if m: cur["status"] = m[1]
    return out


class Router:
    def __init__(self, name, host):
        from netmiko import ConnectHandler
        self.name = name; self.c = ConnectHandler(device_type="cisco_xe", host=host, username=CREDS[0], password=CREDS[1], conn_timeout=30, fast_cli=False)
        self.prompt = re.escape(self.c.find_prompt())

    def close(self): self.c.disconnect()
    def show(self, cmd, timeout=60): return self.c.send_command(cmd, read_timeout=timeout)
    def config(self, lines): return self.c.send_config_set(lines, exit_config_mode=True, read_timeout=60)

    def interact(self, command, answers, paste=None, timeout=120):
        """Run an exec command that asks questions: `answers` = [(regex, reply)]; `paste` (text) is sent at the first
        "Enter the base 64 encoded" prompt, followed by the blank line that ends it. Returns everything printed."""
        c = self.c; c.write_channel(command + "\n"); out = ""; pos = 0; pasted = False; deadline = time.time() + timeout; quiet = time.time()
        patterns = [(re.compile(rx, re.M | re.I), reply) for rx, reply in answers]
        while time.time() < deadline:
            chunk = c.read_channel()
            if chunk: out += chunk; quiet = time.time()
            new = out[pos:]   # only what arrived since the last answer can hold a new question
            if paste and not pasted and re.search(r"Enter the base 64 encoded", new):
                for l in paste.strip().splitlines(): c.write_channel(l + "\n")
                c.write_channel("\n"); pasted = True; pos = len(out); time.sleep(1); continue
            hit = next(((rx, reply) for rx, reply in patterns if rx.search(new)), None)
            if hit:
                c.write_channel(hit[1] + "\n"); out += f" <{hit[1]}>\n"; pos = len(out); time.sleep(0.5); continue
            if re.search(self.prompt + r"\s*$", new) and time.time() - quiet > 1.0: return out
            time.sleep(0.3)
        raise TimeoutError(f"{self.name}: {command}: no prompt after {timeout}s\n{out[-800:]}")


def ensure_key(r, pk, log):
    have = r.show(f"show crypto key mypubkey rsa {pk['keypair']}")
    if "Key name:" in have and "not found" not in have: return False
    log(f"{r.name}: generating RSA key pair {pk['keypair']} ({pk['key_bits']} bits)")
    out = r.interact(f"crypto key generate rsa general-keys label {pk['keypair']} modulus {pk['key_bits']}", [(r"Do you really want to replace them\? \[yes/no\]:", "yes")], timeout=180)
    if "The name for the keys will be" not in out: raise RuntimeError(f"{r.name}: key generation failed: {out[-300:]}")
    for _ in range(60):   # C8000v generates the pair in the background
        if "Key name:" in r.show(f"show crypto key mypubkey rsa {pk['keypair']}"): return True
        time.sleep(2)
    raise RuntimeError(f"{r.name}: key pair {pk['keypair']} did not appear")


def ensure_trustpoint(r, I, pk, log):
    want = trustpoint_config(r.name, I["domain_name"], pk); running = r.show("show running-config | section crypto pki (trustpoint|certificate map)")
    have = {l.rstrip() for l in running.splitlines()}
    missing = [l for l in want if l.rstrip() not in have and l.strip() not in {x.strip() for x in have}]
    if not missing: return False
    log(f"{r.name}: trustpoint {pk['trustpoint']} / certificate map {pk['certificate_map']}: {len(missing)} line(s) set")
    r.config(want); return True


def ensure_ca(r, pk, log):
    ca_pem = ca.CA_CRT.read_text(); ca_fp = ca.cert_info(ca_pem)["fingerprint"]
    certs = parse_certs(r.show(f"show crypto pki certificates {pk['trustpoint']}"))
    ca_serial = ca.cert_info(ca_pem)["serial"]
    if certs.get("ca", {}).get("serial") == ca_serial: return False
    log(f"{r.name}: installing the CA certificate ({ca.CA_CN}, SHA-1 {ca_fp[:8]}…)")
    out = r.interact(f"crypto pki authenticate {pk['trustpoint']}", [(r"Do you accept this certificate\? \[yes/no\]:", "yes"), (r"Do you want to replace it\? \[yes/no\]:", "yes")], paste=ca_pem, timeout=90)
    shown = re.search(r"Fingerprint SHA1: ([0-9A-F ]+)", out)
    if shown and shown[1].replace(" ", "") != ca_fp: raise RuntimeError(f"{r.name}: CA fingerprint on the router {shown[1]} differs from {ca_fp}")
    if "successfully imported" not in out and "accepted" not in out: raise RuntimeError(f"{r.name}: CA authenticate failed: {out[-400:]}")
    if not shown: raise RuntimeError(f"{r.name}: IOS did not show the CA fingerprint: {out[-400:]}")
    return True


def router_cert_due(r, pk, idx_entry, now):
    certs = parse_certs(r.show(f"show crypto pki certificates {pk['trustpoint']}")); rc = certs.get("router")
    if not rc or rc.get("status") != "Available": return "no router certificate", certs
    if not idx_entry or idx_entry["serial"] != rc.get("serial"): return f"router certificate {rc.get('serial')} is not the one the CA issued", certs
    try: end = datetime.datetime.fromisoformat(rc["end"])
    except (KeyError, ValueError): return "cannot read the certificate's validity", certs
    if end - now < datetime.timedelta(days=pk["renew_before_days"]): return f"expires {end.date()} (within {pk['renew_before_days']} days)", certs
    return None, certs


def enroll(r, I, pk, log):
    """CSR from the router -> signed by the CA -> imported. Returns the certificate info."""
    fqdn = f"{r.name}.{I['domain_name']}"
    out = r.interact(f"crypto pki enroll {pk['trustpoint']}",
                     [(r"Include the router serial number in the subject name\? \[yes/no\]:", "no"), (r"Include an IP address in the subject name\? \[no\]:", "no"),
                      (r"Display Certificate Request to terminal\? \[yes/no\]:", "yes"), (r"Redisplay enrollment request\? \[yes/no\]:", "no"),
                      (r"re-?enroll\? \[yes/no\]:", "yes"), (r"replace (it|them)\? \[yes/no\]:", "yes")], timeout=120)
    m = re.search(r"(-----BEGIN CERTIFICATE REQUEST-----.*?-----END CERTIFICATE REQUEST-----)", out, re.S)
    if not m: raise RuntimeError(f"{r.name}: no CSR in the enrolment output: {out[-500:]}")
    csr = "\n".join(l.strip() for l in m[1].splitlines()) + "\n"
    pem = ca.sign(r.name, csr, pk["validity_days"], san=fqdn); info = ca.cert_info(pem)
    log(f"{r.name}: certificate {info['serial'][:12]}… signed (until {info['not_after'][:10]}), importing")
    out = r.interact(f"crypto pki import {pk['trustpoint']} certificate", [(r"replace (it|them)\? \[yes/no\]:", "yes"), (r"\[yes/no\]:", "yes")], paste=pem, timeout=90)
    if "successfully imported" not in out: raise RuntimeError(f"{r.name}: certificate import failed: {out[-500:]}")
    r.show("write memory", timeout=60)
    return info


def record_in_nautobot(name, info, renewed):
    """The device's cert_* custom fields follow the router (None when nothing is enrolled)."""
    import pynautobot
    nb = pynautobot.api(os.environ.get("NAUTOBOT_URL", "http://10.0.0.10:8080"), token=os.environ["NAUTOBOT_TOKEN"]); nb.http_session.verify = False
    dev = nb.dcim.devices.get(name=name)
    if not dev: return
    cf = {"cert_serial": info.get("serial") if info else None, "cert_subject": info.get("cn") or info.get("subject") if info else None,
          "cert_expires": (info.get("end") or info.get("not_after") or "")[:10] or None if info else None, **({"cert_renewed": renewed} if renewed or not info else {})}
    if any((dev.custom_fields or {}).get(k) != v for k, v in cf.items()): dev.update({"custom_fields": {**(dev.custom_fields or {}), **cf}})


def retire(r, pk, idx, check, log):
    """A router none of whose tunnels authenticates with certificates any more (a spoke switched to a key, a headend whose spokes all
    did): the trustpoint (with its certificates) and the certificate map leave the box, the CA index keeps the serial under `retired`,
    Nautobot's cert_* fields are cleared. Returns what was (or would be) done."""
    tp = pk["trustpoint"]; have = r.show("show running-config | include ^crypto pki (trustpoint|certificate map)")
    present = [x for x in (f"crypto pki trustpoint {tp}", f"crypto pki certificate map {pk['certificate_map']} 10") if x in have]
    if not present: return None
    if check: return f"holds {', '.join(present)} but authenticates with keys only"
    log(f"{r.name}: no tunnel uses certificates any more — removing {', '.join(present)}")
    if f"crypto pki trustpoint {tp}" in present:
        r.c.config_mode(); out = r.c.send_command_timing(f"no crypto pki trustpoint {tp}", read_timeout=30)
        if "[yes/no]" in out: out += r.c.send_command_timing("yes", read_timeout=30)   # "Removing an enrolled trustpoint will destroy all certificates ..."
        r.c.exit_config_mode()
        if re.search(r"Invalid input|% (Cannot|Error|Failed)", out): raise RuntimeError(f"{r.name}: could not remove the trustpoint: {out[-300:]}")
    if f"crypto pki certificate map {pk['certificate_map']} 10" in present: r.config([f"no crypto pki certificate map {pk['certificate_map']} 10"])
    r.show("write memory", timeout=60)
    e = idx.pop(r.name, None)
    if e: idx.setdefault("_retired", {})[r.name] = {"serial": e["serial"], "not_after": e["not_after"], "retired": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()}; ca.save_index(idx)
    return "retired"


def run(names=None, force=False, check=False, log=print):
    I = intent_mod.load(); pk = pki_settings(I) or {**pki_settings({**I, "profile": {**I["profile"], "ike": {**I["profile"]["ike"], "authentication": "certificate"}}}), "unused": True}
    if not check: ca.init()
    idx = ca.load_index(); now = datetime.datetime.now(datetime.timezone.utc); report = {"mode": "certificate", "trustpoint": pk["trustpoint"], "devices": {}}
    need = intent_mod.cert_routers(I)   # only routers with a certificate-authenticated tunnel (a PSK-only spoke, or a headend of PSK spokes only, holds none)
    if not need: log("no tunnel authenticates with certificates (per-spoke ike_authentication / the lab default)")
    # routers that authenticate with keys only give their trustpoint back
    for d in [d for d in I["devices"] if d["role"] in ("hub", "spoke") and d["name"] not in need and (not names or d["name"] in names)]:
        r = Router(d["name"], d["mgmt_ip"])
        try:
            what = retire(r, pk, idx, check, log)
            if what:
                report["devices"][d["name"]] = {"due": what if check else None, "changed": [] if check else ["retired"], "serial": None, "subject": None, "expires": None, "ca_installed": False}
                if not check and os.environ.get("NAUTOBOT_TOKEN"): record_in_nautobot(d["name"], None, None)
                log(f"{d['name']}: {'certificate retired (keys only)' if not check else what}")
        finally: r.close()
    routers = [d for d in I["devices"] if d["name"] in need and (not names or d["name"] in names)]
    for d in sorted(routers, key=lambda x: (x["role"] != "hub", x["name"])):
        r = Router(d["name"], d["mgmt_ip"]); changed = []
        try:
            if not check:
                if ensure_key(r, pk, log): changed.append("keypair")
                if ensure_trustpoint(r, I, pk, log): changed.append("trustpoint")
                if ensure_ca(r, pk, log): changed.append("ca")
            due, certs = router_cert_due(r, pk, idx.get(d["name"]), now)
            if force and not due: due = "renewal requested"
            if due and not check:
                log(f"{d['name']}: enrolling — {due}"); info = enroll(r, I, pk, log); changed.append("certificate")
                certs = parse_certs(r.show(f"show crypto pki certificates {pk['trustpoint']}"))
            rc = certs.get("router") or {}
            entry = {"due": due if check else None, "changed": changed, "serial": rc.get("serial"), "subject": rc.get("cn"), "expires": rc.get("end"), "ca_installed": bool(certs.get("ca"))}
            report["devices"][d["name"]] = entry
            if not check and os.environ.get("NAUTOBOT_TOKEN"):
                record_in_nautobot(d["name"], rc, str(now.date()) if "certificate" in changed else None)
            log(f"{d['name']}: {'renewed' if 'certificate' in changed else 'ok'} — serial {rc.get('serial', '-')[:12]} expires {(rc.get('end') or '-')[:10]}" + (f" [{due}]" if check and due else ""))
        finally: r.close()
    return report


def parse_sas(text):
    """`show crypto ikev2 sa detail` -> [{"remote", "status", "auth_sign", "auth_verify"}] per IKE SA."""
    sas = []
    for line in text.splitlines():
        m = re.match(r"^\d+\s+(\S+)/\d+\s+(\S+)/\d+\s+\S+\s+(\w+)", line)
        if m: sas.append({"local": m[1], "remote": m[2], "status": m[3]}); continue
        m = re.search(r"Auth sign: (\S+), Auth verify: (\S+)", line)
        if m and sas: sas[-1].update(auth_sign=m[1].rstrip(","), auth_verify=m[2])
    return sas


def post_apply(names=None, log=print, wait=240, rekey=False):
    """After Terraform: every router's IKE state matches the intent's per-spoke authentication. Per router — tunnels Terraform left
    administratively down are re-enabled (IOS shuts a VTI whose protection profile is swapped); the keyring leaves a router none of
    whose tunnels use a key (IOS refuses the provider's delete while a profile still references it); every IKE SA authenticated the
    wrong way for its peer is cleared (or all of them with `rekey`, after a renewal); then each expected peer must be READY with the
    expected method (Auth sign / verify RSA or PSK) within `wait` seconds."""
    I = intent_mod.load(); ios = I["profile"]["ios"]
    routers = [d for d in I["devices"] if d["role"] in ("hub", "spoke") and (not names or d["name"] in names)]
    wans = intent_mod.tunnel_wans(I)
    expected = {d["name"]: {(t["spoke_wan"] if d["role"] == "hub" else t["hub_wan"]): ("RSA" if t["auth"] == "certificate" else "PSK") for t in wans if d["name"] in (t["hub"], t["spoke"])} for d in routers}
    tunnels = {d["name"]: [f"Tunnel{t['id']}" for t in wans if d["name"] in (t["hub"], t["spoke"])] for d in routers}
    report = {"devices": {}}; conns = {}
    try:
        for d in routers:
            r = conns[d["name"]] = Router(d["name"], d["mgmt_ip"]); changed = []
            down = [l.split()[0] for l in r.show("show ip interface brief | include Tunnel").splitlines() if "administratively down" in l and l.split()[0] in tunnels[d["name"]]]
            if down:
                r.config([x for t in down for x in (f"interface {t}", " no shutdown")]); changed.append(f"{len(down)} tunnel(s) re-enabled"); log(f"{d['name']}: {', '.join(down)} administratively down after the apply — re-enabled")
            auths = intent_mod.router_auths(I, d["name"])
            if "psk" not in auths and f"crypto ikev2 keyring {ios['ikev2_keyring']}" in r.show("show running-config | include crypto ikev2 keyring"):
                r.config([f"no crypto ikev2 keyring {ios['ikev2_keyring']}"]); changed.append("keyring removed"); log(f"{d['name']}: pre-shared keys removed (keyring {ios['ikev2_keyring']}; no tunnel of this router uses one)")
            sas = parse_sas(r.show("show crypto ikev2 sa detail"))
            wrong = [x for x in sas if x["remote"] in expected[d["name"]] and (x.get("auth_sign"), x.get("auth_verify")) != (expected[d["name"]][x["remote"]],) * 2]
            if rekey and sas:   # a renewal: the peers must see the new certificate now, not at the next re-authentication
                r.show("clear crypto ikev2 sa", timeout=60); changed.append(f"{len(sas)} SA(s) cleared"); log(f"{d['name']}: {len(sas)} IKEv2 SA(s) cleared — re-authenticating with the renewed certificate")
            elif wrong:
                r.show("clear crypto ikev2 sa", timeout=60); changed.append(f"{len(wrong)} SA(s) cleared"); log(f"{d['name']}: {len(wrong)} IKEv2 SA(s) authenticated the old way cleared — re-authenticating as modelled")
            report["devices"][d["name"]] = {"changed": changed}
        deadline = time.time() + wait
        for d in routers:
            r = conns[d["name"]]; want = expected[d["name"]]
            while True:
                sas = parse_sas(r.show("show crypto ikev2 sa detail"))
                good = {x["remote"] for x in sas if x["status"] == "READY" and x["remote"] in want and (x.get("auth_sign"), x.get("auth_verify")) == (want[x["remote"]],) * 2}
                if good == set(want): break
                if time.time() > deadline: raise RuntimeError(f"{d['name']}: {len(good)}/{len(want)} tunnels READY with the modelled authentication after {wait}s (missing {sorted(set(want) - good)}): {sas}")
                time.sleep(5)
            if report["devices"][d["name"]]["changed"]: r.show("write memory", timeout=60)
            by = {}
            for ip, m in want.items(): by[m] = by.get(m, 0) + 1
            report["devices"][d["name"]].update(sas_ok=len(good), expected=len(want), by_method=by)
            log(f"{d['name']}: {len(good)}/{len(want)} IKEv2 SAs READY, authenticated as modelled ({', '.join(f'{v} {k}' for k, v in sorted(by.items()))})")
    finally:
        for r in conns.values(): r.close()
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0]); p.add_argument("--force", action="store_true", help="re-enrol even if the certificate is fine")
    p.add_argument("--check", action="store_true", help="report only; exit 1 when a router needs enrolment"); p.add_argument("--json", action="store_true"); p.add_argument("names", nargs="*")
    p.add_argument("--post-apply", action="store_true", help="after the NaC apply: drop the keyrings, clear SAs still on PSK, verify every tunnel re-authenticates with RSA")
    p.add_argument("--rekey", action="store_true", help="with --post-apply: clear every IKEv2 SA of the named routers (after a renewal)")
    a = p.parse_args(); quiet = (lambda *x: None) if a.json else print
    rep = post_apply(a.names, log=quiet, rekey=a.rekey) if a.post_apply else run(a.names, a.force, a.check, log=quiet)
    if a.json: print(json.dumps(rep, indent=2))
    if a.check: sys.exit(1 if any(e["due"] for e in rep["devices"].values()) else 0)


if __name__ == "__main__": main()
