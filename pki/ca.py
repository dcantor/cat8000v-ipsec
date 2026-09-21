#!/usr/bin/env python3
"""The lab certificate authority for IKEv2 certificate authentication (openssl on the host).

  pki/ca/ca.key     the CA private key — never committed (.gitignore), 0600
  pki/ca/ca.crt     the CA certificate (public, committed): every router trusts it (crypto pki authenticate)
  pki/certs/N.crt   the router certificates the CA issued (public, committed)
  pki/index.json    what was issued to whom: serial, subject, not_before / not_after, SHA-1 fingerprint (what IOS-XE shows)

The routers keep their private keys: `crypto pki enroll` prints a CSR, this CA signs it (`sign`), the certificate goes back in
(`crypto pki import ... certificate`) — tools/pki_enroll.py drives that over SSH. Usage:
  ca.py init [--days 3650]           create the CA (idempotent)
  ca.py sign DEVICE CSR_FILE [--days N] [--san DNS]   -> prints the certificate PEM, records it in the index
  ca.py status [--json]              the index with days left, for the portal / metrics / tests
  ca.py fingerprint FILE             SHA-1 fingerprint of a PEM certificate, IOS style (no colons, upper case)"""
import argparse, datetime, json, os, re, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CA_DIR, CERTS, INDEX = HERE / "ca", HERE / "certs", HERE / "index.json"
CA_KEY, CA_CRT = CA_DIR / "ca.key", CA_DIR / "ca.crt"
ORG = "cat8000v-ipsec"; CA_CN = "cat8000v-ipsec lab CA"


def openssl(*args, input=None):
    r = subprocess.run(["openssl", *args], input=input, capture_output=True, text=True)
    if r.returncode: raise RuntimeError(f"openssl {' '.join(args[:3])}: {r.stderr.strip()[-400:]}")
    return r.stdout


def load_index():
    return json.loads(INDEX.read_text()) if INDEX.exists() else {}


def save_index(idx):
    INDEX.write_text(json.dumps(idx, indent=2, sort_keys=True) + "\n")


def cert_info(pem):
    """subject, issuer, serial (hex, upper, as IOS prints it), validity and the SHA-1 fingerprint of a PEM certificate."""
    out = openssl("x509", "-noout", "-subject", "-issuer", "-serial", "-startdate", "-enddate", "-fingerprint", "-sha1", "-nameopt", "RFC2253", input=pem)
    f = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
    fmt = lambda s: datetime.datetime.strptime(s.strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc).isoformat()
    return {"subject": f["subject"].strip(), "issuer": f["issuer"].strip(), "serial": f["serial"].strip().upper().lstrip("0") or "0",
            "not_before": fmt(f["notBefore"]), "not_after": fmt(f["notAfter"]), "fingerprint": f.get("sha1 Fingerprint", f.get("SHA1 Fingerprint", "")).strip().replace(":", "").upper()}


def init(days=3650):
    CA_DIR.mkdir(parents=True, exist_ok=True); CERTS.mkdir(exist_ok=True)
    if CA_KEY.exists() and CA_CRT.exists(): return False
    openssl("req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", str(days), "-keyout", str(CA_KEY), "-out", str(CA_CRT),
            "-subj", f"/O={ORG}/CN={CA_CN}", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    CA_KEY.chmod(0o600); return True


def sign(device, csr_pem, days=365, san=None):
    """Sign a router's CSR: an end-entity certificate with the IKE-relevant usages; returns the PEM and records it."""
    if not CA_KEY.exists(): raise RuntimeError("no CA yet: run ca.py init")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", device): raise ValueError(f"bad device name {device!r}")
    CERTS.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        ext = Path(td, "ext.cnf"); csr = Path(td, "req.csr"); csr.write_text(csr_pem)
        ext.write_text("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n"
                       "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n" + (f"subjectAltName=DNS:{san}\n" if san else ""))
        pem = openssl("x509", "-req", "-in", str(csr), "-CA", str(CA_CRT), "-CAkey", str(CA_KEY), "-CAcreateserial", "-days", str(days), "-sha256", "-extfile", str(ext))
    (CERTS / f"{device}.crt").write_text(pem)
    idx = load_index(); info = cert_info(pem)
    idx[device] = {**info, "issued": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(), "days": days, "file": f"pki/certs/{device}.crt",
                   "previous": [p for p in ([idx[device]["serial"]] if device in idx else []) + (idx.get(device, {}).get("previous") or [])][:10]}
    save_index(idx)
    return pem


def status():
    """The index with days_left per device, plus the CA itself."""
    now = datetime.datetime.now(datetime.timezone.utc); out = {"ca": None, "devices": {}}
    if CA_CRT.exists():
        out["ca"] = {**cert_info(CA_CRT.read_text()), "file": "pki/ca/ca.crt", "key_present": CA_KEY.exists()}
    for dev, e in sorted(load_index().items()):
        na = datetime.datetime.fromisoformat(e["not_after"])
        out["devices"][dev] = {**e, "days_left": (na - now).total_seconds() / 86400, "expired": na < now}
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0]); sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("init"); i.add_argument("--days", type=int, default=3650)
    s = sub.add_parser("sign"); s.add_argument("device"); s.add_argument("csr"); s.add_argument("--days", type=int, default=365); s.add_argument("--san")
    st = sub.add_parser("status"); st.add_argument("--json", action="store_true")
    fp = sub.add_parser("fingerprint"); fp.add_argument("file")
    a = p.parse_args()
    if a.cmd == "init": print(f"CA {'created' if init(a.days) else 'already present'}: {CA_CRT}")
    elif a.cmd == "sign": sys.stdout.write(sign(a.device, Path(a.csr).read_text(), a.days, a.san))
    elif a.cmd == "fingerprint": print(cert_info(Path(a.file).read_text())["fingerprint"])
    else:
        s = status()
        if a.json: print(json.dumps(s, indent=2)); return
        print(f"CA: {s['ca']['subject'] if s['ca'] else 'none'}" + (f"  until {s['ca']['not_after'][:10]}  key {'present' if s['ca']['key_present'] else 'MISSING'}" if s["ca"] else ""))
        for d, e in s["devices"].items(): print(f"  {d:18s} serial {e['serial']:>6s}  expires {e['not_after'][:10]} ({e['days_left']:6.1f} d{', EXPIRED' if e['expired'] else ''})  {e['fingerprint']}")


if __name__ == "__main__": main()
