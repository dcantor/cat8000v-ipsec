"""Login, roles and the audit trail for the portal.

Users are local (users.json next to this file: name -> salted scrypt hash + role); `python3 auth.py add NAME --role ROLE`
manages them. Roles are ordered — viewer < operator < approver:
  viewer     read everything (inventory, runs, tools, audit)
  operator   start runs that build or change (deploy, plan, test, spoke, hub, rotate, rehome), resume runs
  approver   everything, plus the destructive run (remove) and user management
A login sets a signed cookie (HMAC over user / role / expiry with a secret generated on first start, .secret next to this
file). Machine access is a bearer token per user (`python3 auth.py token NAME`), same roles. Prometheus (/metrics, /api/sd) and
the read-only endpoints the lab hub and the Robot suites poll stay open; everything else asks for a login.

The audit trail is append-only JSONL (runs/audit.jsonl): every login / logout and every write request — who, from where, what
(path, run mode, the spec with secrets redacted), and the run id it produced. GET /api/audit reads it; the Audit tab shows it.

OIDC: the middleware only needs `request.state.user = {"name", "role"}`; an OIDC login would set the same cookie after the
provider's callback and map groups to the three roles — nothing else in the portal changes.
"""
import argparse, base64, contextvars, hashlib, hmac, json, os, secrets, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
USERS = Path(os.environ.get("PORTAL_USERS", HERE / "users.json")); SECRET = HERE / ".secret"
ROLES = ["viewer", "operator", "approver"]
COOKIE = "portal_session"; SESSION_HOURS = 12
current_user = contextvars.ContextVar("portal_user", default=None)

# what each verb / path needs: the first matching rule wins; anything not listed needs a viewer login
OPEN = [("GET", "/metrics"), ("GET", "/api/sd"), ("GET", "/api/vpn-inventory"), ("GET", "/api/runs"), ("GET", "/api/intent"), ("GET", "/api/cities"), ("GET", "/api/pki"),
        ("GET", "/api/me"), ("POST", "/api/login"), ("POST", "/api/logout"), ("GET", "/docs"), ("GET", "/redoc"), ("GET", "/openapi.json"), ("GET", "/static/"), ("GET", "/results/"), ("GET", "/")]
APPROVER_RUN_MODES = {"remove"}


def _secret():
    if not SECRET.exists(): SECRET.write_text(secrets.token_hex(32)); SECRET.chmod(0o600)
    return SECRET.read_text().strip().encode()


def load_users():
    return json.loads(USERS.read_text()) if USERS.exists() else {}


def save_users(users):
    USERS.write_text(json.dumps(users, indent=2) + "\n"); USERS.chmod(0o600)


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt, hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1).hex()


def check_password(user, password):
    if not user or not user.get("hash"): return False
    return hmac.compare_digest(hash_password(password, user["salt"])[1], user["hash"])


def role_rank(role): return ROLES.index(role) if role in ROLES else -1


def make_session(name, role, hours=SESSION_HOURS):
    body = base64.urlsafe_b64encode(json.dumps({"u": name, "r": role, "e": int(time.time()) + hours * 3600}).encode()).decode()
    return body + "." + hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()


def read_session(value):
    try:
        body, sig = value.rsplit(".", 1)
        if not hmac.compare_digest(sig, hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()): return None
        d = json.loads(base64.urlsafe_b64decode(body.encode()))
        if d["e"] < time.time(): return None
        u = load_users().get(d["u"])
        if not u: return None
        return {"name": d["u"], "role": u.get("role", d["r"])}   # the role is re-read: a demotion takes effect at once
    except Exception:  # noqa: BLE001
        return None


def user_for_token(token):
    for name, u in load_users().items():
        if u.get("token") and hmac.compare_digest(u["token"], token): return {"name": name, "role": u["role"], "via": "token"}
    return None


def is_open(method, path):
    for m, p in OPEN:
        if method != m: continue
        if path == p: return True
        if p != "/" and p.endswith("/") and path.startswith(p): return True     # a prefix rule (/static/, /results/); "/" itself is exact
        if p == "/api/runs" and path.startswith("/api/runs/") and not path.endswith("/resume"): return True   # reading a run (the hub polls these)
    return False


def required_role(method, path, body=None):
    """The role a request needs (None = open). Writes need an operator; removing a spoke, and managing users, an approver."""
    if is_open(method, path): return None
    if method == "GET": return "viewer"
    if path.endswith("/validate"): return "viewer"   # validating a spec changes nothing
    if path.startswith("/api/users"): return "approver"
    if path == "/api/runs" and isinstance(body, dict) and body.get("mode") in APPROVER_RUN_MODES: return "approver"
    return "operator"


# ---- audit -------------------------------------------------------------------------------------------------------------
def redact(obj):
    """Secrets never reach the audit log: a psk becomes its fingerprint, passwords / tokens are dropped."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in ("psk", "pre_shared_key"): out[k] = f"<sha256:{hashlib.sha256(str(v).encode()).hexdigest()[:12]}>" if v else v
            elif k in ("password", "token", "secret"): out[k] = "<redacted>"
            else: out[k] = redact(v)
        return out
    if isinstance(obj, list): return [redact(x) for x in obj]
    return obj


def audit(logfile, user, action, ip=None, **detail):
    rec = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "ts": time.time(), "user": (user or {}).get("name"), "role": (user or {}).get("role"), "ip": ip, "action": action, **redact(detail)}
    logfile.parent.mkdir(parents=True, exist_ok=True)
    with logfile.open("a") as f: f.write(json.dumps(rec) + "\n")
    return rec


def read_audit(path, limit=200, user=None, action=None):
    if not path.exists(): return []
    rows = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    if user: rows = [r for r in rows if r.get("user") == user]
    if action: rows = [r for r in rows if (r.get("action") or "").startswith(action)]
    return rows[-limit:][::-1]


# ---- CLI ---------------------------------------------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0]); sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add", help="add or update a user"); a.add_argument("name"); a.add_argument("--role", choices=ROLES, required=True); a.add_argument("--password", help="prompted when omitted")
    d = sub.add_parser("del", help="delete a user"); d.add_argument("name")
    t = sub.add_parser("token", help="(re)generate a bearer token for machine access"); t.add_argument("name")
    sub.add_parser("list", help="users and roles")
    args = p.parse_args(); users = load_users()
    if args.cmd == "add":
        pw = args.password or __import__("getpass").getpass(f"password for {args.name}: ")
        salt, h = hash_password(pw); users[args.name] = {**users.get(args.name, {}), "role": args.role, "salt": salt, "hash": h}; save_users(users); print(f"{args.name}: {args.role}")
    elif args.cmd == "del": users.pop(args.name, None); save_users(users); print(f"{args.name} removed")
    elif args.cmd == "token":
        users[args.name]["token"] = secrets.token_urlsafe(32); save_users(users); print(users[args.name]["token"])
    else:
        for n, u in users.items(): print(f"{n:16s} {u['role']:9s} {'token' if u.get('token') else ''}")


if __name__ == "__main__": main()
