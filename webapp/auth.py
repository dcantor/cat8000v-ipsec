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

OIDC: optional, next to the local users — webapp/oidc.json (or PORTAL_OIDC_* variables) names the provider (any OpenID Connect
issuer with discovery; the lab uses Gitea on the NMS), the client, and how identities map to the three roles: `users` (login
name -> role), `groups` (a `groups` claim value -> role, e.g. an org or org:team in Gitea), else `default_role`. The flow is the
authorization code with PKCE (GET /api/oidc/login -> provider -> GET /api/oidc/callback), the id_token is verified against the
provider's JWKS (issuer, audience, expiry, nonce); the session cookie is the same as a local login's, marked `o` so it is
trusted without a users.json entry. The middleware only ever sees `request.state.user = {"name", "role", "via"}`.
"""
import argparse, base64, contextvars, hashlib, hmac, json, os, secrets, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
USERS = Path(os.environ.get("PORTAL_USERS", HERE / "users.json")); SECRET = HERE / ".secret"
ROLES = ["viewer", "operator", "approver"]
COOKIE = "portal_session"; SESSION_HOURS = 12
current_user = contextvars.ContextVar("portal_user", default=None)

# what each verb / path needs: the first matching rule wins; anything not listed needs a viewer login
OPEN = [("GET", "/metrics"), ("GET", "/api/sd"), ("GET", "/api/vpn-inventory"), ("GET", "/api/runs"), ("GET", "/api/intent"), ("GET", "/api/cities"), ("GET", "/api/pki"), ("GET", "/api/hosts"), ("GET", "/api/oidc"), ("GET", "/api/oidc/login"), ("GET", "/api/oidc/callback"),
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


def make_session(name, role, hours=SESSION_HOURS, oidc=False):
    body = base64.urlsafe_b64encode(json.dumps({"u": name, "r": role, "e": int(time.time()) + hours * 3600, **({"o": 1} if oidc else {})}).encode()).decode()
    return body + "." + hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()


def read_session(value):
    try:
        body, sig = value.rsplit(".", 1)
        if not hmac.compare_digest(sig, hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()): return None
        d = json.loads(base64.urlsafe_b64decode(body.encode()))
        if d["e"] < time.time(): return None
        if d.get("o"): return {"name": d["u"], "role": d["r"] if d["r"] in ROLES else "viewer", "via": "oidc"}   # an OIDC identity: the role was mapped at login, good for the session
        u = load_users().get(d["u"])
        if not u: return None
        return {"name": d["u"], "role": u.get("role", d["r"])}   # the role is re-read: a demotion takes effect at once
    except Exception:  # noqa: BLE001
        return None


# ---- OIDC ----------------------------------------------------------------------------------------------------------------
OIDC_FILE = Path(os.environ.get("PORTAL_OIDC", HERE / "oidc.json"))


def oidc_config():
    """The provider settings, or None when OIDC is not configured: issuer (server-side URL, used for discovery and the token /
    userinfo calls), public_url (what the browser is sent to, when the issuer is only reachable from the lab host), client_id /
    client_secret, redirect_uri, scopes, provider (display name), users / groups / default_role for the role mapping."""
    cfg = json.loads(OIDC_FILE.read_text()) if OIDC_FILE.exists() else {}
    for k in ("issuer", "public_url", "client_id", "client_secret", "redirect_uri", "scopes", "provider", "default_role"):
        v = os.environ.get("PORTAL_OIDC_" + k.upper())
        if v: cfg[k] = v
    if not (cfg.get("issuer") and cfg.get("client_id")): return None
    return {"scopes": "openid profile email groups", "provider": "OIDC", "default_role": "viewer", "users": {}, "groups": {}, "public_url": cfg.get("issuer"), **cfg}


_disc = {}
def oidc_discovery(cfg):
    import requests
    key = cfg["issuer"]
    if key not in _disc or time.time() - _disc[key]["t"] > 3600:
        r = requests.get(cfg["issuer"].rstrip("/") + "/.well-known/openid-configuration", timeout=15); r.raise_for_status()
        _disc[key] = {"t": time.time(), "d": r.json()}
    return _disc[key]["d"]


def oidc_begin(cfg):
    """(authorize URL, state cookie value): state, nonce and a PKCE verifier signed into a short-lived cookie."""
    import urllib.parse
    d = oidc_discovery(cfg); state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    authz = d["authorization_endpoint"]
    if cfg.get("public_url") and cfg["public_url"].rstrip("/") != cfg["issuer"].rstrip("/"):   # the browser reaches the provider by another name than the lab host does
        authz = cfg["public_url"].rstrip("/") + authz[len(d["issuer"].rstrip("/")):] if authz.startswith(d["issuer"].rstrip("/")) else authz
    url = authz + "?" + urllib.parse.urlencode({"response_type": "code", "client_id": cfg["client_id"], "redirect_uri": cfg["redirect_uri"], "scope": cfg["scopes"], "state": state, "nonce": nonce,
                                                 "code_challenge": challenge, "code_challenge_method": "S256"})
    body = base64.urlsafe_b64encode(json.dumps({"s": state, "n": nonce, "v": verifier, "e": int(time.time()) + 600}).encode()).decode()
    return url, body + "." + hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()


def oidc_finish(cfg, code, state, flow_cookie):
    """Exchange the code, verify the id_token, read the userinfo, map the role -> {"name", "role", "via", "claims"}."""
    import requests, jwt
    body, sig = (flow_cookie or ".").rsplit(".", 1)
    if not hmac.compare_digest(sig, hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()): raise ValueError("login flow cookie missing or tampered — start again")
    flow = json.loads(base64.urlsafe_b64decode(body.encode()))
    if flow["e"] < time.time(): raise ValueError("login flow expired — start again")
    if not hmac.compare_digest(flow["s"], state or ""): raise ValueError("state mismatch")
    d = oidc_discovery(cfg)
    r = requests.post(d["token_endpoint"], data={"grant_type": "authorization_code", "code": code, "redirect_uri": cfg["redirect_uri"], "code_verifier": flow["v"], "client_id": cfg["client_id"], "client_secret": cfg.get("client_secret", "")},
                      auth=(cfg["client_id"], cfg["client_secret"]) if cfg.get("client_secret") else None, headers={"Accept": "application/json"}, timeout=20)
    if r.status_code != 200: raise ValueError(f"token endpoint: {r.status_code} {r.text[:200]}")
    tok = r.json()
    jwks = jwt.PyJWKClient(d["jwks_uri"]); key = jwks.get_signing_key_from_jwt(tok["id_token"])
    claims = jwt.decode(tok["id_token"], key.key, algorithms=[key.algorithm_name] if hasattr(key, "algorithm_name") else ["RS256", "ES256"], audience=cfg["client_id"], issuer=d["issuer"], options={"require": ["exp", "iat", "sub"]})
    if claims.get("nonce") != flow["n"]: raise ValueError("nonce mismatch")
    info = {}
    if d.get("userinfo_endpoint") and tok.get("access_token"):
        u = requests.get(d["userinfo_endpoint"], headers={"Authorization": f"Bearer {tok['access_token']}"}, timeout=15)
        if u.status_code == 200: info = u.json()
    name = info.get("preferred_username") or claims.get("preferred_username") or info.get("email") or claims.get("email") or claims["sub"]
    groups = list(info.get("groups") or claims.get("groups") or [])
    role = (cfg.get("users") or {}).get(name)
    if role is None:
        ranks = [(cfg.get("groups") or {}).get(g) for g in groups]; ranks = [x for x in ranks if x in ROLES]
        role = max(ranks, key=role_rank) if ranks else cfg.get("default_role", "viewer")
    if role not in ROLES: role = "viewer"
    return {"name": name, "role": role, "via": "oidc", "groups": groups, "provider": cfg.get("provider")}


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
