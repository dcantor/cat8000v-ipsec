"""Robot Framework keyword library for the C8000v IPsec VTI lab.

Talks to the routers over SSH (netmiko) and RESTCONF (requests) and to the host OS for ping/terraform.
"""
import json
import os
import sys
import socket
import subprocess
import time
from pathlib import Path

import requests
import urllib3
from netmiko import ConnectHandler
from robot.api import logger
from robot.api.deco import keyword, library

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LAB_DIR = Path(__file__).resolve().parents[2]
USERNAME = os.environ.get("IOSXE_USERNAME", "admin")
PASSWORD = os.environ.get("IOSXE_PASSWORD", "admin")


@library(scope="GLOBAL")
class LabLib:
    def __init__(self):
        self._ssh = {}   # device host -> netmiko connection

    # ---- switches: SSH ---------------------------------------------------
    def _conn(self, host):
        if host not in self._ssh:
            self._ssh[host] = ConnectHandler(
                device_type="cisco_xe", host=host, username=USERNAME,
                password=PASSWORD, secret=PASSWORD, fast_cli=False,
            )
            self._ssh[host].enable()
        return self._ssh[host]

    @keyword
    def run_command(self, host, command, timeout=60):
        """Run a show/exec command on a switch over SSH and return its output."""
        out = self._conn(host).send_command(command, read_timeout=float(timeout))
        logger.info(f"<pre>{host}# {command}\n{out}</pre>", html=True)
        return out

    @keyword
    def get_running_config(self, host):
        return self._conn(host).send_command("show running-config", read_timeout=120)

    @keyword
    def close_all_connections(self):
        for c in self._ssh.values():
            try:
                c.disconnect()
            except Exception:
                pass
        self._ssh.clear()

    # ---- switches: RESTCONF ----------------------------------------------
    @keyword
    def restconf_get(self, host, path):
        """GET /restconf/data/<path> and return the parsed JSON."""
        url = f"https://{host}/restconf/data/{path}"
        r = requests.get(url, auth=(USERNAME, PASSWORD), verify=False, timeout=30,
                         headers={"Accept": "application/yang-data+json"})
        logger.info(f"GET {url} -> {r.status_code}\n{r.text[:2000]}")
        r.raise_for_status()
        return r.json() if r.text else {}

    # ---- Nautobot (shared NMS of the cat9000v lab) ---------------------------
    def _nautobot(self):
        if not hasattr(self, "_nb"):
            url = os.environ.get("NAUTOBOT_URL", "http://10.0.0.10:8080")
            token = os.environ.get("NAUTOBOT_TOKEN")
            if not token:
                token = subprocess.run(["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
                                        "lab@10.0.0.10", "grep ^NAUTOBOT_SUPERUSER_API_TOKEN /opt/nautobot/.env | cut -d= -f2"],
                                       capture_output=True, text=True, timeout=30).stdout.strip()
            self._nb = (url, token)
        return self._nb

    @keyword
    def nautobot_get(self, path, **params):
        url, token = self._nautobot()
        r = requests.get(f"{url}/api/{path.lstrip('/')}", params=params, timeout=60,
                         headers={"Authorization": f"Token {token}", "Accept": "application/json"})
        logger.info(f"GET {r.url} -> {r.status_code}\n{r.text[:1500]}"); r.raise_for_status()
        return r.json()

    @keyword
    def nautobot_graphql(self, query):
        url, token = self._nautobot()
        r = requests.post(f"{url}/api/graphql/", json={"query": query}, timeout=60, headers={"Authorization": f"Token {token}"})
        logger.info(f"GraphQL {query}\n-> {r.status_code} {r.text[:2000]}"); r.raise_for_status()
        body = r.json()
        if body.get("errors"): raise AssertionError(f"GraphQL errors: {body['errors']}")
        return body["data"]

    @keyword
    def run_vyos_command(self, host, command, timeout=60):
        """Run an operational command on a VyOS firewall (SSH, vyos/vyos)."""
        key = f"vyos:{host}"
        if key not in self._ssh:
            self._ssh[key] = ConnectHandler(device_type="vyos", host=host, username=os.environ.get("VYOS_USERNAME", "vyos"), password=os.environ.get("VYOS_PASSWORD", "vyos"))
        out = self._ssh[key].send_command(command, read_timeout=timeout)
        logger.info(f"<pre>{host}# {command}\n{out}</pre>", html=True)
        return out

    @keyword
    def vyos_check(self):
        url, token = self._nautobot()
        r = subprocess.run([sys.executable, str(LAB_DIR / "nautobot" / "render_vyos.py"), "--check"], capture_output=True, text=True,
                           timeout=300, env={**os.environ, "NAUTOBOT_URL": url, "NAUTOBOT_TOKEN": token})
        logger.info(f"<pre>{r.stdout[-4000:]}\n{r.stderr[-1000:]}</pre>", html=True)
        return r.returncode

    @keyword
    def portal_inventory(self, live=False):
        """The VPN Provisioning Portal's inventory as parsed JSON; `live=True` collects state (incl. CPU) from the headends now."""
        url = os.environ.get("PORTAL_URL", "http://127.0.0.1:8090")
        r = requests.get(f"{url}/api/vpn-inventory", params={"live": "true" if live else "false", "refresh": "true" if live else "false"}, timeout=300)
        logger.info(f"GET {r.url} -> {r.status_code}\n{r.text[:1500]}"); r.raise_for_status()
        return r.json()

    @keyword
    def portal_get(self, path, **params):
        """A read from the portal's API as a logged-in viewer (PORTAL_USER / PORTAL_PASSWORD, default viewer / viewer): the endpoints
        behind the login, such as /api/firewalls. The session cookie is kept for the suite."""
        url = os.environ.get("PORTAL_URL", "http://127.0.0.1:8090")
        if not hasattr(self, "_portal"):
            self._portal = requests.Session()
            r = self._portal.post(f"{url}/api/login", json={"username": os.environ.get("PORTAL_USER", "viewer"), "password": os.environ.get("PORTAL_PASSWORD", "viewer")}, timeout=30)
            logger.info(f"POST {url}/api/login -> {r.status_code}"); r.raise_for_status()
        r = self._portal.get(f"{url}{path}", params=params, timeout=300)
        logger.info(f"GET {r.url} -> {r.status_code}\n{r.text[:1500]}"); r.raise_for_status()
        return r.json()

    @keyword
    def victorialogs_query(self, query):
        """One LogsQL query against VictoriaLogs on the NMS (VICTORIALOGS_URL, default http://10.0.0.10:9428) -> list of result rows."""
        url = os.environ.get("VICTORIALOGS_URL", "http://10.0.0.10:9428")
        r = requests.post(f"{url}/select/logsql/query", data={"query": query}, timeout=60)
        logger.info(f"LogsQL {query} -> {r.status_code}\n{r.text[:1500]}"); r.raise_for_status()
        return [json.loads(l) for l in r.text.splitlines() if l.strip()]

    @keyword
    def render_nac_check(self):
        url, token = self._nautobot()
        r = subprocess.run([sys.executable, str(LAB_DIR / "nautobot" / "render_nac.py"), "--check"], capture_output=True, text=True,
                           timeout=120, env={**os.environ, "NAUTOBOT_URL": url, "NAUTOBOT_TOKEN": token})
        logger.info(f"<pre>{r.stdout[-4000:]}\n{r.stderr[-1000:]}</pre>", html=True)
        return r.returncode

    # ---- host-side helpers -----------------------------------------------
    @keyword
    def host_ping(self, target, count=3):
        """ICMP ping from the host; fails unless at least one reply."""
        r = subprocess.run(["ping", "-c", str(count), "-W", "2", target], capture_output=True, text=True)
        logger.info(r.stdout)
        if r.returncode != 0:
            raise AssertionError(f"no ICMP reply from {target}")

    @keyword
    def tcp_port_should_be_open(self, host, port, timeout=5):
        with socket.socket() as s:
            s.settimeout(float(timeout))
            try:
                s.connect((host, int(port)))
            except OSError as e:
                raise AssertionError(f"{host}:{port} not reachable: {e}")

    @keyword
    def terraform_plan_exit_code(self):
        """Run `terraform plan -detailed-exitcode` via lab.sh nac: 0 = no drift, 2 = changes."""
        r = subprocess.run([str(LAB_DIR / "lab.sh"), "nac", "plan", "-detailed-exitcode",
                            "-no-color", "-input=false", "-lock=false"],
                           capture_output=True, text=True, timeout=600)
        logger.info(f"<pre>{r.stdout[-6000:]}\n{r.stderr[-2000:]}</pre>", html=True)
        return r.returncode

    @keyword
    def save_text_file(self, path, content):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        logger.info(f"wrote {p} ({len(content)} bytes)")
        return str(p)

    @keyword
    def unique_marker(self, prefix="robot"):
        return f"{prefix}-{int(time.time())}"
