"""Pydantic models for the portal's REST API (they drive the Swagger page at /docs)."""
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field


class Site(BaseModel):
    name: str = Field(..., description="Lab-level location in Nautobot (read-only)", examples=["c8000v-ipsec-lab"])
    description: str = ""
    site_code: str = Field("", examples=["LAB-IPSEC"])
    contact: str = Field("", examples=["noc@lab.local"])


class VpnService(BaseModel):
    name: str = Field(..., examples=["IPSEC_VPN"])
    description: str = ""
    change_ticket: str = Field("", examples=["CHG0042002"])
    owner: str = Field("", examples=["network team"])


class IkePolicy(BaseModel):
    encryption: str = Field("AES-256-CBC", examples=["AES-256-CBC"])
    integrity: str = Field("SHA256", examples=["SHA256"])
    dh_group: str = Field("14", examples=["14"])
    lifetime: int = 86400
    authentication: Literal["psk", "certificate"] = Field("psk", description="psk: one pre-shared key per spoke · certificate: every router enrols with the lab CA (rsa-sig); the keys stay in the intent, unused")


class Pki(BaseModel):
    """Certificate settings (IKE authentication `certificate`): names the routers use and the CA's issuing policy."""
    trustpoint: str = "LAB-CA"; keypair: str = "LAB-VPN"; certificate_map: str = "LAB-CERT-MAP"
    key_bits: int = Field(2048, description="RSA modulus generated on each router (2048 / 3072 / 4096)")
    validity_days: int = Field(365, description="lifetime of a router certificate"); renew_before_days: int = Field(30, description="the pki step renews a certificate this close to expiry")


class IpsecPolicy(BaseModel):
    encryption: str = "AES-256-CBC"
    integrity: str = "SHA256"
    lifetime: int = 3600


class Dpd(BaseModel):
    enabled: bool = True
    interval: int = 30
    retries: int = 5


class Profile(BaseModel):
    name: str = Field(..., examples=["VPN-IPSEC"])
    ike: IkePolicy
    ipsec: IpsecPolicy
    dpd: Dpd
    pki: Optional[Pki] = Field(None, description="certificate settings; used when ike.authentication is certificate")
    ios: dict[str, str] = Field(..., description="Cisco object names (ikev2_proposal, ikev2_policy, ikev2_keyring, ikev2_profile, transform_set, ipsec_profile)")


class Customer(BaseModel):
    """The customer a branch belongs to (every branch is a customer of ACME, the provider that owns the headends): a Nautobot tenant."""
    company: str = Field(..., examples=["Bluewater Logistics LLC"])
    address: str = Field("", description="street address of the branch (the Nautobot location's physical address)", examples=["1200 Harbor Dr, Suite 300, Boston, MA 02110"])
    industry: str = Field("", examples=["Logistics"])
    account_id: str = Field("", description="ACME account number", examples=["ACME-482913"])
    service_tier: Literal["Bronze", "Silver", "Gold"] = "Bronze"
    contract_start: str = Field("", description="ISO date", examples=["2024-03-01"])


class DesignPattern(BaseModel):
    """The ACME design pattern of a branch — it follows from the number of tunnels (headends) the branch has."""
    code: str = Field(..., examples=["ACME-DH"]); name: str = Field(..., examples=["Dual headend (resilient)"]); description: str = ""; tunnels: int = 0


class Device(BaseModel):
    name: str = Field(..., description="hostname / Nautobot device name", examples=["spoke1"])
    mgmt_ip: str = Field(..., description="management address (fixed by the VM's day-0 config)", examples=["10.2.0.12"])
    role: Literal["hub", "spoke", "dci", "partner", "firewall", "host"] = Field(..., description="hub / spoke: the VPN routers · dci: ACME's data-centre interconnect off a headend (plain eBGP) · partner: an acquired company's edge router behind the DCI · firewall · host: a LAN host")
    hub: Optional[str] = Field(None, description="firewall only: the headend it fronts")
    router: Optional[str] = Field(None, description="LAN host only: the router it hangs off (eth1 = .2 of that router's site LAN, gateway .1 on the router's LAN port)")
    asn: Optional[int] = Field(None, examples=[65201])
    router_id: Optional[str] = Field(None, examples=["10.255.1.2"])
    lan: Optional[str] = Field(None, description="site LAN /24 on the router's LAN port (.1; the LAN host is .2)", examples=["192.168.12.0/24"])
    comments: str = ""
    region: Optional[str] = Field(None, examples=["East"])
    site: Optional[str] = Field(None, description="branch / HQ location in Nautobot", examples=["branch-1"])
    site_code: str = ""
    contact: str = ""
    psk: Optional[str] = Field(None, description="spoke's own pre-shared key (spokes only; never stored in Nautobot)")
    bandwidth_mbps: Optional[int] = Field(None, description="firewall only: throughput it can carry (bounds the headend's capacity)", examples=[50])
    city: Optional[str] = Field(None, description="where the site is (shown on the map)", examples=["Boston, MA"])
    lat: Optional[float] = None; lon: Optional[float] = None
    psk_rotated: Optional[str] = Field(None, description="when the spoke's key was last rotated")
    ike_authentication: Optional[Literal["psk", "certificate"]] = Field(None, description="spokes only: how this spoke authenticates IKEv2 (chosen at provisioning, changeable later); unset = the lab default profile.ike.authentication")
    customer: Optional[Customer] = Field(None, description="spokes and partner routers: the customer this site belongs to (a Nautobot tenant; generated when missing)")
    loopbacks: Optional[list[dict[str, Any]]] = Field(None, description="extra loopbacks the router originates besides Loopback0: [{name, address, description, advertise, namespace}] — the acquisition's service prefix, and its server on a prefix that overlaps ACME's (its own Nautobot namespace)")
    nat: Optional[dict[str, Any]] = Field(None, description="the DCI's twice-NAT for overlapping address space: {inside_interface, outside_interface, dns_fixup, overlaps: [{prefix, inside_global, outside_local, description}]}")
    dns: Optional[dict[str, Any]] = Field(None, description="the DNS zone this router answers for: {domain, hosts: {name: address}} — the names the acquisition resolves through the DCI's NAT (with DNS fix-up)")
    dns_client: Optional[dict[str, Any]] = Field(None, description="where this router resolves names: {server, source_interface, domain} — the acquisition asks ACME's server through the DCI, sourced from its translated address")
    address: Optional[str] = Field(None, description="headends only: the street address of ACME's regional site (the Nautobot location's physical address)")


class Link(BaseModel):
    a: str = Field(..., description="first end (the headend)"); a_port: int
    b: str = Field(..., description="second end (the spoke)"); b_port: int
    prefix: str = Field(..., examples=["100.65.1.0/30"])


class Tunnel(BaseModel):
    id: int = Field(..., description="TunnelN on both routers", examples=[1])
    hub: str
    spoke: str
    prefix: str = Field(..., examples=["172.17.1.0/30"])


class Intent(BaseModel):
    """The whole VPN service intent — what the Provision form edits and every pipeline step reads."""
    site: Site
    vpn: VpnService
    profile: Profile
    regions: list[str] = Field(..., description="ordered geographically; distance = index difference", examples=[["East", "Central", "West"]])
    devices: list[Device]
    links: list[Link]
    tunnels: list[Tunnel]
    oob: dict[str, str]
    domain_name: str = "lab.local"
    capacity: dict[str, int] = Field(default={"tunnels_per_headend": 50, "bandwidth_per_tunnel_mbps": 8},
                                     description="tunnels_per_headend: slots per headend; bandwidth_per_tunnel_mbps: what every tunnel commits of its headend firewall's bandwidth_mbps")
    internet: Optional[dict[str, Any]] = Field(None, description="internet breakout: {enabled: bool, uplink_port: N} — each firewall NATs the site LANs out of ethN, headends originate a default route, spokes prefer the nearest headend")
    provider: Optional[dict[str, Any]] = Field(None, description="the provider that sells the service and owns the headends: {name, group, address, description} (ACME Networks; a Nautobot tenant)")


class RunOptions(BaseModel):
    golden: bool = Field(True, description="run Golden Config backup/intended/compliance after apply")
    test: bool = Field(True, description="run the Robot Framework suite at the end")
    delete_disk: bool = Field(True, description="(remove) delete the VM disk and node directory")


class SpokeLink(BaseModel):
    hub: str = Field(..., examples=["central-headend"])
    edge: Optional[str] = Field(None, description="device the link lands on: the headend's firewall (fw-…) or the headend itself", examples=["fw-central"])
    hub_port: int = Field(..., description="port number on the edge device (ethN on a firewall, GigabitEthernetN on a headend)", examples=[6])
    spoke_port: int = Field(..., examples=[2])
    tunnel_id: int = Field(..., examples=[12])
    wan_prefix: str = Field(..., examples=["100.65.12.0/30"])
    tunnel_prefix: str = Field(..., examples=["172.17.12.0/30"])
    spoke: Optional[str] = None


class SpokeSpec(BaseModel):
    """A new spoke: identity, metadata and one link per headend (get a fully suggested one from GET /api/spokes/suggest)."""
    name: str = Field(..., examples=["spoke6"]); mgmt_ip: str = Field(..., examples=["10.2.0.19"])
    node_idx: int = Field(..., description="VM index (MACs, UDP ports); from suggest"); console_port: int = Field(..., description="serial console TCP port; from suggest")
    router_id: str; lan: str; asn: int
    region: str = Field(..., examples=["West"]); site: str = Field(..., examples=["branch-6"]); site_code: str = ""; contact: str = ""
    city: str = Field("", description="where the branch is (a catalogue city, GET /api/cities, or any name with lat / lon); shown on the portal's map", examples=["Denver, CO"])
    lat: Optional[float] = Field(None, description="site latitude (filled from the catalogue for a known city)"); lon: Optional[float] = None
    psk: str = Field(..., description="the spoke's own pre-shared key (8-64 chars; kept even when the spoke authenticates with a certificate, so it can switch back)")
    ike_authentication: Optional[Literal["psk", "certificate"]] = Field(None, description="how the spoke authenticates IKEv2: psk, or certificate (enrolled with the lab CA); unset = the lab default")
    customer: Optional[Customer] = Field(None, description="the customer this branch belongs to (suggest proposes one; a Nautobot tenant is created for the company)")
    comments: str = ""; change_ticket: str = ""; ram_mib: int = 4096
    role: Literal["spoke"] = "spoke"
    links: list[SpokeLink] = Field(..., description="at least two headends", min_length=2)
    spoke_port: Optional[int] = None


class HubSpec(BaseModel):
    """A new headend; it gets a link + tunnel to every spoke listed in connect_spokes."""
    name: str = Field(..., examples=["north-headend"]); mgmt_ip: str; node_idx: int; console_port: int
    router_id: str; lan: str; asn: int
    region: str; site: str; site_code: str = ""; contact: str = ""
    city: str = ""; lat: Optional[float] = None; lon: Optional[float] = None
    comments: str = ""; change_ticket: str = ""; ram_mib: int = 4096
    role: Literal["hub"] = "hub"
    connect_spokes: list[str] = Field(default_factory=list)


class RemoveSpec(BaseModel):
    name: str = Field(..., description="spoke to decommission", examples=["spoke5"])


class RunRequest(BaseModel):
    """Start a pipeline run. Which body fields matter depends on `mode`."""
    mode: Literal["deploy", "plan", "test", "spoke", "hub", "remove", "rotate", "rehome", "renew", "auth", "golden", "remediate", "reapply"] = Field(..., description=(
        "deploy: intent → Nautobot → NAC → terraform plan+apply → Golden Config → tests · plan: dry run through terraform plan · "
        "test: Robot suite only · spoke: provision a new spoke VM (needs `spoke`) · hub: provision a new headend (needs `hub`) · remove: decommission a spoke (needs `spoke.name`) · rotate: new pre-shared key for a spoke · rehome: a spoke onto other headends · renew: a new certificate for a router (needs `spoke.name`) · auth: switch a deployed spoke between pre-shared key and certificate (needs `spoke.name` and `spoke.ike_authentication`) · golden: Nautobot Golden Config backup / intended / compliance only · "
        "remediate: push Nautobot's remediation lines for a router's non-compliant features (needs `spoke.name`, optional `spoke.features`), then Golden Config · reapply: re-assert the model on one router through a targeted Terraform apply (needs `spoke.name`), then Golden Config"))
    intent: Optional[Intent] = Field(None, description="deploy/plan: the intent to save and deploy")
    spoke: Optional[dict[str, Any]] = Field(None, description="spoke: a SpokeSpec · remove: {\"name\": ...} · rotate: {\"name\": ..., \"psk\": optional chosen key} · rehome: {\"name\": ..., \"hubs\": [wanted headends]} · renew: {\"name\": router} · auth: {\"name\": spoke, \"ike_authentication\": psk | certificate} · remediate: {\"name\": router, \"features\": optional [compliance features]} · reapply: {\"name\": router}")
    hub: Optional[HubSpec] = None
    options: RunOptions = RunOptions()


class Step(BaseModel):
    name: str; title: str; status: Literal["pending", "running", "success", "failed", "skipped"]
    started: Optional[float] = None; finished: Optional[float] = None; summary: str = ""


class TestResult(BaseModel):
    name: str; status: str; message: str = ""; elapsed: Optional[str] = None


class TestSuite(BaseModel):
    name: str; tests: list[TestResult]; passed: int; failed: int


class TestReport(BaseModel):
    suites: list[TestSuite]; total: int; passed: int; failed: int


class Run(BaseModel):
    id: str = Field(..., examples=["2026-09-13_14-40-20-0fa9"])
    mode: str; status: Literal["queued", "running", "success", "failed", "interrupted", "cancelled"]
    started: float; finished: Optional[float] = None
    queue_position: Optional[int] = Field(None, description="queued runs: place in line (runs execute one at a time, in the order they were started)")
    waiting_for: Optional[str] = Field(None, description="queued runs: the id of the run executing now")
    user: Optional[str] = Field(None, description="who started the run")
    steps: list[Step]
    tests: Optional[TestReport] = None
    results_dir: Optional[str] = Field(None, description="results/<dir>/ holds report.html, log.html and config backups")
    error: Optional[str] = None
    options: dict[str, Any] = {}
    site: Optional[str] = None; vpn: Optional[str] = None; change_ticket: Optional[str] = None
    devices: list[str] = []
    spoke: Optional[dict[str, Any]] = None
    resume_of: Optional[str] = None
    log: Optional[list[dict[str, Any]]] = Field(None, description="[{t, line}] — only on GET /api/runs/{id}, from `since`")
    log_offset: Optional[int] = None


class Problems(BaseModel):
    problems: list[str] = Field(..., description="empty when valid")


class SpokeValidation(Problems):
    hub_changes: Optional[dict[str, Any]] = Field(None, description="what each headend and the spoke will get (only when valid)")


class RemovalPlan(Problems):
    details: Optional[dict[str, Any]] = None
