#!/usr/bin/env python3
"""Discover the C8000v routers into the shared Nautobot with the Device Onboarding app
(location c8000v-ipsec-lab, secrets group lab-devices, job "Sync Devices From Network")."""
import argparse, os, sys, time
import pynautobot

p = argparse.ArgumentParser()
p.add_argument("--url", default=os.environ.get("NAUTOBOT_URL", "http://10.0.0.10:8080"))
p.add_argument("--token", default=os.environ.get("NAUTOBOT_TOKEN"))
p.add_argument("ips", nargs="*", default=["10.2.0.11", "10.2.0.12", "10.2.0.13"])
a = p.parse_args()
nb = pynautobot.api(a.url, token=a.token)

def get_or_create(ep, lookup, **defaults):
    o = ep.get(**lookup)
    if o is None:
        o = ep.create(**lookup, **defaults); print(f"  created {ep.name}: {list(lookup.values())[0]}")
    return o

active = nb.extras.statuses.get(name="Active")
lt = nb.dcim.location_types.get(name="Site")
site = get_or_create(nb.dcim.locations, {"name": "c8000v-ipsec-lab"}, location_type=lt.id, status=active.id,
                     description="Catalyst 8000v IPsec VTI + eBGP lab (~/cat8000v-ipsec)")
role = get_or_create(nb.extras.roles, {"name": "vpn-router"}, color="ff9800", content_types=["dcim.device"])
sg = nb.extras.secrets_groups.get(name="lab-devices")        # admin/admin, created by the cat9000v onboarding
ns = nb.ipam.namespaces.get(name="Global")
job = nb.extras.jobs.get(name="Sync Devices From Network")
if not job.enabled:
    job.update({"enabled": True})
data = {"location": site.id, "namespace": ns.id, "ip_addresses": ",".join(a.ips), "port": 22, "timeout": 30,
        "secrets_group": sg.id, "device_role": role.id, "device_status": active.id, "interface_status": active.id,
        "ip_address_status": active.id, "set_mgmt_only": True, "update_devices_without_primary_ip": False,
        "dryrun": False, "memory_profiling": False, "debug": False}
# the job matches existing devices by name + location; devices that were moved to a branch location would be
# duplicated, so only addresses Nautobot does not know yet (anywhere under the lab site) are onboarded
known = {str(getattr(d.primary_ip4, "address", "")).split("/")[0] for d in nb.dcim.devices.filter(location=site.id)}
new_ips = [ip for ip in a.ips if ip not in known]
st = "SUCCESS"
if new_ips:
    data["ip_addresses"] = ",".join(new_ips)
    print(f"==> running '{job.name}' for {new_ips}")
    res = nb.extras.jobs.run(job_id=job.id, data=data); jr = res.job_result.id
    for _ in range(120):
        st = str(nb.extras.job_results.get(jr).status)
        if st in ("SUCCESS", "FAILURE", "REVOKED"): break
        time.sleep(5)
    print(f"==> {st}  {a.url}/extras/job-results/{jr}/")
    for e in nb.extras.job_logs.filter(job_result=jr):
        if str(e.log_level) in ("warning", "error", "critical", "failure"): print(f"   [{e.log_level}] {e.message[:200]}")
else:
    print(f"==> all of {a.ips} already onboarded; refreshing serials only")
# the onboarding job does not refresh existing devices, and a C8000v's serial follows the VM UUID: re-read it over SSH
try:
    from netmiko import ConnectHandler
    for d in nb.dcim.devices.filter(location=site.id):
        ip = getattr(d.primary_ip4, "address", None)
        if not ip or ip.split("/")[0] not in a.ips: continue
        c = ConnectHandler(device_type="cisco_xe", host=ip.split("/")[0], username=os.environ.get("IOSXE_USERNAME", "admin"), password=os.environ.get("IOSXE_PASSWORD", "admin"))
        serial = c.send_command("show version | include Processor board ID").split()[-1]; c.disconnect()
        if serial and serial != d.serial: d.update({"serial": serial}); print(f"   {d.name}: serial refreshed {d.serial} -> {serial}")
except ImportError:
    pass
for d in nb.dcim.devices.filter(location=site.id):
    print(f"   {d.name}: {d.device_type.model} {getattr(d.platform,'name',None)} serial={d.serial} primary={getattr(d.primary_ip4,'address',None)}")
sys.exit(0 if st == "SUCCESS" else 1)
