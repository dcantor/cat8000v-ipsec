# Portal demo

`portal-demo.mp4` (H.264, 1400×860, ~3½ min) and `portal-demo.gif` (960 px, same scenes) walk through the VPN provisioning portal
with on-screen annotations — a numbered caption banner per scene and callouts pointing at the control being shown:

1. sign-in: local roles (viewer / operator / approver) and single sign-on (OIDC via Gitea)
2. Provision: the intent form; the routers table with per-branch IKE authentication, certificates and the day-2 actions
   (Change auth, Rotate PSK, Renew cert, Re-home, Remove); the Change-auth dialog
3. the add-spoke wizard: identity and the customer block (every branch is a customer of ACME), auto-suggested addressing, the
   hub / spoke review with the design pattern
4. runs: live status per step, the queue, resume
5. Inventory: KPIs, topology and map, headend capacity, the per-tunnel report, the LAN hosts' ping mesh (live)
6. Branches: customers, ACME design patterns, the filter bar
7. a router's page: customer box, tunnels, firewall rules and log, live show commands, configuration (running / intended /
   backup, dark toggle) and the Gitea history
8. Firewalls; 9. Compliance: the report, a cell's detail with Remediate / Re-apply, the drift history, a real Golden Config run
10. Tools, Audit, dark mode, the REST API (Swagger)

`nautobot-nac-demo.gif` shows where the data lives in Nautobot and how NaC consumes it (`record_nautobot.py`).

Re-record against the running portal (system Chrome via Playwright; the Golden Config run and the ping mesh are real, ~6 min):

```bash
webapp/.venv/bin/python webapp/demo/record.py             # --no-runs starts nothing on the lab
```
