# Portal demos

## `portal-workflows.mp4` — the executive walkthrough (2½ min)

The moving version of `docs/portal-workflows.pptx`, beat for beat: the same fifteen beats, but against the live portal, so
the forms fill themselves in, the wizard steps forward and a finished job's steps and tests are the real ones.
H.264, 1400×860; `portal-workflows.gif` (960 px) is the same walkthrough for a README.

1. title card — what the service is
2. sign in: the role decides what you may start (viewer / operator / approver, or SSO)
3. the task launcher: "what do you want to do?" — every card with its duration and the role it needs
4. add a branch, step 1: identity, the ACME customer block, the headends it will reach
5. step 2: addressing allocated for you — router-id, LAN, AS, firewall ports, WAN /30s, tunnel numbers, and the capacity left
6. step 3: the whole change in one place, under a change ticket (cancelled — the walkthrough starts nothing)
7. the run: validate → intent → Nautobot → NaC render → Terraform plan → apply → tests, each step saying what it changed
8. a finished job's own page: nine steps, the log, 74/74 tests, who started it and against which ticket
9. add a headend: the same shape of form for the other direction, a tunnel allocated at both ends of every branch
10. change a branch safely: the "which router?" step, then Change IKE authentication (PSK ↔ the lab CA)
11. remove a branch: what will be deleted, listed before anything is — approver only
12. the ledger: every job the portal has run, filterable, with its ticket and Resume
13. Home: tunnels up, headend CPU, firewall bandwidth, free slots; the topology coloured live; headend capacity
14. Compliance: Golden Config's report, Remediate vs Re-apply, the drift history
15. closing card

Re-record it against the running portal (nothing is started on the lab — every dialog is cancelled, ~4 min):

```bash
webapp/.venv/bin/python webapp/demo/record_workflows.py
```

## `portal-demo.mp4` — the full product tour (~3½ min)

`portal-demo.mp4` (H.264, 1400×860) and `portal-demo.gif` (960 px, same scenes) walk through every page of the portal with
on-screen annotations — a numbered caption banner per scene and callouts pointing at the control being shown:

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

`demolib.py` holds what both recorders need — the caption banner, the callouts, the cursor, frame capture and the ffmpeg
encode (the concat demuxer, so each scene's length is decided when it is recorded). `record.py` predates it and carries its
own copies; `record_workflows.py` uses it.
