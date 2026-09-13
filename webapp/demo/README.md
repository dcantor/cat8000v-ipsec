# Portal demo

`portal-demo.gif` (animated, ~90 s) and `portal-demo.webm` (video) walk through the VPN provisioning portal:
the intent form, the add-spoke wizard (headend selection, auto-suggested addressing, hub/spoke review), a
live dry-run of the pipeline with the streaming status panel, the inventory page (KPIs, topology map,
headend capacity, per-tunnel live report, CSV export) and the remove-spoke dialog.

Re-record against the running portal (uses the system Chrome via Playwright; the dry run takes a few minutes):

```bash
webapp/.venv/bin/playwright install ffmpeg      # once
webapp/.venv/bin/python webapp/demo/record.py   # add --fast to skip the dry run
```
