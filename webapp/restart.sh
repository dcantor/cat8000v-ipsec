#!/usr/bin/env bash
# Restart the portal service only when no run is in progress (a restart would interrupt it).
set -euo pipefail
if curl -sf localhost:8090/api/runs | python3 -c "import sys,json; sys.exit(0 if any(r['status'] in ('running','queued') for r in json.load(sys.stdin)) else 1)"; then
  echo "a run is in progress - not restarting" >&2; exit 1
fi
systemctl --user restart lab-webapp && sleep 3 && curl -sf -o /dev/null localhost:8090/ && echo "portal restarted"
