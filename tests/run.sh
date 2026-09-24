#!/usr/bin/env bash
# Run the Robot Framework test suite against the lab.
#   tests/run.sh [robot options...]      e.g.  tests/run.sh --exclude internet
# Every run gets its own folder named by date and time: results/YYYY-MM-DD_HH-MM-SS/
#   configs/pre-run/    running + startup config of each router before the tests
#   configs/post-run/   the same, captured again after the tests (the backup of record)
#   configs/pre-vs-post.diff   what the run changed on the switches (empty = nothing)
#   log.html, report.html, output.xml   Robot Framework results
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")"
[[ -x .venv/bin/robot ]] || { echo "error: run tests/setup.sh first" >&2; exit 1; }

# Runs execute one at a time (one Terraform state, one intent): a suite started while the portal is mid-run fails every test
# that needs the run queue. Wait for the queue to drain — unless these tests *are* the portal's test step (PORTAL_RUN_ID), or
# the caller says not to (QUEUE_WAIT=0).
wait_for_queue() {
  local wait_s="${QUEUE_WAIT:-1800}" said=""
  [[ "$wait_s" == "0" ]] && return 0
  local deadline=$(( SECONDS + wait_s ))
  while :; do
    busy="$(.venv/bin/python queue_state.py 2>/dev/null)" || return 0
    [[ -z "$busy" ]] && { [[ -n "$said" ]] && echo "==> the run queue is free"; return 0; }
    if (( SECONDS >= deadline )); then
      echo "error: the portal is still running $busy" >&2
      echo "       these tests need the run queue; start them when it is free, or set QUEUE_WAIT=0 to run anyway" >&2
      exit 3
    fi
    [[ -z "$said" ]] && { echo "==> waiting for the portal's run queue: $busy"; said=1; }
    sleep 15
  done
}
wait_for_queue

ts="$(date +%Y-%m-%d_%H-%M-%S)"
out="$(cd .. && pwd)/results/$ts"
mkdir -p "$out/configs"
echo "==> results: $out"

echo "==> capturing router configurations (pre-run)"
.venv/bin/python capture_configs.py "$out/configs/pre-run" || echo "warning: config capture failed" >&2

echo "==> running Robot Framework suites"
.venv/bin/robot --outputdir "$out" --name "c8000v ipsec vti lab" --loglevel INFO "$@" suites/
rc=$?

echo "==> capturing router configurations (post-run backup)"
.venv/bin/python capture_configs.py "$out/configs/post-run" || echo "warning: config capture failed" >&2
# diff ignoring the capture-timestamp header line
diff -ru -I '^! .* captured ' "$out/configs/pre-run" "$out/configs/post-run" > "$out/configs/pre-vs-post.diff" \
  && echo "    no configuration changes during the run" \
  || echo "    configuration changed during the run, see configs/pre-vs-post.diff"

echo "==> evidence report"
"$(cd .. && pwd)/webapp/.venv/bin/python" report_pdf.py "$out" || echo "warning: could not build the PDF report (needs webapp/.venv: playwright)" >&2

ln -sfn "$(basename "$out")" ../results/latest
echo "==> report: $out/report.html  (rc=$rc)"
exit $rc
