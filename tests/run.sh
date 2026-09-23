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
