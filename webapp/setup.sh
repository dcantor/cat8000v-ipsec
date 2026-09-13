#!/usr/bin/env bash
# Create the web app's virtualenv (python3 -m venv) and install its requirements.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
[[ -d .venv ]] || python3 -m venv .venv
.venv/bin/pip install -q --upgrade pip
.venv/bin/pip install -q -r requirements.txt
echo "webapp venv ready: $(pwd)/.venv"
