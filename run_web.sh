#!/usr/bin/env bash
# cve_hunter web paneli baslatici (repo kokunden, venv aktif olmali).
#   source .venv/bin/activate && ./run_web.sh
# Panel SADECE http://127.0.0.1:5000 (localhost) uzerinde acilir.
set -euo pipefail
cd "$(dirname "$0")"
exec python web/app.py
