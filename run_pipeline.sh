#!/usr/bin/env bash
# Uctan uca boru hatti (Linux / WSL / Docker ortaminda calistir).
# indir -> cok-motorlu statik tarama -> AI kesif -> AI triyaj -> oncelik kuyrugu
set -euo pipefail
cd "$(dirname "$0")"

DL_DIR="${DL_DIR:-.}"
LIMIT="${LIMIT:-}"

echo "[1/5] Eklentiler indiriliyor..."
python wordpress-plugin-audit.py --download --download-dir "$DL_DIR" --create-schema

echo "[2/5] Cok-motorlu statik tarama (Semgrep + varsa Psalm/progpilot)..."
python multiscan.py --download-dir "$DL_DIR" --config ./rules/wp

echo "[3/5] AI kesif (saldiri yuzeyi - statikten bagimsiz)..."
python discover.py --plugins-root "$DL_DIR" ${LIMIT:+--limit-plugins "$LIMIT"}

echo "[4/5] AI triyaj (statik bulgular)..."
python triage.py --plugins-root "$DL_DIR" ${LIMIT:+--limit "$LIMIT"}

echo "[5/5] Oncelik kuyrugu:"
python triage.py --report

cat <<TIP

Sirada:
  - Dinamik dogrulama:  cd verify && docker compose up -d && ./install-plugin.sh <slug>
                        python dast.py --id <id> --plugins-root "$DL_DIR" --run
  - Yeni kural uret:    python mine_cve.py --slug <slug> --auto
  - N-day tara:         python ndiff.py --slug <slug> --auto --ai
  - Rapor:              python report.py --id <id> --ai
TIP
