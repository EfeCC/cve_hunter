#!/usr/bin/env bash
# Uctan uca boru hatti (Linux / WSL / Docker ortaminda calistir).
# 1) indir + custom kurallarla Semgrep  2) AI triyaj  3) oncelik kuyrugu
set -euo pipefail
cd "$(dirname "$0")"

DL_DIR="${DL_DIR:-.}"
LIMIT="${LIMIT:-}"

echo "[1/3] Eklentiler indiriliyor + Semgrep (custom kurallar) calistiriliyor..."
python wordpress-plugin-audit.py --download --audit \
  --download-dir "$DL_DIR" --config ./rules/wp --create-schema

echo "[2/3] AI triyaj..."
python triage.py --plugins-root "$DL_DIR" ${LIMIT:+--limit "$LIMIT"}

echo "[3/3] Oncelik kuyrugu:"
python triage.py --report

echo
echo "Sirada: verify/ ile bir bulguyu localde dogrula, sonra:"
echo "  python report.py --id <id> --plugins-root \"$DL_DIR\" --ai"
