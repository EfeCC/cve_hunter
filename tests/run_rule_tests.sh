#!/usr/bin/env bash
# Custom Semgrep kurallarinin TP/FP dogrulamasi.
# vuln.php -> tum kurallar tetiklenmeli; safe.php -> hicbir sey tetiklenmemeli.
# Linux/WSL'de: semgrep kurulu olmali.  Windows'ta: Docker image kullan (asagi).
set -euo pipefail
cd "$(dirname "$0")/.."

if command -v semgrep >/dev/null 2>&1; then
  RUN=(semgrep scan)
else
  echo "[i] semgrep yok, Docker image kullaniliyor"
  RUN=(docker run --rm -v "$(pwd):/src" -w /src semgrep/semgrep semgrep scan)
fi

OUT=$(mktemp)
"${RUN[@]}" --config rules/wp tests/fixtures --json --no-git-ignore --quiet > "$OUT" 2>/dev/null || true

python3 - "$OUT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
res = d.get("results", [])
vuln = {r["check_id"].split(".")[-1] for r in res if "vuln.php" in r["path"].replace("\\","/")}
safe = [r for r in res if "safe.php" in r["path"].replace("\\","/")]
expected = {
    "wp-wpdb-sqli","wp-reflected-xss","wp-lfi-path-traversal",
    "wp-php-object-injection","wp-rest-route-missing-permission-callback",
    "wp-rest-route-public-permission-callback","wp-ajax-nopriv-handler",
}
missing = expected - vuln
ok = True
if missing:
    print("FAIL: vuln.php'de eksik kurallar:", missing); ok = False
if safe:
    print("FAIL: safe.php'de false-positive:", [r["check_id"].split(".")[-1] for r in safe]); ok = False
if d.get("errors"):
    print("FAIL: parse hatasi:", [e.get("message","")[:60] for e in d["errors"]]); ok = False
print("PASS: tum kurallar TP, safe.php temiz" if ok else "TEST BASARISIZ")
sys.exit(0 if ok else 1)
PY
rm -f "$OUT"
