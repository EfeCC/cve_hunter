#!/usr/bin/env bash
# Lokal WP'ye karsi otomatik dinamik tarama (nuclei) + yardimci ipuclari.
# Onkosul: docker compose up -d ; hedef eklenti kurulu (install-plugin.sh).
# Kali'de: nuclei, ffuf, sqlmap kurulu olmali.
set -euo pipefail
TARGET="${1:-http://localhost:8080}"
OUT="${2:-../reports}"
mkdir -p "$OUT"

echo "[*] Hedef: $TARGET"

if command -v nuclei >/dev/null 2>&1; then
  echo "[*] nuclei (wordpress + expsoures + misconfig)..."
  nuclei -u "$TARGET" -tags wordpress,wp-plugin,exposure,misconfig \
    -o "$OUT/nuclei-$(date +%Y%m%d-%H%M%S).txt" -silent || true
else
  echo "[!] nuclei yok (Kali: apt install nuclei / go install). Atlaniyor."
fi

cat <<TIP

[i] Belirli bir bulgu icin AI-uretimli PoC:
    python ../dast.py --id <bulgu_id> --target "$TARGET" --run

[i] Elle fuzzing ornekleri (Kali):
    ffuf  -u "$TARGET/wp-admin/admin-ajax.php?action=FUZZ" -w actions.txt
    sqlmap -u "$TARGET/wp-admin/admin-ajax.php?action=X&id=1" --batch --level=2
TIP
