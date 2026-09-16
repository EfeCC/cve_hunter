#!/usr/bin/env bash
# Hedef eklentiyi lokal WP'ye kurar, aktiflestirir ve test kullanicilari acar.
# Kullanim:
#   ./install-plugin.sh <plugin-slug> [surum]
#   ./install-plugin.sh <plugin-slug> --zip /yol/eklenti.zip
# Onkosul: docker compose up -d (WP kurulum sihirbazi tamamlanmis olmali)
set -euo pipefail

SLUG="${1:?kullanim: ./install-plugin.sh <slug> [surum|--zip yol]}"
WP() { docker compose exec -T wpcli wp --allow-root --path=/var/www/html "$@"; }

# WP kurulu degilse otomatik kur (test ortami)
if ! WP core is-installed >/dev/null 2>&1; then
  echo "[*] WordPress kuruluyor (test ortami)..."
  WP core install \
    --url="http://localhost:8080" \
    --title="CVE Test" \
    --admin_user=admin \
    --admin_password=admin123 \
    --admin_email=admin@example.test \
    --skip-email
fi

# Eklentiyi kur
if [[ "${2:-}" == "--zip" ]]; then
  ZIP="${3:?--zip icin dosya yolu gerekli}"
  echo "[*] Zip'ten kuruluyor: $ZIP"
  docker compose cp "$ZIP" wpcli:/tmp/plugin.zip
  WP plugin install /tmp/plugin.zip --force --activate
else
  VER="${2:-}"
  if [[ -n "$VER" ]]; then
    echo "[*] $SLUG (surum $VER) kuruluyor..."
    WP plugin install "$SLUG" --version="$VER" --force --activate
  else
    echo "[*] $SLUG (guncel) kuruluyor..."
    WP plugin install "$SLUG" --force --activate
  fi
fi

# Dusuk yetkili test kullanicisi (subscriber senaryolari icin)
if ! WP user get subtest >/dev/null 2>&1; then
  WP user create subtest sub@example.test --role=subscriber --user_pass=subpass123
fi

echo
echo "[+] Hazir. Aktif eklentiler:"
WP plugin list --status=active
echo
echo "    WP:        http://localhost:8080"
echo "    admin:     admin / admin123"
echo "    subscriber: subtest / subpass123"
echo "    Nonce almak icin (subscriber olarak) tarayicidan giris yapip ilgili sayfadan nonce cek."
