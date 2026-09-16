# verify/ - Lokal Dogrulama Harness'i

Triyajda `real`/`likely` cikan bulgulari **kendi localinde** kurup PoC ile
dogrulamak icin. Sadece izole/lokal test icindir; canli hicbir siteye test yapma.

## Kullanim

```bash
cd verify
docker compose up -d               # WP + MariaDB + wp-cli ayaga kalkar
./install-plugin.sh <plugin-slug>  # hedef eklentiyi kur+aktiflestir, test user ac
```

- WordPress: http://localhost:8080 (admin / admin123)
- Subscriber test kullanicisi: subtest / subpass123
- Belirli (zafiyetli) surum icin: `./install-plugin.sh <slug> 1.2.3`
- Yerel zip'ten: `./install-plugin.sh <slug> --zip ../plugins/<slug>.zip`

## PoC dogrulama (ornek)

- Unauth AJAX:   `curl 'http://localhost:8080/wp-admin/admin-ajax.php?action=<action>&param=<payload>'`
- REST endpoint: `curl 'http://localhost:8080/wp-json/<ns>/<route>?...'`
- Reflected XSS: yaniti `<payload>` yansimasi icin kontrol et.
- SQLi:          hata tabanli/boolean/time-based; `SLEEP()` ile gecikme olcumu.

Dogruladiktan sonra: `python ../report.py --id <bulgu_id> --ai`

## Temizlik
```bash
docker compose down -v   # konteynerler + volume'lar silinir
```
