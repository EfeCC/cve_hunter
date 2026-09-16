# WP Eklenti CVE Avcılığı Toolu

WordPress eklentilerinde ölçekli zafiyet avı için bir boru hattı:
**indir → Semgrep (custom kurallar) → AI triyaj → lokal doğrulama → advisory**.

[prjblk/wordpress-audit-automation](https://github.com/prjblk/wordpress-audit-automation)
tabanı üzerine kuruludur; asıl darboğaz olan **false-positive elemesi** için bir
Claude tabanlı triyaj katmanı ve **lokal PoC doğrulama** harness'ı eklenmiştir.

## Neden bu yaklaşım
- WP eklenti ekosistemi = ücretsiz kurulabilir demo + [Patchstack](https://patchstack.com/bug-bounty/)
  & [Wordfence](https://www.wordfence.com/) CNA'ları senin adına CVE veriyor.
- Semgrep binlerce ham bulgu üretir; hacmi işleyebilmek için AI ile `unauth`/`subscriber`
  + yüksek install'lı bulguları öne çıkarıp gürültüyü keseriz.

## Mimari
| Katman | Dosya | İş |
|---|---|---|
| Orkestratör (taban) | `wordpress-plugin-audit.py`, `dbutils.py` | Eklentileri indir, Semgrep koş, MySQL'e yaz |
| Custom kurallar | `rules/wp/*.yaml` | WP'ye özgü sink'ler (SQLi, XSS, LFI, object injection, broken authz) |
| **AI triyaj** | `triage.py` | Her bulguyu Claude ile ele; verdict + auth_context + güven skoru (2 motor: abonelik / API) |
| Doğrulama | `verify/` | Docker WP + wp-cli ile eklentiyi kurup PoC dene |
| Rapor | `report.py` | Patchstack/Wordfence'e submit-hazır advisory taslağı |

## ⚠️ Platform notu (önemli)
**Semgrep Windows'ta native çalışmaz** (OCaml core binary yok — sessizce exit 2 verir).
Tarama adımını **WSL, Linux veya Docker** içinde çalıştır. Sende `kali-linux` WSL
dağıtımı ve Docker mevcut. Triyaj/rapor/verify katmanları Windows'ta da çalışır.

## Triyaj motoru: abonelik mi, API mi?
`triage.py` (ve `report.py --ai`) iki şekilde çalışır:

| Motor | Bayrak | Faturalandırma | Not |
|---|---|---|---|
| **claude-code** (varsayılan) | `--engine claude-code` | **Claude Code aboneliğinin kotası** — ayrı API faturası yok | Yerel `claude -p` CLI'ını kullanır (otomatik bulunur). Abonelik kullanım limitlerine (5 saatlik/haftalık pencere) tabidir. |
| api | `--engine api` | Anthropic API, **token başına ödeme** | `ANTHROPIC_API_KEY` veya `config.ini [anthropic] api_key`. Bulk için limit yok, ölçeklenir. |

Sayı-oyunu / yüksek hacim: önce Semgrep + ön-filtreyle bulgu sayısını kes; kalanı
abonelik motoruyla ele. Abonelik limitine takılırsan `--engine api`'ye geç veya
`--model claude-sonnet-5` ile kota harca (opus yerine).

## Kurulum
```bash
cp config.ini.sample config.ini      # MySQL (API motoru icin ayrica anthropic api_key)
pip install -r requirements.txt      # mysql-connector, tqdm, semgrep, (api icin) anthropic
```

## Kullanım

### 1) İndir + tara (WSL/Linux/Docker)
```bash
python wordpress-plugin-audit.py --download --audit \
  --download-dir . --config ./rules/wp --create-schema
# veya hepsi bir arada:
./run_pipeline.sh
```

### 2) AI triyaj
```bash
python triage.py --plugins-root . --limit 200 --verbose          # abonelik motoru (varsayilan)
python triage.py --engine api --plugins-root . --limit 200       # API motoru (token basina)
python triage.py --report            # oncelik kuyrugu (unauth + yuksek install once)
```

### 3) Lokal doğrulama
```bash
cd verify && docker compose up -d
./install-plugin.sh <plugin-slug>    # veya:  <slug> 1.2.3  |  <slug> --zip yol
# curl/Burp ile PoC'yi dogrula (verify/README.md)
```

### 4) Rapor
```bash
python report.py --id <bulgu_id> --plugins-root . --ai
```

## Testler
```bash
tests/run_rule_tests.sh   # vuln.php tum kurallari tetiklemeli, safe.php temiz olmali
```

## Etik / kapsam
Sadece pasif statik analiz + **kendi localinde** dinamik test. Canlı üçüncü parti
sitelere test yok. Bulgular Patchstack/Wordfence üzerinden sorumlu şekilde açıklanır.

---
Taban: [prjblk/wordpress-audit-automation](https://github.com/prjblk/wordpress-audit-automation) (MIT).
