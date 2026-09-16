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
Tek statik motora güvenmek yerine **çok katmanlı**: farklı statik motorlar + AI-keşif +
dinamik doğrulama birlikte. AI sadece triyajda değil, keşif/PoC/kural üretiminde de devrede.

| Katman | Dosya | İş |
|---|---|---|
| İndirme (taban) | `wordpress-plugin-audit.py`, `dbutils.py` | Eklentileri indir, MySQL'e yaz |
| **Çok-motorlu statik tarama** | `multiscan.py`, `scanners.py` | Semgrep + Psalm(taint) + progpilot; hepsi tek şemaya normalize, `engine` etiketli |
| Custom kurallar | `rules/wp/*.yaml` (+ `generated/`) | WP'ye özgü sink'ler (SQLi/XSS/LFI/object injection/broken authz) |
| **AI keşif** | `discover.py` | Saldırı yüzeyini (AJAX/REST/hook/form) statikten **bağımsız** Claude'a okutur — logic bug/IDOR/auth bypass |
| **AI triyaj** | `triage.py` | Her bulguyu ele; verdict + auth_context + güven skoru (2 motor: abonelik / API) |
| **Dinamik test (DAST)** | `dast.py`, `verify/dast.sh`, `verify/` | Docker WP + nuclei; AI bulguyu somut HTTP PoC'a çevirip curl/sqlmap ile çalıştırır |
| **CVE-mining** | `mine_cve.py`, `wputils.py` | Zafiyetli↔yamalı diff → AI → yeni Semgrep kuralı |
| **N-day tespiti** | `ndiff.py` | Sessiz güvenlik yamalarını yakalar (eksik fix / hâlâ savunmasız kurulumlar) |
| Rapor | `report.py` | Patchstack/Wordfence submit-hazır advisory taslağı |

### Statik motor notu
- **PHP (WordPress) için:** Semgrep + **Psalm taint** + **progpilot**. Farklı taint motorları farklı şeyler yakalar.
- **CodeQL PHP'yi DESTEKLEMEZ** (C/C++, C#, Go, Java/Kotlin, JS/TS, Python, Ruby, Swift). CodeQL, ileride JS/Python hedeflere genişlerken kullanılacak — WP profilinde yok.
- Motorlar Kali'de kurulur: `pip install semgrep`, `composer global require vimeo/psalm`, progpilot (composer/phar). Kurulu olmayan motor `multiscan.py` tarafından otomatik atlanır.

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

Hepsi bir arada (WSL/Linux/Docker): `./run_pipeline.sh`
Aşağıda adım adım:

### 1) İndir + çok-motorlu tarama
```bash
python wordpress-plugin-audit.py --download --download-dir . --create-schema
python multiscan.py --download-dir . --config ./rules/wp     # Semgrep+Psalm+progpilot
```

### 2) AI keşif (statikten bağımsız, saldırı yüzeyi)
```bash
python discover.py --plugins-root . --limit-plugins 50 --verbose
```

### 3) AI triyaj
```bash
python triage.py --plugins-root . --limit 200 --verbose      # abonelik motoru (varsayilan)
python triage.py --engine api --plugins-root . --limit 200   # API motoru (token basina)
python triage.py --report                                    # oncelik kuyrugu
```

### 4) Dinamik doğrulama (DAST)
```bash
cd verify && docker compose up -d
./install-plugin.sh <plugin-slug>            # <slug> 1.2.3 | <slug> --zip yol
./dast.sh http://localhost:8080              # nuclei taramasi
python ../dast.py --id <id> --plugins-root .. --run   # AI-uretimli PoC (curl/sqlmap)
```

### 5) Kural üretimi + N-day + Rapor
```bash
python mine_cve.py --slug <slug> --auto      # diff -> yeni Semgrep kurali (rules/wp/generated/)
python ndiff.py --slug <slug> --auto --ai    # sessiz guvenlik yamasi / n-day tespiti
python report.py --id <bulgu_id> --ai        # submit-hazir advisory
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
