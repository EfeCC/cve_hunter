# cve_hunter web paneli

Boru hattını (indir → statik tara → AI keşif → AI triyaj → bulgu inceleme) butonlara
bağlayan yerel panel. Mevcut CLI script'lerini sarmalar; DB'yi (config.ini) okur.

## Çalıştırma (Kali, repo kökünden)
```bash
cd /opt/cve_hunter
source .venv/bin/activate
pip install -r requirements.txt      # flask eklendi
./run_web.sh                         # veya: python web/app.py
```
Tarayıcıda: **http://127.0.0.1:5000**

> ⚠️ Panel komut çalıştırır ve **sadece 127.0.0.1**'e bağlanır. ASLA `0.0.0.0`/dışarı açma.
> Farklı port: `CVEH_PORT=5001 ./run_web.sh`

## Sekmeler
- **Eklentiler** — wordpress.org'da ara/browse, kurulum sayısı + son güncelleme ile
  listele, tek tıkla indir (`fetch_one.py`). Altta indirilmiş eklentiler + bulgu sayacı.
- **Boru Hattı** — ① Statik Tarama (`multiscan`), ② AI Keşif (`discover`),
  ③ AI Triyaj (`triage`) butonları. İşler arka planda job olarak koşar, canlı log akar.
- **Bulgular** — verdict/yetki filtresi, bulgu tablosu. Bir bulguya tıkla → kod bağlamı,
  AI notu, **verdict butonları** (real/likely/false_positive) ve **🔎 Reachability grep**
  (giriş noktası + gate'leri otomatik tarar — manuel triyajı hızlandırır).

## Notlar
- Ön koşullar CLI ile aynı: MariaDB ayakta + `config.ini`, `semgrep`/`claude` PATH'te.
  Paneli **venv aktifken** başlat ki alt script'ler doğru Python + PATH'i kullansın.
- Uzun işler (AI keşif/triyaj) dakikalar sürebilir; job listesinden takip et.
