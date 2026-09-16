#!/usr/bin/env python3
"""Rapor uretici - fork eklentisi.

Dogrulanmis (triyaj + lokal PoC) bir bulgu icin Patchstack / Wordfence'e
submit-hazir bir advisory taslagi uretir. --ai ile Claude tam metni yazar;
--ai olmadan sablonu doldurup birakir (sen PoC'yi elle eklersin).

Kullanim:
    python report.py --id 42 --plugins-root . --ai
    python report.py --id 42            # AI'siz sablon
"""
import argparse
import configparser
import os
import sys
from datetime import date
from pathlib import Path

from dbutils import connect_to_db, get_finding_by_id
from triage import (
    build_context,
    load_config,
    make_api_client,
    find_claude_bin,
    call_claude_code,
)


TEMPLATE = """# Guvenlik Advisory Taslagi

**Eklenti:** {slug}
**Etkilenen surum(ler):** <= {version}
**Zafiyet sinifi:** {vuln_class}
**Gereken yetki:** {auth_context}
**Somurulebilirlik:** {exploitability}
**Aktif kurulum:** {active_installs}
**Tarih:** {today}

## Ozet
{notes}

## Etkilenen kod
Dosya: `{file_path}` (satir {start_line}-{end_line})

```php
{snippet}
```

## Kanit / PoC
<!-- verify/ ile localde dogruladigin adimlari buraya yaz:
     1. Eklentiyi kur/aktiflestir
     2. Istek (curl/Burp) ...
     3. Beklenen sonuc / yansiyan payload -->

## Etki
<!-- SQLi -> veri sizdirma, XSS -> oturum calma, LFI -> dosya okuma vb. -->

## Cozum onerisi
<!-- prepare()/esc_*/nonce/current_user_can eklenmesi -->

## CVSS (taslak)
Vektor: <!-- or. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N -->
"""


AI_SYSTEM = """Sen bir WordPress guvenlik advisory yazarisin. Sana dogrulanmis bir
zafiyet bulgusu ve kod baglami verilecek. Patchstack/Wordfence'e submit edilebilir,
net ve teknik bir advisory yaz (Turkce). Su bolumleri doldur: Ozet, Etkilenen kod
aciklamasi, adim adim PoC iskeleti (gercek payload ornekleriyle), Etki, Cozum
onerisi (somut kod), ve gerekce ile birlikte bir CVSS 3.1 vektoru + skoru.
Uydurma yapma; sadece kod baglamindaki kanita dayan. Emin olmadigin yeri
'DOGRULANMALI' diye isaretle."""


def generate_ai_report(args, finding, snippet):
    prompt = f"""Bulgu:
Eklenti: {finding['slug']} (surum <= {finding.get('version')}, kurulum: {finding.get('active_installs')})
Zafiyet sinifi: {finding.get('vuln_class')}
Gereken yetki: {finding.get('auth_context')}
Dosya: {finding['file_path']} satir {finding['start_line']}-{finding['end_line']}
Triyaj notu: {finding.get('triage_notes')}

--- KOD BAGLAMI ---
{snippet}
--- SON ---

Bu bulgu icin tam bir guvenlik advisory'si yaz (markdown)."""
    if args.engine == "api":
        import anthropic  # noqa: F401
        config = load_config(args.config)
        client, model = make_api_client(config)
        if args.model:
            model = args.model
        resp = client.messages.create(
            model=model,
            max_tokens=8000,
            thinking={"type": "adaptive"},
            system=AI_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in resp.content if b.type == "text")
    # claude-code motoru: abonelik kotasi
    claude_bin = find_claude_bin(args.claude_bin)
    return call_claude_code(prompt, AI_SYSTEM, claude_bin, model=args.model, timeout=300)


def main():
    parser = argparse.ArgumentParser(description="Bulgu icin advisory taslagi uretir.")
    parser.add_argument("--id", type=int, required=True, help="PluginResults.id")
    parser.add_argument("--config", default="config.ini")
    parser.add_argument("--plugins-root", default=".")
    parser.add_argument("--out", default="reports", help="Cikti dizini")
    parser.add_argument("--ai", action="store_true",
                        help="Claude ile tam advisory yaz (aksi halde bos sablon)")
    parser.add_argument("--engine", choices=["claude-code", "api"],
                        default="claude-code",
                        help="claude-code: abonelik kotasi (varsayilan) | api: token basina")
    parser.add_argument("--claude-bin", default=None, help="claude CLI yolu")
    parser.add_argument("--model", default=None, help="Model override")
    args = parser.parse_args()

    db_conn, cursor = connect_to_db(create_schema=False)
    finding = get_finding_by_id(cursor, args.id)
    cursor.close()
    db_conn.close()
    if not finding:
        raise SystemExit(f"id={args.id} bulunamadi.")

    snippet, fallback, _ = build_context(args.plugins_root, finding)
    snippet = snippet or fallback or "(kod baglami bulunamadi)"

    os.makedirs(args.out, exist_ok=True)
    out_path = Path(args.out) / f"{finding['slug']}-{finding['id']}.md"

    if args.ai:
        body = generate_ai_report(args, finding, snippet)
    else:
        body = TEMPLATE.format(
            slug=finding["slug"],
            version=finding.get("version"),
            vuln_class=finding.get("vuln_class"),
            auth_context=finding.get("auth_context"),
            exploitability=finding.get("exploitability"),
            active_installs=finding.get("active_installs"),
            today=date.today().isoformat(),
            notes=finding.get("triage_notes") or "",
            file_path=finding["file_path"],
            start_line=finding["start_line"],
            end_line=finding["end_line"],
            snippet=snippet,
        )

    out_path.write_text(body, encoding="utf-8")
    print(f"Rapor yazildi: {out_path}")


if __name__ == "__main__":
    main()
