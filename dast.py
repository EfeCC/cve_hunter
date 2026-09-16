#!/usr/bin/env python3
"""Dinamik test (DAST) koprusu - fork eklentisi.

Statik bulgu kod satiridir; onu somut bir HTTP istegine cevirmek gerekir. Bu modul
bulgunun kod baglamini Claude'a verip lokal WP'ye (verify/ harness) atilacak
concrete bir PoC istegi (metod/yol/parametre/payload + curl veya sqlmap komutu)
urettirir; --run ile calistirip kaniti reports/ altina yazar.

Onkosul: verify/ ayakta (docker compose up -d) ve hedef eklenti kurulu.

Kullanim:
    python dast.py --id 42 --plugins-root .            # PoC plani uret (calistirma)
    python dast.py --id 42 --plugins-root . --run      # curl/sqlmap'i calistir
"""
import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from dbutils import connect_to_db, get_finding_by_id
from triage import build_context, find_claude_bin, call_claude_code, load_config, make_api_client

DAST_SYSTEM = """Sen bir sizma testcisisin. Sana bir WordPress zafiyet bulgusunun kod
baglami ve lokal hedef URL verilecek. Bu zafiyeti lokal ortamda tetikleyecek SOMUT
bir HTTP PoC istegi uret. WP endpoint'leri: AJAX -> /wp-admin/admin-ajax.php?action=<action>,
REST -> /wp-json/<ns>/<route>. action/route/parametre adlarini KODDAN cikar.

CIKTI: SADECE JSON:
{"method":"GET|POST","url_path":"/...","params":{"k":"v"},"payload_param":"<param>",
"payload":"<ornek payload>","tool":"curl|sqlmap","command":"<tam calistirilabilir komut>",
"expected_evidence":"<beklenen kanit: yansiyan payload / SQL hatasi / SLEEP gecikmesi>",
"notes":"..."}
command alani {TARGET} yer tutucusunu kullanabilir (hedef URL ile degistirilir)."""


def extract_json(text):
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?|\n?```$", "", text).strip()
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError(f"JSON yok: {text[:200]}")
    return json.loads(m.group(0))


def ask(args, prompt):
    if args.engine == "api":
        client, model = make_api_client(load_config(args.config))
        if args.model:
            model = args.model
        resp = client.messages.create(
            model=model, max_tokens=3000, thinking={"type": "adaptive"},
            system=DAST_SYSTEM, messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in resp.content if b.type == "text")
    return call_claude_code(prompt, DAST_SYSTEM,
                            find_claude_bin(args.claude_bin), args.model, timeout=240)


def main():
    parser = argparse.ArgumentParser(description="Bulgu -> HTTP PoC (DAST koprusu).")
    parser.add_argument("--id", type=int, required=True)
    parser.add_argument("--target", default="http://localhost:8080")
    parser.add_argument("--plugins-root", default=".")
    parser.add_argument("--engine", choices=["claude-code", "api"], default="claude-code")
    parser.add_argument("--claude-bin", default=None)
    parser.add_argument("--config", default="config.ini")
    parser.add_argument("--model", default=None)
    parser.add_argument("--run", action="store_true", help="Uretilen komutu calistir")
    parser.add_argument("--out", default="reports")
    args = parser.parse_args()

    db_conn, cursor = connect_to_db(create_schema=False)
    finding = get_finding_by_id(cursor, args.id)
    cursor.close()
    db_conn.close()
    if not finding:
        raise SystemExit(f"id={args.id} bulunamadi.")

    snippet, fallback, _ = build_context(args.plugins_root, finding)
    ctx = snippet or fallback or "(baglam yok)"
    prompt = (f"Zafiyet: {finding.get('vuln_class')} / yetki={finding.get('auth_context')}\n"
              f"Eklenti: {finding['slug']}  Dosya: {finding['file_path']}\n"
              f"Hedef: {args.target}\nTriyaj notu: {finding.get('triage_notes')}\n\n"
              f"--- KOD ---\n{ctx}\n--- SON ---\n\nSomut PoC istegi uret (JSON).")
    plan = extract_json(ask(args, prompt))

    print(json.dumps(plan, indent=2, ensure_ascii=False))
    command = (plan.get("command") or "").replace("{TARGET}", args.target)

    if not command:
        print("Komut uretilemedi.")
        return

    if not args.run:
        print(f"\n[calistirmak icin --run ekle]\nKOMUT: {command}")
        return

    os.makedirs(args.out, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    log = Path(args.out) / f"dast-{finding['slug']}-{args.id}-{ts}.log"
    print(f"\n[calistiriliyor] {command}")
    try:
        proc = subprocess.run(command, shell=True, capture_output=True, text=True,
                              timeout=300, encoding="utf-8", errors="replace")
        output = (proc.stdout or "") + "\n--- STDERR ---\n" + (proc.stderr or "")
    except subprocess.TimeoutExpired:
        output = "(zaman asimi)"
    log.write_text(f"KOMUT: {command}\nBEKLENEN: {plan.get('expected_evidence')}\n\n"
                   f"{output}", encoding="utf-8")
    print(f"Kanit yazildi: {log}")
    print(f"Beklenen: {plan.get('expected_evidence')}")


if __name__ == "__main__":
    main()
