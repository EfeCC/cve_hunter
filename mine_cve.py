#!/usr/bin/env python3
"""CVE-mining kural uretici - fork eklentisi.

Bir eklentinin zafiyetli <-> yamali surumleri arasindaki diff, duzeltilen sink'i
gosterir. Bu diff'i Claude'a verip (a) yamalanan zafiyeti ozetletir ve (b) o
patterni yakalayacak yeni bir Semgrep kurali urettiririz. Cikan kural
rules/wp/generated/ altina yazilir; bir sonraki taramada devreye girer.

Kullanim:
    python mine_cve.py --slug some-plugin --old 1.2.3 --new 1.2.4
    python mine_cve.py --slug some-plugin --auto      # son iki surum
"""
import argparse
import re
import sys
from pathlib import Path

import yaml  # PyYAML - kural dogrulamasi icin

from triage import (
    find_claude_bin, call_claude_code, load_config, make_api_client,
)
from wputils import list_versions, fetch_pair, diff_versions, security_relevant_added_lines

MINE_SYSTEM = """Sen bir WordPress guvenlik arastirmacisisin. Sana bir eklentinin
zafiyetli ve yamali surumleri arasindaki PHP diff'i verilecek. Yamanin duzelttigi
guvenlik acigini bul (eklenen sanitize/nonce/capability/prepare = fix ipucu) ve o
zafiyet sinifini yakalayacak GENEL bir Semgrep kurali uret (sadece bu eklentiye
degil, ayni pattern'e sahip diger eklentilere de uysun).

CIKTI: SADECE tek JSON nesnesi dondur:
{"vuln_summary":"...","vuln_class":"...","cwe":"CWE-XX",
 "rule_id":"wp-<kisa-slug>","semgrep_rule":"<gecerli tek-kural Semgrep YAML metni>"}
semgrep_rule alani 'rules:' ile baslayan, tek kural iceren gecerli YAML olmali."""


def extract_json(text):
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?|\n?```$", "", text).strip()
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError(f"JSON yok: {text[:200]}")
    import json
    return json.loads(m.group(0))


def ask(args, prompt):
    if args.engine == "api":
        client, model = make_api_client(load_config(args.config))
        if args.model:
            model = args.model
        resp = client.messages.create(
            model=model, max_tokens=6000, thinking={"type": "adaptive"},
            system=MINE_SYSTEM, messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in resp.content if b.type == "text")
    return call_claude_code(prompt, MINE_SYSTEM,
                            find_claude_bin(args.claude_bin), args.model, timeout=300)


def main():
    parser = argparse.ArgumentParser(description="Diff'ten Semgrep kurali uret.")
    parser.add_argument("--slug", required=True)
    parser.add_argument("--old", default=None)
    parser.add_argument("--new", default=None)
    parser.add_argument("--auto", action="store_true", help="Son iki surumu kullan")
    parser.add_argument("--engine", choices=["claude-code", "api"], default="claude-code")
    parser.add_argument("--claude-bin", default=None)
    parser.add_argument("--config", default="config.ini")
    parser.add_argument("--model", default=None)
    parser.add_argument("--out", default="rules/wp/generated")
    args = parser.parse_args()

    if args.auto or not (args.old and args.new):
        vers = list_versions(args.slug)
        if len(vers) < 2:
            raise SystemExit("Yeterli surum yok.")
        args.old, args.new = vers[-2], vers[-1]
    print(f"Diff: {args.slug} {args.old} -> {args.new}")

    old_dir, new_dir, _ = fetch_pair(args.slug, args.old, args.new)
    diff = diff_versions(old_dir, new_dir)
    if not diff.strip():
        print("PHP diff bos.")
        return
    sig = security_relevant_added_lines(diff)
    print(f"Guvenlik-ilgili eklenen satir sinyali: {len(sig)}")

    prompt = (f"Eklenti: {args.slug}  ({args.old} -> {args.new})\n"
              f"Eklenen guvenlik sinyalleri: {[s for s, _ in sig][:10]}\n\n"
              f"--- PHP DIFF ---\n{diff}\n--- SON ---\n\n"
              "Yamalanan zafiyeti bul ve genel bir Semgrep kurali uret (JSON).")
    data = extract_json(ask(args, prompt))

    print(f"\nZafiyet: {data.get('vuln_class')} - {data.get('vuln_summary')}")
    rule_text = data.get("semgrep_rule", "")
    try:
        yaml.safe_load(rule_text)  # dogrula
    except Exception as e:
        print(f"UYARI: uretilen kural gecerli YAML degil: {e}", file=sys.stderr)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    rid = data.get("rule_id", f"wp-{args.slug}")
    out_path = out_dir / f"{rid}.yaml"
    out_path.write_text(rule_text, encoding="utf-8")
    print(f"Kural yazildi: {out_path}")
    print("Sonraki taramada devreye girer: --config ./rules/wp (generated dahil).")


if __name__ == "__main__":
    main()
