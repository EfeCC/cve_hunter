#!/usr/bin/env python3
"""N-day / sessiz-yama tespiti - fork eklentisi.

Bir eklentinin ardisik iki surumunu diff'leyip, yamanin sessizce guvenlik duzeltmesi
icerip icermedigini (eklenen nonce/capability/sanitize/prepare) tespit eder. Sessiz
guvenlik yamalari cogu zaman CVE almadan gecer -> (a) eksik/yetersiz fix arayabilir,
(b) sahada hala eski surumu kullanan kurulumlar icin n-day firsatidir.

Kullanim:
    python ndiff.py --slug some-plugin --auto
    python ndiff.py --slug some-plugin --old 1.2.3 --new 1.2.4 --ai
"""
import argparse
import json
import re
import sys

from triage import find_claude_bin, call_claude_code, load_config, make_api_client
from wputils import list_versions, fetch_pair, diff_versions, security_relevant_added_lines

NDIFF_SYSTEM = """Sen bir guvenlik arastirmacisisin. Sana bir eklenti yamasinin PHP
diff'i verilecek. Karar ver: bu yama SESSIZ bir guvenlik duzeltmesi mi (nonce,
capability, sanitize, prepare, escape eklenmis)? Eklenen korumanin duzelttigi
zafiyet sinifi ne? Fix EKSIK/atlatilabilir gorunuyor mu?

CIKTI: SADECE JSON:
{"is_security_fix":true/false,"vuln_class":"...","auth_context":"unauth|subscriber|admin|unknown",
"fix_complete":true/false,"reasoning":"...","confidence":0.0}"""


def extract_json(text):
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?|\n?```$", "", text).strip()
    m = re.search(r"\{.*\}", text, re.S)
    return json.loads(m.group(0)) if m else {}


def ai_confirm(args, slug, old, new, diff, sig):
    prompt = (f"Eklenti: {slug} ({old} -> {new})\n"
              f"Eklenen guvenlik sinyalleri: {[s for s, _ in sig][:12]}\n\n"
              f"--- PHP DIFF ---\n{diff}\n--- SON ---")
    if args.engine == "api":
        client, model = make_api_client(load_config(args.config))
        if args.model:
            model = args.model
        resp = client.messages.create(
            model=model, max_tokens=3000, thinking={"type": "adaptive"},
            system=NDIFF_SYSTEM, messages=[{"role": "user", "content": prompt}],
        )
        raw = "".join(b.text for b in resp.content if b.type == "text")
    else:
        raw = call_claude_code(prompt, NDIFF_SYSTEM,
                               find_claude_bin(args.claude_bin), args.model, timeout=240)
    return extract_json(raw)


def main():
    parser = argparse.ArgumentParser(description="Sessiz guvenlik yamasi / n-day tespiti.")
    parser.add_argument("--slug", required=True)
    parser.add_argument("--old", default=None)
    parser.add_argument("--new", default=None)
    parser.add_argument("--auto", action="store_true")
    parser.add_argument("--ai", action="store_true", help="AI ile teyit et + sinifla")
    parser.add_argument("--engine", choices=["claude-code", "api"], default="claude-code")
    parser.add_argument("--claude-bin", default=None)
    parser.add_argument("--config", default="config.ini")
    parser.add_argument("--model", default=None)
    args = parser.parse_args()

    if args.auto or not (args.old and args.new):
        vers = list_versions(args.slug)
        if len(vers) < 2:
            raise SystemExit("Yeterli surum yok.")
        args.old, args.new = vers[-2], vers[-1]

    old_dir, new_dir, _ = fetch_pair(args.slug, args.old, args.new)
    diff = diff_versions(old_dir, new_dir)
    sig = security_relevant_added_lines(diff)

    print(f"\n{args.slug}: {args.old} -> {args.new}")
    print(f"Guvenlik-ilgili eklenen satir: {len(sig)}")
    for s, line in sig[:15]:
        print(f"  +[{s}] {line}")

    if not sig:
        print("=> Sessiz guvenlik yamasi sinyali YOK.")
    else:
        print("=> OLASI sessiz guvenlik yamasi. Eski surum n-day adayi.")

    if args.ai and sig:
        verdict = ai_confirm(args, args.slug, args.old, args.new, diff, sig)
        print("\nAI degerlendirmesi:")
        print(f"  guvenlik_yamasi={verdict.get('is_security_fix')} "
              f"sinif={verdict.get('vuln_class')} "
              f"yetki={verdict.get('auth_context')} "
              f"fix_tam={verdict.get('fix_complete')} "
              f"conf={verdict.get('confidence')}")
        print(f"  {verdict.get('reasoning','')}")
        if verdict.get("is_security_fix") and verdict.get("fix_complete") is False:
            print("  !! Fix EKSIK gorunuyor - yeni CVE potansiyeli, incele.")


if __name__ == "__main__":
    main()
