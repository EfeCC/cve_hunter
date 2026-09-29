#!/usr/bin/env python3
"""AI-kesif katmani - fork eklentisi.

Semgrep 'nereye bakilacagini' daraltir; bu katman saldiri yuzeyini (AJAX/REST
handler, form isleyici, hook, dosya islemleri) DOGRUDAN Claude'a okutur ve statik
motor hic isaretlemese bile logic bug / auth bypass / IDOR arar. Bulgular
'ai-discovery' motoru olarak, triyaj alanlari dolu sekilde MySQL'e yazilir.

Kullanim:
    python discover.py --plugins-root . --max-files 6 --limit-plugins 50
    python discover.py --engine api ...
"""
import argparse
import json
import re
import sys
from pathlib import Path

from tqdm import tqdm

from dbutils import (
    connect_to_db, ensure_triage_schema, ensure_engine_column, insert_ai_finding,
)
from triage import find_claude_bin, call_claude_code, load_config, make_api_client

# Saldiri yuzeyi imzalari - bu markerlari iceren dosyalar oncelikli
ENTRYPOINT_RE = re.compile(
    r"wp_ajax_|register_rest_route|admin_post_|add_shortcode|add_menu_page|"
    r"add_submenu_page|\$_GET|\$_POST|\$_REQUEST|\$_FILES|\$_COOKIE|"
    r"wp_handle_upload|move_uploaded_file"
)

DISCOVER_SYSTEM = """Sen kidemli bir WordPress eklenti guvenlik denetcisisin. Sana
bir eklentinin bir PHP dosyasi (satir numarali) verilecek. Gorevin: SALDIRI
YUZEYINI (wp_ajax(_nopriv), REST route, admin_post, shortcode, form/$_GET/$_POST
isleyiciler, dosya upload) inceleyip GERCEK, raporlanabilir zafiyetleri bulmak -
Semgrep gibi pattern eslemenin kaciracagi LOGIC hatalari dahil: auth bypass,
IDOR, eksik nonce/capability, guvensiz dosya islemleri, SSRF, mantik hatalari.

Her bulgu icin: gercekten somurulebilir mi ve hangi yetki gerekir (unauth ipucu:
wp_ajax_nopriv_, permission_callback yoklugu/__return_true) degerlendir. Uydurma;
sadece dosyadaki koda dayan. Zayif/teorik seyleri dahil etme.

ERISILEBILIRLIK (cross-file) - EN COK YAPILAN HATA: Bir handler'da cap/nonce
GORMEMEK, korumasiz oldugu ANLAMINA GELMEZ. Koruma cogu zaman BASKA katmanda olur
ve sana verilen dosyada GORUNMEZ:
1) Admin-menu gate: handler bir add_menu_page/add_submenu_page callback'i ise
   yetki o registration'daki capability argumaniyla (or. 'manage_options')
   ZORLANIR; ayrica ortak bir dispatcher/Controller::auth() gate'i olabilir.
2) Nonce kaynagi: bir nonce yalnizca yuksek-yetkili sayfada (or. manage_options
   admin sayfasi) uretiliyorsa, dusuk-yetkili kullanici o nonce'u ALAMAZ ->
   pratikte o yetki seviyesinde gate'lidir. Bir handler sadece nonce kontrol edip
   cap kontrol etmese bile, nonce nerede basiliyorsa gercek yetki seviyesi odur.
3) wp_ajax_ (nopriv YOK) = en az giris yapmis kullanici gerekir.
4) Source-sanitize: 'sink' escape'siz gorunse bile SOURCE'un yakalandigi yerde
   sanitize_text_field/wp_kses/esc_* olabilir -> stored XSS'i source'u gormeden
   yuksek guvenle iddia etme.
5) Guvenlik toggle'lari (or. *_FORCE_*/*_STRICT_* sabitleri) cogunlukla guvenli
   tarafta (true) default'lanir; degisken adindan "default false" varsayma.
Bu gate'ler dosyada GORUNMUYORSA: auth_context'i EMIN olmadan 'unauth'/'subscriber'
VERME -> 'unknown' kullan; confidence <= 0.5 tut; reasoning'de ACIKCA
"erisilebilirlik dogrulanmali: <hangi dosya/registration/nonce kaynagi>" yaz.

CIKTI: SADECE bir JSON DIZISI dondur, baska metin yok. Bos ise []. Her eleman:
{"line":<int>,"vuln_class":"...","auth_context":"unauth|subscriber|admin|unknown",
"exploitability":"easy|medium|hard","verdict":"real|likely",
"confidence":0.0,"title":"...","reasoning":"..."}"""


def extract_json_array(text):
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?|\n?```$", "", text).strip()
    m = re.search(r"\[.*\]", text, re.S)
    if not m:
        return []
    return json.loads(m.group(0))


def numbered(path, max_chars):
    lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    body = "\n".join(f"{i + 1}: {ln}" for i, ln in enumerate(lines))
    if len(body) > max_chars:
        body = body[:max_chars] + "\n... [dosya kirpildi] ..."
    return body


def candidate_files(plugin_dir, max_files):
    scored = []
    for php in Path(plugin_dir).rglob("*.php"):
        try:
            txt = php.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        hits = len(ENTRYPOINT_RE.findall(txt))
        if hits:
            scored.append((hits, php))
    scored.sort(reverse=True)  # en cok saldiri-yuzeyi sinyali olan dosyalar once
    return [p for _, p in scored[:max_files]]


def ask(engine, ctx, prompt):
    if engine == "api":
        resp = ctx["client"].messages.create(
            model=ctx["model"], max_tokens=4000,
            thinking={"type": "adaptive"}, system=DISCOVER_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        return "".join(b.text for b in resp.content if b.type == "text")
    return call_claude_code(prompt, DISCOVER_SYSTEM, ctx["claude_bin"], ctx["model"])


def main():
    parser = argparse.ArgumentParser(description="AI ile saldiri yuzeyi kesfi.")
    parser.add_argument("--engine", choices=["claude-code", "api"], default="claude-code")
    parser.add_argument("--claude-bin", default=None)
    parser.add_argument("--config", default="config.ini")
    parser.add_argument("--plugins-root", default=".")
    parser.add_argument("--max-files", type=int, default=6,
                        help="Eklenti basina en cok kac dosya incelensin")
    parser.add_argument("--max-chars", type=int, default=28000,
                        help="Dosya basina gonderilecek en fazla karakter")
    parser.add_argument("--limit-plugins", type=int, default=None)
    parser.add_argument("--min-confidence", type=float, default=0.5)
    parser.add_argument("--model", default=None)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    ctx = {}
    if args.engine == "api":
        ctx["client"], ctx["model"] = make_api_client(load_config(args.config))
        if args.model:
            ctx["model"] = args.model
    else:
        ctx["claude_bin"] = find_claude_bin(args.claude_bin)
        ctx["model"] = args.model

    db_conn, cursor = connect_to_db(create_schema=False)
    ensure_triage_schema(cursor)
    ensure_engine_column(cursor)
    db_conn.commit()

    plugins_dir = Path(args.plugins_root) / "plugins"
    plugins = sorted(p.name for p in plugins_dir.iterdir() if p.is_dir())
    if args.limit_plugins:
        plugins = plugins[:args.limit_plugins]

    found = 0
    for plugin in tqdm(plugins, desc="AI kesif"):
        pdir = plugins_dir / plugin
        for php in candidate_files(pdir, args.max_files):
            rel = str(php.relative_to(args.plugins_root)) if str(php).startswith(
                str(args.plugins_root)) else str(php)
            prompt = (f"Eklenti: {plugin}\nDosya: {rel}\n\n"
                      f"--- DOSYA ---\n{numbered(php, args.max_chars)}\n--- SON ---\n\n"
                      "Saldiri yuzeyindeki gercek zafiyetleri JSON dizisi olarak dondur.")
            try:
                items = extract_json_array(ask(args.engine, ctx, prompt))
            except Exception as e:
                if args.verbose:
                    print(f"  HATA {plugin}/{php.name}: {e}", file=sys.stderr)
                continue
            for it in items:
                if float(it.get("confidence", 0)) < args.min_confidence:
                    continue
                line = int(it.get("line", 0))
                lines = numbered(php, 2000).splitlines()
                snippet = "\n".join(lines[max(0, line - 4):line + 3])
                insert_ai_finding(
                    cursor, plugin, rel, line, line, snippet,
                    it.get("verdict", "likely"), float(it.get("confidence", 0.5)),
                    it.get("vuln_class", "unknown"),
                    it.get("auth_context", "unknown"),
                    it.get("exploitability", "medium"),
                    f"[AI-kesif] {it.get('title','')}: {it.get('reasoning','')}",
                )
                found += 1
                if args.verbose:
                    print(f"  {plugin} L{line}: {it.get('vuln_class')} "
                          f"({it.get('auth_context')}) conf={it.get('confidence')}")
            db_conn.commit()

    print(f"\nAI-kesif toplam bulgu: {found}")
    cursor.close()
    db_conn.close()


if __name__ == "__main__":
    main()
