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

ERISILEBILIRLIK (cross-file) - EN KRITIK ADIM: Bir handler'da cap/nonce GORMEMEK,
korumasiz oldugu ANLAMINA GELMEZ; koruma genelde BASKA dosyadadir. Prompt'ta sana
DOSYAYLA BIRLIKTE bir "PLUGIN GATE HARITASI" verilir (tum dosyalardan cikarilmis
AJAX/REST/admin-menu/nonce kayitlari). auth_context ve confidence'i MUTLAKA bu
haritayla capraz kontrol ederek belirle:
1) Handler bir wp_ajax_ action'ina baglıysa: haritada 'AJAX nopriv' altinda mi
   (UNAUTH) yoksa 'AJAX auth-only' altinda mi (en az giris gerekir)?
2) Handler bir add_(sub)menu_page callback'i ise: haritadaki o satirdaki capability
   argumani (or. 'manage_options') GERCEK gate'tir -> is_admin() yetki kontrolu DEGIL.
3) Handler sadece nonce dogruluyorsa (cap yok): o nonce action'i haritada NEREDE
   uretiliyor? Nonce yalnizca yuksek-yetkili sayfada (manage_options admin sayfasi)
   basiliyorsa dusuk-yetkili kullanici o nonce'u ALAMAZ -> gercek yetki = o sayfanin
   yetkisi. Yani "cap yok" tek basina unauth/subscriber DEMEK DEGILDIR.
4) REST route'ta permission_callback '__return_true' veya yoksa UNAUTH; varsa callback'e gore.
5) Sink escape'siz gorunse bile SOURCE'ta sanitize_text_field/wp_kses/esc_* olabilir;
   ve *_FORCE_*/*_STRICT_* gibi guvenlik sabitleri genelde TRUE default'lanir
   (degisken adindan "default false" varsayma).
Haritada da netlesmeyen durumda: auth_context='unknown', confidence <= 0.5 ver ve
reasoning'de neyin dogrulanmasi gerektigini yaz.

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


# --- plugin geneli GATE HARITASI (cross-file reachability icin) -------------
_AJAX_RE = re.compile(r"""add_action\(\s*['"]wp_ajax_(nopriv_)?([\w\-]+)['"]""")
_ADMINPOST_RE = re.compile(r"""add_action\(\s*['"]admin_post_(nopriv_)?([\w\-]+)['"]""")
_NONCE_RE = re.compile(r"""wp_(?:create_nonce|nonce_field)\(\s*['"]([^'"]+)['"]""")
_SHORTCODE_RE = re.compile(r"""add_shortcode\(\s*['"]([^'"]+)['"]""")


def _rel(php, plugins_root):
    sp = str(php)
    return str(php.relative_to(plugins_root)) if sp.startswith(str(plugins_root)) else sp


def plugin_gate_map(plugin_dir, plugins_root, max_chars=6000, per_section=25):
    """Eklentinin TUM PHP dosyalarindan giris-noktasi + gate kayitlarini cikarir.
    Boylece AI, incelenen dosyadaki bir handler'in gercek yetki seviyesini
    (nopriv? menu capability? nonce nerede uretiliyor?) capraz kontrol edebilir."""
    ajax_nopriv, ajax_auth, rest, adminpost, menu, nonce, shortcode = (
        [], [], [], [], [], [], [])
    for php in Path(plugin_dir).rglob("*.php"):
        try:
            text = php.read_text("utf-8", "replace")
        except Exception:  # noqa: BLE001
            continue
        rel = _rel(php, plugins_root)
        for i, ln in enumerate(text.splitlines(), 1):
            s = ln.strip()
            if not s:
                continue
            m = _AJAX_RE.search(s)
            if m:
                (ajax_nopriv if m.group(1) else ajax_auth).append(f"{rel}:{i}  {s[:160]}")
                continue
            if _ADMINPOST_RE.search(s):
                adminpost.append(f"{rel}:{i}  {s[:160]}")
                continue
            if "register_rest_route" in s or "permission_callback" in s:
                rest.append(f"{rel}:{i}  {s[:160]}")
                continue
            if "add_menu_page" in s or "add_submenu_page" in s:
                menu.append(f"{rel}:{i}  {s[:190]}")
                continue
            if _NONCE_RE.search(s):
                nonce.append(f"{rel}:{i}  {s[:160]}")
                continue
            if _SHORTCODE_RE.search(s):
                shortcode.append(f"{rel}:{i}  {s[:120]}")
    sections = [
        ("AJAX nopriv (UNAUTH erisim)", ajax_nopriv),
        ("AJAX auth-only (en az giris gerekir)", ajax_auth),
        ("REST route / permission_callback (__return_true = UNAUTH)", rest),
        ("admin_post", adminpost),
        ("ADMIN MENU (callback BU capability ile gate'li)", menu),
        ("NONCE URETIM (bu nonce'u ancak bu sayfayi gorebilen kullanici alir)", nonce),
        ("SHORTCODE", shortcode),
    ]
    out = ["=== PLUGIN GATE HARITASI (cross-file, TUM dosyalardan) ==="]
    for title, items in sections:
        if not items:
            continue
        seen = list(dict.fromkeys(items))[:per_section]
        out.append(f"[{title}]")
        out.extend("  " + x for x in seen)
    body = "\n".join(out)
    if len(body) > max_chars:
        body = body[:max_chars] + "\n... [gate haritasi kirpildi] ..."
    return body


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
    parser.add_argument("--gate-chars", type=int, default=6000,
                        help="Plugin gate haritasi icin en fazla karakter")
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
        # Gate haritasi eklenti basina BIR KEZ cikarilir, her dosya prompt'una eklenir.
        gate_map = plugin_gate_map(pdir, args.plugins_root, args.gate_chars)
        for php in candidate_files(pdir, args.max_files):
            rel = str(php.relative_to(args.plugins_root)) if str(php).startswith(
                str(args.plugins_root)) else str(php)
            prompt = (f"Eklenti: {plugin}\nDosya: {rel}\n\n"
                      f"{gate_map}\n\n"
                      f"--- DOSYA ---\n{numbered(php, args.max_chars)}\n--- SON ---\n\n"
                      "Saldiri yuzeyindeki gercek zafiyetleri JSON dizisi olarak dondur. "
                      "auth_context ve confidence'i yukaridaki GATE HARITASIYLA capraz "
                      "kontrol ederek belirle.")
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
