#!/usr/bin/env python3
"""AI triyaj katmani - fork eklentisi.

Semgrep'in ham bulgularini Claude ile eler: her bulgu icin kod baglamini toplayip
gercek zafiyet mi / false-positive mi, hangi auth seviyesinde erisilebilir onu
belirler ve sonucu MySQL'e yazar. Amac: hacimli tarama ciktisindaki gurultuyu
kesip 'unauth/subscriber' + yuksek install'li bulgulari one cikarmak.

Iki motor:
  --engine claude-code  (varsayilan): yerel `claude -p` CLI'i uzerinden calisir,
      yani Claude Code ABONELIGININ kotasini kullanir - ayri API faturasi cikmaz.
  --engine api: Anthropic API (ANTHROPIC_API_KEY / config.ini), token basina odeme.

Kullanim:
    python triage.py --plugins-root . --limit 200            # claude-code motoru
    python triage.py --engine api --plugins-root . --limit 200
    python triage.py --create-schema     # triyaj kolonlarini ekler
    python triage.py --report            # oncelik kuyrugunu yazdirir
"""
import argparse
import configparser
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from tqdm import tqdm

from dbutils import (
    connect_to_db,
    ensure_triage_schema,
    get_untriaged_results,
    update_triage_result,
    get_prioritized_findings,
)

try:
    from pydantic import BaseModel, Field
    from typing import Literal
except ImportError:
    print("Eksik bagimlilik. Once: pip install -r requirements.txt", file=sys.stderr)
    raise


# --- Claude'dan bekledigimiz yapisal cikti ---------------------------------
class TriageResult(BaseModel):
    verdict: Literal["real", "likely", "false_positive"] = Field(
        description="Gercek/muhtemel zafiyet mi yoksa false-positive mi"
    )
    vuln_class: str = Field(
        description="Zafiyet sinifi: sqli, xss_reflected, xss_stored, csrf, lfi, "
        "rfi, object_injection, idor, broken_access_control, file_upload, ssrf, "
        "open_redirect, none"
    )
    auth_context: Literal["unauth", "subscriber", "admin", "unknown"] = Field(
        description="Tetiklemek icin gereken minimum yetki seviyesi"
    )
    exploitability: Literal["easy", "medium", "hard"] = Field(
        description="Somurulme zorlugu"
    )
    confidence: float = Field(
        ge=0.0, le=1.0, description="0-1 arasi guven skoru"
    )
    reasoning: str = Field(description="Kisa gerekce (1-3 cumle, Turkce)")


SYSTEM_PROMPT = """Sen kidemli bir WordPress eklenti guvenlik denetcisisin ve CVE
avciligi icin Semgrep bulgularini triyaj ediyorsun. Sana bir Semgrep bulgusu,
etrafindaki kod baglami ve ayni dosyadaki yetki/nonce kontrol sinyalleri verilecek.

Gorevin: bunun gercek, raporlanabilir bir zafiyet mi yoksa false-positive mi
oldugunu degerlendirmek. Ozellikle sunlara dikkat et:
- Kullanici girdisi (source) gercekten sink'e ulasiyor mu, yoksa arada
  sanitizasyon/escape/prepare/whitelist var mi?
- Tetikleme icin hangi yetki gerekiyor? wp_ajax_nopriv_, register_rest_route
  permission_callback yoklugu/__return_true, admin_init disi hook = unauth ipucu.
  current_user_can / is_admin / check_ajax_referer + wp_verify_nonce varsa yetki
  yukselir (subscriber/admin) veya CSRF korumasi vardir.
- 'admin' yetki gerektiren, nonce ile korunan ve sanitize edilmis kod genelde
  false_positive veya dusuk oncelik.
- Emin degilsen 'likely' + orta guven ver; asiri iyimser olma.

Sadece verilen kanita dayan; kodda gormedigin sanitizasyonu varsayma.
CIKTI: SADECE tek bir JSON nesnesi dondur, baska hicbir metin/markdown yazma. Sema:
{"verdict":"real|likely|false_positive","vuln_class":"...","auth_context":"unauth|subscriber|admin|unknown","exploitability":"easy|medium|hard","confidence":0.0,"reasoning":"..."}"""


def load_config(path="config.ini"):
    config = configparser.ConfigParser()
    if not os.path.exists(path):
        raise SystemExit(
            f"{path} bulunamadi. config.ini.sample'i kopyalayip doldur."
        )
    config.read(path)
    return config


# ===========================================================================
# Motor 1: Claude Code CLI (`claude -p`) - abonelik kotasini kullanir
# ===========================================================================
DISALLOWED_TOOLS = ["Bash", "Read", "Edit", "Write", "Glob", "Grep",
                    "WebSearch", "WebFetch", "Task", "NotebookEdit"]


def find_claude_bin(explicit=None):
    """Yerel `claude` CLI'ini bulur (PATH, CLAUDE_BIN, VSCode extension cache)."""
    if explicit and os.path.exists(explicit):
        return explicit
    env = os.environ.get("CLAUDE_BIN")
    if env and os.path.exists(env):
        return env
    found = shutil.which("claude") or shutil.which("claude.exe")
    if found:
        return found
    home = os.path.expanduser("~")
    patterns = [
        os.path.join(home, "AppData", "Roaming", "Code", "agent-host",
                     "sdk-cache", "claude", "*", "win32-x64", "node_modules",
                     "@anthropic-ai", "claude-agent-sdk-win32-x64", "claude.exe"),
        os.path.join(home, ".vscode*", "**", "claude.exe"),
    ]
    cands = []
    for p in patterns:
        cands += glob.glob(p, recursive=True)
    if cands:
        cands.sort()
        return cands[-1]
    raise SystemExit(
        "claude CLI bulunamadi. --claude-bin <yol> ver, CLAUDE_BIN ayarla veya "
        "PATH'e ekle. (Alternatif: --engine api)"
    )


def call_claude_code(prompt, system, claude_bin, model=None, timeout=240):
    """`claude -p` headless cagrisi, envelope'un 'result' metnini doner."""
    cmd = [claude_bin, "-p", prompt,
           "--system-prompt", system,
           "--output-format", "json",
           "--max-turns", "1"]
    if model:
        cmd += ["--model", model]
    cmd += ["--disallowedTools", *DISALLOWED_TOOLS]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(
            f"claude -p rc={proc.returncode}: {(proc.stderr or '')[:300]}"
        )
    env = json.loads(proc.stdout)
    if env.get("is_error"):
        raise RuntimeError(f"claude -p is_error: {str(env.get('result'))[:200]}")
    return env.get("result", "")


def extract_json(text):
    """Metinden ilk JSON nesnesini cikarir (kod bloklari/aciklama olsa bile)."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?|\n?```$", "", text).strip()
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError(f"JSON bulunamadi: {text[:200]}")
    return json.loads(m.group(0))


# ===========================================================================
# Motor 2: Anthropic API (token basina odeme)
# ===========================================================================
def make_api_client(config):
    import anthropic
    api_key = ""
    model = "claude-opus-5"
    if config.has_section("anthropic"):
        api_key = config["anthropic"].get("api_key", "").strip()
        model = config["anthropic"].get("model", "claude-opus-5").strip() or "claude-opus-5"
    client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
    return client, model


def triage_one_api(client, model, prompt):
    response = client.messages.parse(
        model=model,
        max_tokens=4000,
        thinking={"type": "adaptive"},
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
        output_format=TriageResult,
    )
    return response.parsed_output


# --- Kod baglami toplama ----------------------------------------------------
GUARD_SIGNALS = [
    "check_ajax_referer", "wp_verify_nonce", "check_admin_referer",
    "current_user_can", "is_user_logged_in", "is_admin", "permission_callback",
    "wp_ajax_nopriv_", "register_rest_route", "sanitize_", "esc_", "wp_kses",
    "$wpdb->prepare",
]


def resolve_file(plugins_root, slug, file_path):
    """Semgrep'in kaydettigi yolu diskteki gercek dosyaya cozer."""
    p = Path(file_path)
    if p.exists():
        return p
    cand = Path(plugins_root) / file_path
    if cand.exists():
        return cand
    base = p.name
    plugin_dir = Path(plugins_root) / "plugins" / slug
    if plugin_dir.exists():
        for match in plugin_dir.rglob(base):
            return match
    return None


def build_context(plugins_root, finding, pad=40):
    slug = finding["slug"]
    fpath = resolve_file(plugins_root, slug, finding["file_path"])
    vuln_lines = finding.get("vuln_lines") or ""
    if not fpath:
        return None, vuln_lines, []
    try:
        lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return str(fpath), vuln_lines, []
    start = max(0, int(finding["start_line"]) - 1 - pad)
    end = min(len(lines), int(finding["end_line"]) + pad)
    snippet = "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, end))
    signals = [s for s in GUARD_SIGNALS if any(s in ln for ln in lines)]
    return snippet, snippet or vuln_lines, signals


def build_prompt(finding, snippet, guard_signals):
    return f"""Semgrep bulgusu triyaji:

Eklenti: {finding['slug']}  (aktif kurulum: {finding.get('active_installs')})
Semgrep kural: {finding['check_id']}
Dosya: {finding['file_path']}  satir {finding['start_line']}-{finding['end_line']}
Dosyada gorulen yetki/nonce/sanitizasyon sinyalleri: {', '.join(guard_signals) or 'YOK'}

--- KOD BAGLAMI ---
{snippet}
--- KOD BAGLAMI SONU ---

Yukaridaki bulguyu degerlendir ve SADECE JSON nesnesi olarak dondur."""


def classify(finding, snippet, guards, engine, ctx):
    """Motora gore tek bulguyu siniflandirir, TriageResult doner."""
    prompt = build_prompt(finding, snippet or "(kod baglami bulunamadi)", guards)
    if engine == "api":
        return triage_one_api(ctx["client"], ctx["model"], prompt)
    raw = call_claude_code(prompt, SYSTEM_PROMPT, ctx["claude_bin"], ctx["model"])
    return TriageResult(**extract_json(raw))


def run_triage(args):
    db_conn, cursor = connect_to_db(create_schema=False)
    ensure_triage_schema(cursor)
    db_conn.commit()

    # Motor kurulumu
    ctx = {}
    if args.engine == "api":
        config = load_config(args.config)
        ctx["client"], ctx["model"] = make_api_client(config)
        if args.model:
            ctx["model"] = args.model
        engine_desc = f"api ({ctx['model']})"
    else:
        ctx["claude_bin"] = find_claude_bin(args.claude_bin)
        ctx["model"] = args.model  # None ise Claude Code varsayilan modeli
        engine_desc = f"claude-code [{Path(ctx['claude_bin']).name}]" + (
            f" ({args.model})" if args.model else " (CC varsayilan model)")

    findings = get_untriaged_results(cursor, limit=args.limit)
    if not findings:
        print("Triyaj edilecek yeni bulgu yok.")
        return
    print(f"{len(findings)} bulgu triyaj edilecek (motor: {engine_desc})")

    stats = {"real": 0, "likely": 0, "false_positive": 0, "error": 0}
    for finding in tqdm(findings, desc="Triyaj"):
        snippet, fallback, guards = build_context(args.plugins_root, finding)
        ctx_text = snippet or fallback
        try:
            result = classify(finding, ctx_text, guards, args.engine, ctx)
        except Exception as e:
            stats["error"] += 1
            if args.verbose:
                print(f"  HATA (id={finding['id']}): {e}", file=sys.stderr)
            continue
        update_triage_result(
            cursor, finding["id"], result.verdict, result.confidence,
            result.vuln_class, result.auth_context, result.exploitability,
            result.reasoning,
        )
        db_conn.commit()
        stats[result.verdict] = stats.get(result.verdict, 0) + 1
        if args.verbose:
            print(f"  id={finding['id']} {finding['slug']}: {result.verdict} "
                  f"({result.vuln_class}/{result.auth_context}, "
                  f"conf={result.confidence:.2f})")

    print("\nTriyaj ozeti:", stats)
    cursor.close()
    db_conn.close()


def run_report(args):
    db_conn, cursor = connect_to_db(create_schema=False)
    rows = get_prioritized_findings(
        cursor,
        min_confidence=args.min_confidence,
        limit=args.limit or 100,
    )
    if not rows:
        print("Oncelik kuyrugunda bulgu yok. Once triyaj calistir.")
        return
    print(f"\n{'=' * 90}\nONCELIK KUYRUGU (dogrulanacak bulgular)\n{'=' * 90}")
    for r in rows:
        print(f"\n[id={r['id']}] {r['slug']} v{r.get('version')} "
              f"(install: {r.get('active_installs')})")
        print(f"  {r['vuln_class']} | {r['auth_context']} | "
              f"{r['exploitability']} | conf={r['confidence']:.2f}")
        print(f"  {r['file_path']} satir {r['start_line']}-{r['end_line']}")
        print(f"  Not: {r['triage_notes']}")
    cursor.close()
    db_conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Semgrep bulgularini Claude ile triyaj eder."
    )
    parser.add_argument("--engine", choices=["claude-code", "api"],
                        default="claude-code",
                        help="claude-code: abonelik kotasi (varsayilan) | api: token basina")
    parser.add_argument("--claude-bin", default=None,
                        help="claude CLI yolu (claude-code motoru; otomatik bulunur)")
    parser.add_argument("--config", default="config.ini")
    parser.add_argument("--plugins-root", default=".",
                        help="Eklentilerin indirildigi dizin (plugins/ ust dizini)")
    parser.add_argument("--limit", type=int, default=None,
                        help="En fazla kac bulgu islensin")
    parser.add_argument("--model", default=None,
                        help="Model override (or. claude-sonnet-5 ile kota tasarrufu)")
    parser.add_argument("--create-schema", action="store_true",
                        help="Sadece triyaj kolonlarini ekle ve cik")
    parser.add_argument("--report", action="store_true",
                        help="Oncelik kuyrugunu yazdir (triyaj yapma)")
    parser.add_argument("--min-confidence", type=float, default=0.5)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    if args.create_schema:
        db_conn, cursor = connect_to_db(create_schema=False)
        ensure_triage_schema(cursor)
        db_conn.commit()
        print("Triyaj semasi hazir.")
        cursor.close()
        db_conn.close()
        return
    if args.report:
        run_report(args)
        return
    run_triage(args)


if __name__ == "__main__":
    main()
