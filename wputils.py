#!/usr/bin/env python3
"""Ortak WP yardimcilari: belirli surumu indir, ac, iki surumu diff'le.
mine_cve.py (kural uretimi) ve ndiff.py (n-day tespiti) kullanir."""
import io
import os
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path

import requests

WP_DL = "https://downloads.wordpress.org/plugin/{slug}.{version}.zip"
WP_INFO = "https://api.wordpress.org/plugins/info/1.0/{slug}.json"

# "Sessiz guvenlik yamasi" sinyalleri: bir yama bunlari EKLIYORSA muhtemelen fix
SECURITY_ADDED = [
    "wp_verify_nonce", "check_admin_referer", "check_ajax_referer",
    "current_user_can", "sanitize_text_field", "sanitize_", "esc_html",
    "esc_attr", "esc_url", "esc_sql", "wp_kses", "absint", "intval",
    "$wpdb->prepare", "wp_unslash", "is_user_logged_in",
]


def plugin_info(slug):
    """WP.org'dan eklenti meta (surum listesi dahil)."""
    r = requests.get(WP_INFO.format(slug=slug), timeout=30)
    r.raise_for_status()
    return r.json()


def list_versions(slug):
    info = plugin_info(slug)
    versions = list((info.get("versions") or {}).keys())
    # 'trunk' vb. ayikla, sundum sirala (kaba)
    versions = [v for v in versions if re.match(r"^\d", v)]
    versions.sort(key=lambda s: [int(x) for x in re.findall(r"\d+", s)] or [0])
    return versions


def download_version(slug, version, dest_dir):
    """slug/version zip'ini indirip dest_dir/<slug> altina acar, yolu doner."""
    url = WP_DL.format(slug=slug, version=version)
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    out = Path(dest_dir) / f"{slug}-{version}"
    if out.exists():
        return out
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        z.extractall(dest_dir)
    # zip genelde <slug>/ olarak acilir; standardize et
    extracted = Path(dest_dir) / slug
    if extracted.exists() and not out.exists():
        extracted.rename(out)
    return out


def diff_versions(old_dir, new_dir, only_php=True, max_chars=60000):
    """Iki dizin arasi unified diff (php'ye kisitli). Buyukse kirpar."""
    cmd = ["diff", "-ruN"]
    if only_php:
        cmd += ["--include=*.php"]
    cmd += [str(old_dir), str(new_dir)]
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    # diff exit 1 = fark var (normal), 2 = hata
    out = proc.stdout or ""
    if len(out) > max_chars:
        out = out[:max_chars] + "\n... [diff kirpildi] ..."
    return out


def security_relevant_added_lines(diff_text):
    """Diff'te EKLENEN (+) satirlardan guvenlik sinyali iceren olanlar."""
    hits = []
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            for sig in SECURITY_ADDED:
                if sig in line:
                    hits.append((sig, line[1:].strip()[:140]))
                    break
    return hits


def fetch_pair(slug, v_old, v_new, workdir=None):
    """Iki surumu indirip (old_dir, new_dir) doner."""
    workdir = workdir or tempfile.mkdtemp(prefix=f"wpdiff-{slug}-")
    old_dir = download_version(slug, v_old, workdir)
    new_dir = download_version(slug, v_new, workdir)
    return old_dir, new_dir, workdir
