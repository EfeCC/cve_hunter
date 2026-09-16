#!/usr/bin/env python3
"""Tek eklenti getir - fork eklentisi.

Toplu indirme yerine TEK bir eklentiyi (istege bagli belirli surum) plugins/
altina indirir, semayi kurar ve PluginData satirini ekler. Ardindan multiscan/
discover/triage dogrudan bu eklenti uzerinde calisir.

Kullanim:
    python fetch_one.py --slug loco-translate                 # guncel surum
    python fetch_one.py --slug loco-translate --version 2.6.1 # belirli surum
"""
import argparse
import io
import os
import zipfile
from pathlib import Path

import requests

from dbutils import (
    connect_to_db, ensure_triage_schema, ensure_engine_column, upsert_plugin_basic,
)
from wputils import plugin_info

WP_DL = "https://downloads.wordpress.org/plugin/{slug}.{version}.zip"
WP_DL_LATEST = "https://downloads.wordpress.org/plugin/{slug}.zip"


def main():
    ap = argparse.ArgumentParser(description="Tek eklentiyi indir + semayi kur.")
    ap.add_argument("--slug", required=True)
    ap.add_argument("--version", default=None, help="Bos ise guncel surum")
    ap.add_argument("--download-dir", default=".")
    args = ap.parse_args()

    # Meta (install sayisi + surum) - bulunamazsa devam
    active = 0
    version = args.version
    try:
        info = plugin_info(args.slug)
        active = int(info.get("active_installs", 0) or 0)
        version = version or info.get("version", "latest")
    except Exception:
        version = version or "latest"

    url = (WP_DL.format(slug=args.slug, version=args.version)
           if args.version else WP_DL_LATEST.format(slug=args.slug))
    print(f"Indiriliyor: {url}")
    r = requests.get(url, timeout=60)
    r.raise_for_status()

    plugins_dir = Path(args.download_dir) / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        z.extractall(plugins_dir)          # zip icinde <slug>/ -> plugins/<slug>/
    print(f"Acildi: {plugins_dir / args.slug}")

    # Sema + PluginData
    db_conn, cursor = connect_to_db(create_schema=True)
    ensure_triage_schema(cursor)
    ensure_engine_column(cursor)
    upsert_plugin_basic(cursor, args.slug, version, active, url)
    db_conn.commit()
    cursor.close()
    db_conn.close()
    print(f"Hazir. slug={args.slug} version={version} active_installs={active}")
    print("Sirada:  python multiscan.py --download-dir .  &&  "
          "python discover.py --plugins-root .  &&  python triage.py --plugins-root .")


if __name__ == "__main__":
    main()
