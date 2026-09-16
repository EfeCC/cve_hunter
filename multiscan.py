#!/usr/bin/env python3
"""Cok-motorlu tarama orkestratoru - fork eklentisi.

plugins/ altindaki her eklentiyi kurulu tum statik motorlarla (Semgrep+Psalm+
progpilot) tarar ve normalize bulgulari 'engine' etiketiyle MySQL'e yazar.
Boylece tek motora bagli kalmayiz; triyaj hepsini ayni sekilde eler.

Kullanim:
    python multiscan.py --download-dir . --config ./rules/wp
    python multiscan.py --download-dir . --engines semgrep psalm
"""
import argparse
import os

from tqdm import tqdm

from dbutils import connect_to_db, ensure_triage_schema, ensure_engine_column, insert_finding
from scanners import available_engines, scan_plugin


def main():
    parser = argparse.ArgumentParser(description="Cok-motorlu statik tarama.")
    parser.add_argument("--download-dir", default=".")
    parser.add_argument("--config", default="./rules/wp",
                        help="Semgrep kural yolu/registry")
    parser.add_argument("--engines", nargs="*", default=None,
                        help="Kullanilacak motorlar (varsayilan: kurulu olanlar)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    engines = args.engines or available_engines()
    if not engines:
        raise SystemExit("Hicbir statik motor bulunamadi (semgrep/psalm/progpilot).")
    print(f"Aktif motorlar: {', '.join(engines)}")

    db_conn, cursor = connect_to_db(create_schema=False)
    ensure_triage_schema(cursor)
    ensure_engine_column(cursor)
    db_conn.commit()

    plugins_dir = os.path.join(args.download_dir, "plugins")
    plugins = sorted(os.listdir(plugins_dir))
    total = {e: 0 for e in engines}

    for plugin in tqdm(plugins, desc="Cok-motor tarama"):
        ppath = os.path.join(plugins_dir, plugin)
        try:
            findings = scan_plugin(ppath, engines, args.config)
        except Exception as e:
            if args.verbose:
                print(f"  HATA {plugin}: {e}")
            continue
        for f in findings:
            insert_finding(cursor, plugin, f["path"], f["check_id"],
                           f["start"], f["end"], f["lines"], f["engine"])
            total[f["engine"]] = total.get(f["engine"], 0) + 1
        db_conn.commit()
        if args.verbose and findings:
            print(f"  {plugin}: {len(findings)} bulgu")

    print("\nMotor basina bulgu:", total)
    cursor.close()
    db_conn.close()


if __name__ == "__main__":
    main()
