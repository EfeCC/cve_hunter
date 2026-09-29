#!/usr/bin/env python3
"""cve_hunter web paneli.

Mevcut CLI boru hattini (fetch_one/multiscan/discover/triage/report) butonlara
baglayan yerel Flask paneli. Uzun isler arka plan job'u olarak calisir; canli log
poll ile akar. Bulgular DB'den okunur, verdict tek tikla guncellenir, ve
"reachability" yardimcisi giris-noktasi + gate grep'lerini otomatik kosar.

Calistirma (repo kokunden, venv aktifken):
    python web/app.py                 # http://127.0.0.1:5000
GUVENLIK: sadece 127.0.0.1'e baglanir. Komut calistiran bir paneldir; ASLA
disari/0.0.0.0'a acma.
"""
import os
import re
import sys
import json
import shlex
import threading
import subprocess
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

from flask import Flask, request, jsonify, Response, render_template

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import dbutils  # noqa: E402  (repo kokunden import)

app = Flask(__name__, template_folder="templates", static_folder="static")

PYTHON = sys.executable or "python3"
WP_API = "https://api.wordpress.org/plugins/info/1.2/"

# --- arka plan job yonetimi -------------------------------------------------
_jobs = {}
_jobs_lock = threading.Lock()
_job_seq = 0


def _new_job(label, cmd):
    global _job_seq
    with _jobs_lock:
        _job_seq += 1
        jid = _job_seq
        _jobs[jid] = {
            "id": jid, "label": label, "cmd": " ".join(cmd),
            "status": "running", "returncode": None, "log": [],
            "started": datetime.now().strftime("%H:%M:%S"), "finished": None,
        }
    return jid


def _run_job(jid, cmd):
    job = _jobs[jid]
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(ROOT), stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1,
            encoding="utf-8", errors="replace", env=os.environ.copy(),
        )
        for line in proc.stdout:
            job["log"].append(line.rstrip("\n"))
            if len(job["log"]) > 5000:
                job["log"] = job["log"][-4000:]
        proc.wait()
        job["returncode"] = proc.returncode
        job["status"] = "done" if proc.returncode == 0 else "error"
    except Exception as e:  # noqa: BLE001
        job["log"].append(f"[job hata] {e}")
        job["status"] = "error"
        job["returncode"] = -1
    finally:
        job["finished"] = datetime.now().strftime("%H:%M:%S")


def start_job(label, cmd):
    jid = _new_job(label, cmd)
    threading.Thread(target=_run_job, args=(jid, cmd), daemon=True).start()
    return jid


# --- DB yardimcilari --------------------------------------------------------
def db():
    """Her istek icin taze baglanti (mysql baglantilari thread-safe degil)."""
    conn, _ = dbutils.connect_to_db(create_schema=False)
    return conn


def q(sql, params=None, one=False):
    conn = db()
    cur = conn.cursor(dictionary=True)
    cur.execute(sql, params or ())
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return (rows[0] if rows else None) if one else rows


def exec_sql(sql, params=None):
    conn = db()
    cur = conn.cursor()
    cur.execute(sql, params or ())
    conn.commit()
    n = cur.rowcount
    cur.close()
    conn.close()
    return n


# --- sayfalar ---------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# --- eklenti arama (wordpress.org) -----------------------------------------
@app.route("/api/plugins/search")
def plugins_search():
    """wordpress.org plugins API proxy: arama veya browse (popular/new/updated)."""
    search = request.args.get("q", "").strip()
    browse = request.args.get("browse", "popular")
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 24))
    fields = ("active_installs,last_updated,short_description,version,"
              "rating,num_ratings,downloaded")
    params = {
        "action": "query_plugins",
        "request[page]": page,
        "request[per_page]": per_page,
        "request[fields]": fields,
    }
    if search:
        params["request[search]"] = search
    else:
        params["request[browse]"] = browse
    url = WP_API + "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": str(e)}), 502
    out = []
    for p in data.get("plugins", []):
        out.append({
            "slug": p.get("slug"),
            "name": re.sub(r"<[^>]+>", "", p.get("name", "")),
            "version": p.get("version"),
            "active_installs": p.get("active_installs", 0),
            "last_updated": (p.get("last_updated", "") or "")[:10],
            "rating": p.get("rating", 0),
            "downloaded": p.get("downloaded", 0),
            "desc": re.sub(r"<[^>]+>", "", p.get("short_description", ""))[:160],
        })
    return jsonify({"plugins": out, "info": data.get("info", {})})


# --- boru hatti aksiyonlari (arka plan job) --------------------------------
@app.route("/api/download", methods=["POST"])
def api_download():
    d = request.get_json(force=True)
    slug = (d.get("slug") or "").strip()
    if not re.fullmatch(r"[a-z0-9\-]+", slug or ""):
        return jsonify({"error": "gecersiz slug"}), 400
    cmd = [PYTHON, "fetch_one.py", "--slug", slug]
    ver = (d.get("version") or "").strip()
    if re.fullmatch(r"[0-9][0-9.]*", ver or ""):
        cmd += ["--version", ver]
    return jsonify({"job": start_job(f"indir: {slug}", cmd)})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    cmd = [PYTHON, "multiscan.py", "--download-dir", ".", "--config", "./rules/wp"]
    return jsonify({"job": start_job("statik tarama (multiscan)", cmd)})


@app.route("/api/discover", methods=["POST"])
def api_discover():
    d = request.get_json(force=True) or {}
    cmd = [PYTHON, "discover.py", "--plugins-root", ".", "--verbose"]
    lim = str(d.get("limit_plugins", "")).strip()
    if lim.isdigit():
        cmd += ["--limit-plugins", lim]
    return jsonify({"job": start_job("AI kesif (discover)", cmd)})


@app.route("/api/triage", methods=["POST"])
def api_triage():
    d = request.get_json(force=True) or {}
    cmd = [PYTHON, "triage.py", "--plugins-root", ".", "--verbose"]
    lim = str(d.get("limit", "")).strip()
    if lim.isdigit():
        cmd += ["--limit", lim]
    return jsonify({"job": start_job("AI triyaj (triage)", cmd)})


# --- job durumu -------------------------------------------------------------
@app.route("/api/jobs")
def api_jobs():
    with _jobs_lock:
        rows = [{k: v for k, v in j.items() if k != "log"}
                for j in _jobs.values()]
    rows.sort(key=lambda x: x["id"], reverse=True)
    return jsonify(rows[:30])


@app.route("/api/jobs/<int:jid>")
def api_job(jid):
    job = _jobs.get(jid)
    if not job:
        return jsonify({"error": "job yok"}), 404
    since = int(request.args.get("since", 0))
    return jsonify({
        "id": job["id"], "label": job["label"], "status": job["status"],
        "returncode": job["returncode"], "started": job["started"],
        "finished": job["finished"],
        "log": job["log"][since:], "total": len(job["log"]),
    })


# --- indirilmis eklentiler --------------------------------------------------
@app.route("/api/installed")
def api_installed():
    rows = q(
        """
        SELECT d.slug, d.version, d.active_installs,
               COUNT(r.id) AS findings,
               SUM(r.triage_verdict IN ('real','likely')) AS open_q,
               SUM(r.triage_verdict='real') AS real_c,
               SUM(r.triage_verdict='false_positive') AS fp_c
        FROM PluginData d
        LEFT JOIN PluginResults r ON r.slug = d.slug
        GROUP BY d.slug, d.version, d.active_installs
        ORDER BY open_q DESC, findings DESC
        """
    )
    return jsonify(rows)


# --- bulgular (oncelik kuyrugu) --------------------------------------------
@app.route("/api/findings")
def api_findings():
    verdict = request.args.get("verdict", "")   # real,likely / all / ...
    auth = request.args.get("auth", "")          # unauth,subscriber / all
    slug = request.args.get("slug", "")
    where, params = ["1=1"], []
    if verdict and verdict != "all":
        vs = verdict.split(",")
        where.append("r.triage_verdict IN (%s)" % ",".join(["%s"] * len(vs)))
        params += vs
    if auth and auth != "all":
        a = auth.split(",")
        where.append("r.auth_context IN (%s)" % ",".join(["%s"] * len(a)))
        params += a
    if slug:
        where.append("r.slug = %s")
        params.append(slug)
    rows = q(
        f"""
        SELECT r.id, r.slug, r.file_path, r.start_line, r.end_line,
               r.engine, r.check_id, r.triage_verdict, r.confidence,
               r.vuln_class, r.auth_context, r.exploitability, r.triage_notes,
               d.active_installs, d.version
        FROM PluginResults r
        LEFT JOIN PluginData d ON d.slug = r.slug
        WHERE {' AND '.join(where)}
        ORDER BY FIELD(r.auth_context,'unauth','subscriber','unknown','admin'),
                 r.confidence DESC
        LIMIT 500
        """,
        params,
    )
    return jsonify(rows)


@app.route("/api/finding/<int:fid>")
def api_finding(fid):
    row = q("SELECT * FROM PluginResults WHERE id=%s", (fid,), one=True)
    if not row:
        return jsonify({"error": "bulgu yok"}), 404
    # kod baglami (dosya satir +/- 25)
    row["code"] = _read_code(row.get("file_path"), row.get("start_line"))
    return jsonify(row)


@app.route("/api/finding/<int:fid>/verdict", methods=["POST"])
def api_verdict(fid):
    d = request.get_json(force=True)
    verdict = d.get("verdict")
    if verdict not in ("real", "likely", "false_positive"):
        return jsonify({"error": "gecersiz verdict"}), 400
    note = (d.get("note") or "").strip()
    prefix = f"[panel {datetime.now():%Y-%m-%d %H:%M}] " + (note + " " if note else "")
    n = exec_sql(
        "UPDATE PluginResults SET triage_verdict=%s, "
        "triage_notes=CONCAT(%s, IFNULL(triage_notes,'')), triaged_at=NOW() "
        "WHERE id=%s",
        (verdict, prefix, fid),
    )
    return jsonify({"updated": n})


# --- reachability yardimcisi (otomatik grep) -------------------------------
ENTRY_RE = (r"wp_ajax_nopriv_|wp_ajax_|register_rest_route|admin_post_nopriv_|"
            r"admin_post_|add_shortcode|add_menu_page|add_submenu_page")
GATE_RE = (r"current_user_can|check_ajax_referer|check_admin_referer|"
           r"wp_verify_nonce|wp_create_nonce|is_user_logged_in|permission_callback")


@app.route("/api/finding/<int:fid>/reachability")
def api_reach(fid):
    row = q("SELECT slug, file_path, start_line FROM PluginResults WHERE id=%s",
            (fid,), one=True)
    if not row:
        return jsonify({"error": "bulgu yok"}), 404
    slug = row["slug"]
    pdir = ROOT / "plugins" / slug
    if not pdir.is_dir():
        return jsonify({"error": f"eklenti dizini yok: plugins/{slug}"}), 404
    return jsonify({
        "slug": slug,
        "code": _read_code(row.get("file_path"), row.get("start_line")),
        "entrypoints": _grep(pdir, ENTRY_RE),
        "gates": _grep(pdir, GATE_RE),
    })


def _grep(base, pattern, limit=120):
    rx = re.compile(pattern)
    out = []
    for php in base.rglob("*.php"):
        try:
            for i, ln in enumerate(php.read_text("utf-8", "replace").splitlines(), 1):
                if rx.search(ln):
                    rel = php.relative_to(ROOT).as_posix()
                    out.append({"file": rel, "line": i, "text": ln.strip()[:200]})
                    if len(out) >= limit:
                        return out
        except Exception:  # noqa: BLE001
            continue
    return out


def _read_code(file_path, start_line, radius=25):
    if not file_path:
        return None
    p = ROOT / file_path
    if not p.is_file():
        # file_path bazen 'plugins/...' bazen mutlak olabilir; toparla
        alt = ROOT / "plugins" / file_path
        p = alt if alt.is_file() else p
    if not p.is_file():
        return {"error": f"dosya bulunamadi: {file_path}"}
    try:
        lines = p.read_text("utf-8", "replace").splitlines()
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}
    s = max(1, int(start_line or 1) - radius)
    e = min(len(lines), int(start_line or 1) + radius)
    return {
        "path": p.relative_to(ROOT).as_posix() if str(ROOT) in str(p) else str(p),
        "start": s, "focus": int(start_line or 1),
        "lines": [{"n": n, "t": lines[n - 1]} for n in range(s, e + 1)],
    }


if __name__ == "__main__":
    port = int(os.environ.get("CVEH_PORT", "5000"))
    print(f"cve_hunter paneli: http://127.0.0.1:{port}  (sadece localhost)")
    app.run(host="127.0.0.1", port=port, threaded=True, debug=False)
