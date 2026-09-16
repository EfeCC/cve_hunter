#!/usr/bin/env python3
"""Cok-motorlu statik tarama - fork eklentisi.

Ayni koda farkli gozler: Semgrep + Psalm(taint) + progpilot. Her motor ciktisini
tek bir normalize sema'ya cevirir: {path, check_id, start, end, lines, engine}.
Kurulu olmayan motor otomatik atlanir (Kali'de: pip/composer ile kur).
"""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def _read_lines(path, start, end, pad=2):
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return ""
    s = max(0, start - 1 - pad)
    e = min(len(lines), end + pad)
    return "\n".join(lines[s:e])


# ---------------------------------------------------------------------------
def available_engines():
    eng = []
    if shutil.which("semgrep"):
        eng.append("semgrep")
    if shutil.which("psalm"):
        eng.append("psalm")
    if shutil.which("progpilot"):
        eng.append("progpilot")
    return eng


# ---------------------------------------------------------------------------
def run_semgrep(plugin_path, config="./rules/wp"):
    out = os.path.join(tempfile.gettempdir(), "sg_out.json")
    cmd = ["semgrep", "scan", "--config", config, "--json", "--no-git-ignore",
           "--quiet", "--output", out, plugin_path]
    subprocess.run(cmd, capture_output=True, text=True)
    findings = []
    try:
        data = json.load(open(out, encoding="utf-8"))
    except Exception:
        return findings
    for r in data.get("results", []):
        findings.append({
            "path": r["path"],
            "check_id": r["check_id"],
            "start": r["start"]["line"],
            "end": r["end"]["line"],
            "lines": r.get("extra", {}).get("lines", ""),
            "engine": "semgrep",
        })
    return findings


# ---------------------------------------------------------------------------
PSALM_XML = """<?xml version="1.0"?>
<psalm errorLevel="8" resolveFromConfigFile="true"
       xmlns="https://getpsalm.org/schema/config" findUnusedBaselineEntry="false">
  <projectFiles>
    <directory name="{dir}" />
  </projectFiles>
</psalm>
"""


def run_psalm(plugin_path):
    """Psalm taint analizi (SARIF). Plugin'e gecici psalm.xml uretir."""
    findings = []
    with tempfile.TemporaryDirectory() as td:
        cfg = os.path.join(td, "psalm.xml")
        sarif = os.path.join(td, "psalm.sarif")
        open(cfg, "w", encoding="utf-8").write(PSALM_XML.format(dir=plugin_path))
        cmd = ["psalm", "--taint-analysis", f"--config={cfg}",
               f"--report={sarif}", "--no-cache", "--no-progress"]
        subprocess.run(cmd, capture_output=True, text=True)
        try:
            data = json.load(open(sarif, encoding="utf-8"))
        except Exception:
            return findings
        for run in data.get("runs", []):
            for res in run.get("results", []):
                rule = res.get("ruleId", "psalm-taint")
                for loc in res.get("locations", []):
                    pl = loc.get("physicalLocation", {})
                    uri = pl.get("artifactLocation", {}).get("uri", "")
                    reg = pl.get("region", {})
                    start = reg.get("startLine", 0)
                    end = reg.get("endLine", start)
                    findings.append({
                        "path": uri,
                        "check_id": f"psalm.{rule}",
                        "start": start,
                        "end": end,
                        "lines": _read_lines(uri, start, end),
                        "engine": "psalm",
                    })
    return findings


# ---------------------------------------------------------------------------
def run_progpilot(plugin_path):
    """progpilot taint analizi (JSON stdout)."""
    findings = []
    proc = subprocess.run(["progpilot", plugin_path],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    try:
        data = json.loads(proc.stdout or "[]")
    except Exception:
        return findings
    for item in data:
        path = item.get("sink_file") or item.get("source_file", "")
        line = int(item.get("sink_line") or item.get("source_line") or 0)
        findings.append({
            "path": path,
            "check_id": f"progpilot.{item.get('vuln_name', 'taint')}",
            "start": line,
            "end": line,
            "lines": _read_lines(path, line, line) if path else "",
            "engine": "progpilot",
        })
    return findings


# ---------------------------------------------------------------------------
def scan_plugin(plugin_path, engines, semgrep_config="./rules/wp"):
    """Verilen motorlarin hepsini bir eklentiye uygular, birlesik liste doner."""
    out = []
    if "semgrep" in engines:
        out += run_semgrep(plugin_path, semgrep_config)
    if "psalm" in engines:
        out += run_psalm(plugin_path)
    if "progpilot" in engines:
        out += run_progpilot(plugin_path)
    return out
