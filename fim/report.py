"""
report.py - security report generation (Markdown + HTML).
"""
import html
import platform
from collections import Counter
from datetime import datetime
from pathlib import Path

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def build_report_data(engine) -> dict:
    events = list(reversed(engine.db.list_events()))          # oldest first
    return {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host": platform.node() or "unknown",
        "system": f"{platform.system()} {platform.release()}",
        "watches": engine.watches(),
        "baseline_files": len(engine.db.all_baseline()),
        "last_scan": engine.db.get_meta("last_scan", "never"),
        "events": events,
        "by_type": Counter(e["event_type"] for e in events),
        "by_severity": Counter(e["severity"] for e in events),
        "open": [e for e in events if e["status"] == "open"],
        "approved": [e for e in events if e["status"] == "approved"],
        "reverted": [e for e in events if e["status"] == "reverted"],
    }


def _verdict(data) -> str:
    if any(e["severity"] == "CRITICAL" for e in data["open"]):
        return "CRITICAL - the integrity baseline itself shows signs of tampering. Investigate immediately."
    if data["open"]:
        return f"ATTENTION - {len(data['open'])} unresolved integrity alert(s) need review."
    return "CLEAN - no unresolved integrity alerts."


def to_markdown(data: dict) -> str:
    L = ["# File Integrity Monitoring - Security Report", "",
         f"- **Generated:** {data['generated']}", f"- **Host:** {data['host']} ({data['system']})",
         f"- **Last scan:** {data['last_scan']}", f"- **Files in baseline:** {data['baseline_files']}",
         f"- **Overall status:** {_verdict(data)}", "", "## Monitored locations", ""]
    L += [f"- `{w['path']}` ({'file' if w['kind'] == 'file' else 'folder'})" for w in data["watches"]] or ["- none"]
    L += ["", "## Incident summary", "", "| Metric | Count |", "|---|---|",
          f"| Total incidents recorded | {len(data['events'])} |", f"| Still open | {len(data['open'])} |",
          f"| Approved as legitimate | {len(data['approved'])} |",
          f"| Reverted to baseline | {len(data['reverted'])} |", "",
          "### By type", "", "| Type | Count |", "|---|---|"]
    L += [f"| {t} | {n} |" for t, n in sorted(data["by_type"].items())] or ["| - | 0 |"]
    L += ["", "### By severity", "", "| Severity | Count |", "|---|---|"]
    L += [f"| {s} | {data['by_severity'][s]} |" for s in SEV_ORDER if data["by_severity"][s]] or ["| - | 0 |"]
    L += ["", "## Incident details", "",
          "| # | Time | Type | Severity | Path | Status | Old hash | New hash |", "|---|---|---|---|---|---|---|---|"]
    for e in data["events"]:
        path = f"{e['old_path']} → {e['path']}" if e["old_path"] else e["path"]
        L.append(f"| {e['id']} | {e['timestamp']} | {e['event_type']} | {e['severity']} | `{path}` | "
                 f"{e['status']} | `{(e['old_hash'] or '-')[:12]}` | `{(e['new_hash'] or '-')[:12]}` |")
    if not data["events"]:
        L.append("| - | - | - | - | - | - | - | - |")
    L += ["", "## Recommendations", ""]
    if data["open"]:
        L += ["1. Review every open alert and confirm whether the change was expected.",
              "2. For unexpected changes: restore the file from a trusted backup and investigate how it changed.",
              "3. For expected changes: approve them in the dashboard so the baseline stays accurate."]
    else:
        L += ["1. No action needed. Keep periodic scans enabled.",
              "2. Review the activity log regularly and back up the baseline database."]
    return "\n".join(L) + "\n"


def to_html(data: dict) -> str:
    esc = html.escape
    color = {"CRITICAL": "#b00020", "HIGH": "#d84315", "MEDIUM": "#f9a825", "LOW": "#2e7d32"}
    rows = ""
    for e in data["events"]:
        path = f"{e['old_path']} → {e['path']}" if e["old_path"] else e["path"]
        rows += (f"<tr><td>{e['id']}</td><td>{esc(e['timestamp'])}</td><td>{esc(e['event_type'])}</td>"
                 f"<td style='color:{color.get(e['severity'], '#000')};font-weight:bold'>{esc(e['severity'])}</td>"
                 f"<td><code>{esc(path)}</code></td><td>{esc(e['status'])}</td></tr>")
    watches = "".join(f"<li><code>{esc(w['path'])}</code></li>" for w in data["watches"]) or "<li>none</li>"
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>FIM Security Report</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:2rem auto;max-width:1000px;color:#222}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:6px 8px;text-align:left;font-size:14px}}
th{{background:#263238;color:#fff}}.box{{background:#eceff1;padding:1rem;border-radius:6px}}</style></head><body>
<h1>File Integrity Monitoring - Security Report</h1>
<div class="box"><p><b>Generated:</b> {esc(data['generated'])} &nbsp; <b>Host:</b> {esc(data['host'])} ({esc(data['system'])})</p>
<p><b>Last scan:</b> {esc(data['last_scan'])} &nbsp; <b>Files in baseline:</b> {data['baseline_files']}</p>
<p><b>Overall status:</b> {esc(_verdict(data))}</p></div>
<h2>Monitored locations</h2><ul>{watches}</ul>
<h2>Summary</h2><p>Total incidents: <b>{len(data['events'])}</b> | Open: <b>{len(data['open'])}</b> |
Approved: <b>{len(data['approved'])}</b> | Reverted: <b>{len(data['reverted'])}</b></p>
<h2>Incident details</h2><table><tr><th>#</th><th>Time</th><th>Type</th><th>Severity</th><th>Path</th><th>Status</th></tr>
{rows or "<tr><td colspan=6>No incidents recorded.</td></tr>"}</table></body></html>"""


def generate_report(engine) -> dict:
    """Write report files and return their paths plus the Markdown text."""
    data = build_report_data(engine)
    engine.report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    md_path = engine.report_dir / f"fim_report_{stamp}.md"
    html_path = engine.report_dir / f"fim_report_{stamp}.html"
    markdown = to_markdown(data)
    md_path.write_text(markdown, encoding="utf-8")
    html_path.write_text(to_html(data), encoding="utf-8")
    return {"markdown_path": md_path, "html_path": html_path, "markdown": markdown,
            "html": html_path.read_text(encoding="utf-8")}
