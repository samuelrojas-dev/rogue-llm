"""Generate a visual HTML security report from scan results.

The report is self-contained (no external dependencies) and designed to be
shared: it shows the security score, per-profile results, and leaked secrets
in a clean, dark-themed dashboard.
"""

import html
import json
from datetime import datetime, timezone


def render_html_report(data: dict) -> str:
    """Render scan results as a self-contained HTML page."""
    score = data["score"]
    grade = data["grade"]
    verdict = data["verdict"]
    profiles = data["profiles"]

    # Score color
    if score >= 90:
        score_color = "#22c55e"  # green
    elif score >= 70:
        score_color = "#eab308"  # yellow
    elif score >= 50:
        score_color = "#f97316"  # orange
    else:
        score_color = "#ef4444"  # red

    # Build profile rows
    profile_rows = ""
    for p in profiles:
        v = p["verdict"]
        icon = "✓" if v == "STRUCTURAL" else "✗"
        row_class = "pass" if v == "STRUCTURAL" else "fail"
        leaked_pct = (
            int(100 * p["leaked"] / p["total_secrets"]) if p["total_secrets"] else 0
        )
        bar_color = "#22c55e" if leaked_pct == 0 else "#ef4444"

        leak_details = ""
        if p["leaks"]:
            for lk in p["leaks"]:
                leak_details += (
                    f'<div class="leak-item">'
                    f'<span class="leak-secret">{html.escape(str(lk["secret"]))}</span>'
                    f'<span class="leak-technique">via {html.escape(str(lk["technique"]))}</span>'
                    f'</div>'
                )

        profile_rows += f"""
        <div class="profile-card {row_class}">
            <div class="profile-header">
                <span class="profile-icon">{icon}</span>
                <span class="profile-name">{html.escape(p["profile"])}</span>
                <span class="profile-verdict {row_class}">{v}</span>
            </div>
            <div class="profile-bar-container">
                <div class="profile-bar" style="width:{100-leaked_pct}%;background:{bar_color}"></div>
            </div>
            <div class="profile-stats">
                <span>Blocked: {p["total_secrets"]-p["leaked"]}/{p["total_secrets"]} secrets</span>
                <span>{p["interactions"]} interactions</span>
            </div>
            {f'<div class="leak-list">{leak_details}</div>' if leak_details else ''}
        </div>"""

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rogue-llm Security Report</title>
<style>
:root {{
    --bg: #0f172a;
    --surface: #1e293b;
    --surface2: #334155;
    --text: #f1f5f9;
    --text-dim: #94a3b8;
    --accent: {score_color};
    --pass: #22c55e;
    --fail: #ef4444;
    --border: #475569;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 2rem;
    max-width: 900px;
    margin: 0 auto;
}}
.header {{
    text-align: center;
    margin-bottom: 2.5rem;
    padding-bottom: 2rem;
    border-bottom: 1px solid var(--border);
}}
.logo {{ font-size: 1rem; color: var(--text-dim); letter-spacing: .1em; text-transform: uppercase; }}
.score-circle {{
    width: 160px; height: 160px;
    border-radius: 50%;
    border: 6px solid var(--accent);
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    margin: 1.5rem auto;
    background: var(--surface);
}}
.score-number {{ font-size: 3rem; font-weight: 700; color: var(--accent); line-height:1; }}
.score-label {{ font-size: .85rem; color: var(--text-dim); }}
.grade {{ font-size: 1.2rem; font-weight: 600; margin-top: .5rem; }}
.verdict {{
    display: inline-block;
    padding: .4rem 1.2rem;
    border-radius: 999px;
    font-weight: 600;
    font-size: .9rem;
    margin-top: .75rem;
}}
.verdict.STRUCTURAL {{ background: rgba(34,197,94,.15); color: var(--pass); border: 1px solid var(--pass); }}
.verdict.BEHAVIORAL {{ background: rgba(239,68,68,.15); color: var(--fail); border: 1px solid var(--fail); }}
.section-title {{
    font-size: 1.1rem;
    font-weight: 600;
    margin-bottom: 1rem;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: .05em;
}}
.profile-card {{
    background: var(--surface);
    border-radius: 12px;
    padding: 1.25rem;
    margin-bottom: .75rem;
    border-left: 4px solid var(--border);
}}
.profile-card.pass {{ border-left-color: var(--pass); }}
.profile-card.fail {{ border-left-color: var(--fail); }}
.profile-header {{
    display: flex;
    align-items: center;
    gap: .75rem;
    margin-bottom: .75rem;
}}
.profile-icon {{ font-size: 1.2rem; }}
.profile-card.pass .profile-icon {{ color: var(--pass); }}
.profile-card.fail .profile-icon {{ color: var(--fail); }}
.profile-name {{
    font-weight: 600;
    flex: 1;
    font-family: 'SF Mono', 'Fira Code', monospace;
}}
.profile-verdict {{
    font-size: .8rem;
    padding: .15rem .6rem;
    border-radius: 999px;
    font-weight: 600;
}}
.profile-verdict.pass {{ background: rgba(34,197,94,.15); color: var(--pass); }}
.profile-verdict.fail {{ background: rgba(239,68,68,.15); color: var(--fail); }}
.profile-bar-container {{
    height: 6px;
    background: var(--surface2);
    border-radius: 3px;
    overflow: hidden;
    margin-bottom: .5rem;
}}
.profile-bar {{
    height: 100%;
    border-radius: 3px;
    transition: width .3s;
}}
.profile-stats {{
    display: flex;
    justify-content: space-between;
    font-size: .8rem;
    color: var(--text-dim);
}}
.leak-list {{
    margin-top: .75rem;
    padding-top: .75rem;
    border-top: 1px solid var(--surface2);
}}
.leak-item {{
    display: flex;
    gap: .5rem;
    padding: .25rem 0;
    font-size: .8rem;
}}
.leak-secret {{ color: var(--fail); font-family: monospace; }}
.leak-technique {{ color: var(--text-dim); }}
.footer {{
    text-align: center;
    margin-top: 2rem;
    padding-top: 1.5rem;
    border-top: 1px solid var(--border);
    color: var(--text-dim);
    font-size: .8rem;
}}
.footer a {{ color: var(--accent); text-decoration: none; }}
.json-block {{
    background: var(--surface);
    border-radius: 8px;
    padding: 1rem;
    margin-top: 1.5rem;
    font-family: monospace;
    font-size: .75rem;
    color: var(--text-dim);
    overflow-x: auto;
    white-space: pre;
}}
</style>
</head>
<body>

<div class="header">
    <div class="logo">rogue-llm security report</div>
    <div class="score-circle">
        <div class="score-number">{score}</div>
        <div class="score-label">/ 100</div>
    </div>
    <div class="grade">Grade: {grade}</div>
    <div class="verdict {verdict}">{verdict}</div>
</div>

<div class="section-title">Attack Profile Results</div>
{profile_rows}

<div class="footer">
    Generated by <a href="https://github.com/samuelrojas-dev/rogue-llm">rogue-llm</a> on {timestamp}<br>
    Structural security testing — the model is the adversary
</div>

<details style="margin-top:1.5rem">
<summary style="cursor:pointer;color:var(--text-dim);font-size:.85rem">Raw JSON data</summary>
<div class="json-block">{html.escape(json.dumps(data, indent=2, ensure_ascii=False))}</div>
</details>

</body>
</html>"""
