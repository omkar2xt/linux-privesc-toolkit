"""Builds a single-file, styled HTML report from the findings list."""
import html
from datetime import datetime

COLORS = {
    "CRITICAL": "#7a0d0d",
    "HIGH": "#c0392b",
    "MEDIUM": "#d68910",
    "LOW": "#2e86c1",
    "INFO": "#5d6d7e",
}


def build(findings, counts):
    rows = []
    for f in findings:
        color = COLORS.get(f["severity"], "#333")
        rows.append(f"""
        <div class="finding" style="border-left-color:{color}">
          <div class="badge" style="background:{color}">{html.escape(f['severity'])}</div>
          <h3>{html.escape(f['title'])}</h3>
          <pre>{html.escape(f['evidence'])}</pre>
          <p><strong>Recommendation:</strong> {html.escape(f['recommendation'])}</p>
        </div>""")

    summary_chips = "".join(
        f'<span class="chip" style="background:{COLORS.get(k, "#333")}">{k}: {v}</span>'
        for k, v in counts.items()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Linux Privilege Escalation Scan Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; background:#f4f6f7; color:#1c2833; margin:0; padding:2rem; }}
  h1 {{ margin-bottom:0.2rem; }}
  .meta {{ color:#566573; margin-bottom:1.5rem; }}
  .chips {{ margin-bottom:2rem; }}
  .chip {{ color:white; padding:0.3rem 0.8rem; border-radius:999px; margin-right:0.5rem; font-size:0.85rem; }}
  .finding {{ background:white; border-left:6px solid #333; border-radius:6px; padding:1rem 1.2rem; margin-bottom:1rem; box-shadow:0 1px 3px rgba(0,0,0,0.08); }}
  .finding h3 {{ margin:0.2rem 0 0.6rem 0; }}
  .badge {{ display:inline-block; color:white; font-size:0.75rem; font-weight:bold; padding:0.15rem 0.6rem; border-radius:4px; }}
  pre {{ white-space:pre-wrap; background:#f8f9f9; padding:0.6rem; border-radius:4px; font-size:0.85rem; overflow-x:auto; }}
  .disclaimer {{ margin-top:2rem; padding:1rem; background:#fdf2e9; border-radius:6px; font-size:0.9rem; }}
</style>
</head>
<body>
  <h1>Linux Privilege Escalation Scan Report</h1>
  <div class="meta">Generated {datetime.now():%Y-%m-%d %H:%M:%S} &middot; Detection only, no exploitation performed.</div>
  <div class="chips">{summary_chips}</div>
  {"".join(rows)}
  <div class="disclaimer">
    This report lists potential misconfigurations for review. It does not confirm exploitability
    and does not execute any exploit code. Verify each finding manually before making changes on
    a production system.
  </div>
</body>
</html>"""
