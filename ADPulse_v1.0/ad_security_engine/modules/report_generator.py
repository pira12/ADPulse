"""
report_generator.py
--------------------
ADPulse - Open Source AD Security Assessment Engine
Generates professional HTML and PDF reports. Fully generic, no vendor branding.
Output is saved to disk for manual sharing — no email dependency.

ADPulse Brand Colors:
  Primary Blue : #0053A4
  Orange Accent: #FF8800
  Light Blue   : #e1f4fd
  Dark Text    : #0a1628
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── ADPulse Brand ────────────────────────────────────────────────────────────
CS_BLUE        = "#0053A4"
CS_ORANGE      = "#FF8800"
CS_LIGHT_BLUE  = "#e1f4fd"
CS_DARK        = "#0a1628"
CS_MID         = "#1a3a6b"

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SEVERITY_HEX = {
    "CRITICAL": "#c0152a",
    "HIGH":     "#d9500a",
    "MEDIUM":   "#b07d00",
    "LOW":      "#1a7a3f",
    "INFO":     CS_BLUE,
}

SEVERITY_LIGHT = {
    "CRITICAL": "#fff0f1",
    "HIGH":     "#fff5ee",
    "MEDIUM":   "#fffaeb",
    "LOW":      "#f0faf4",
    "INFO":     CS_LIGHT_BLUE,
}

SEVERITY_ICON = {
    "CRITICAL": "\u26d4",
    "HIGH":     "\U0001f534",
    "MEDIUM":   "\U0001f7e1",
    "LOW":      "\U0001f7e2",
    "INFO":     "\U0001f535",
}

# Inline SVG wordmark (ADPulse, no external dependency)
ADPULSE_LOGO_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 300 58' height='48'>"
    "<defs><clipPath id='sc'><path d='M 29 4 L 54 13 L 54 32 Q 54 48 29 56 Q 4 48 4 32 L 4 13 Z'/></clipPath></defs>"
    "<path d='M 29 4 L 54 13 L 54 32 Q 54 48 29 56 Q 4 48 4 32 L 4 13 Z' fill='#0053A4'/>"
    "<path d='M 29 9 L 49 17 L 49 32 Q 49 44 29 51 Q 9 44 9 32 L 9 17 Z' fill='none' stroke='rgba(255,255,255,0.15)' stroke-width='1'/>"
    "<polyline points='9,31 17,31 20,38 22,31 25,14 28,48 31,31 41,31 44,24 47,31 49,31' fill='none' stroke='white' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round' clip-path='url(#sc)'/>"
    "<circle cx='25' cy='14' r='2.5' fill='#FF8800' clip-path='url(#sc)'/>"
    "<text x='64' y='40' font-family='Arial Black,Arial,sans-serif' font-weight='900' font-size='34' fill='white' letter-spacing='-0.5'>AD</text>"
    "<text x='112' y='40' font-family='Arial Black,Arial,sans-serif' font-weight='900' font-size='34' fill='#FF8800' letter-spacing='-0.5'>Pulse</text>"
    "<rect x='112' y='44' width='145' height='2.5' rx='1.25' fill='#FF8800' opacity='0.4'/>"
    "</svg>"
)


# =============================================================================
#  HTML Report
# =============================================================================

class HTMLReportGenerator:

    def generate(self, findings, run_id, output_path, company_name="Your Organisation",
                 domain_info=None, scan_stats=None, suppressed=None):
        html = self._build(findings, run_id, company_name, domain_info,
                           suppressed=suppressed or [])
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")
        logger.info(f"HTML report -> {output_path}")
        return str(path)

    def _build(self, findings, run_id, company_name, domain_info, suppressed=None):
        now = datetime.now().strftime("%d %B %Y, %H:%M")
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

        risk_score = min(
            counts["CRITICAL"] * 40 + counts["HIGH"] * 15 +
            counts["MEDIUM"] * 5 + counts["LOW"] * 1, 100
        )
        if   risk_score >= 70: risk_label, risk_col = "CRITICAL", SEVERITY_HEX["CRITICAL"]
        elif risk_score >= 40: risk_label, risk_col = "HIGH",     SEVERITY_HEX["HIGH"]
        elif risk_score >= 20: risk_label, risk_col = "MEDIUM",   SEVERITY_HEX["MEDIUM"]
        else:                  risk_label, risk_col = "LOW",      SEVERITY_HEX["LOW"]

        # Stat cards — clickable to filter by severity
        stat_cards = ""
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            col  = SEVERITY_HEX[sev]
            icon = SEVERITY_ICON[sev]
            stat_cards += f"""
            <div class="stat-card" data-sev-filter="{sev}" onclick="toggleSevFilter('{sev}')"
                 style="border-top:4px solid {col}; cursor:pointer;" title="Click to filter {sev} findings">
                <div class="stat-icon">{icon}</div>
                <div class="stat-num" style="color:{col};">{counts[sev]}</div>
                <div class="stat-lbl">{sev}</div>
            </div>"""

        # Collect unique categories for the category filter
        categories = sorted(set(f.get("category", "") for f in findings))

        # Findings — collapsible cards with data attributes for filtering
        findings_html = ""
        for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity","INFO"), 99)):
            sev   = f.get("severity", "INFO")
            col   = SEVERITY_HEX.get(sev, "#666")
            light = SEVERITY_LIGHT.get(sev, "#fafafa")
            icon  = SEVERITY_ICON.get(sev, "-")
            is_new = f.get("is_new", 1)
            fid   = f.get("finding_id", "")
            cat   = f.get("category", "")

            affected  = f.get("affected", [])
            tags_html = "".join(
                f'<span class="atag" title="{a}">{a}</span>'
                for a in affected[:25]
            )
            if len(affected) > 25:
                tags_html += f'<span class="atag atag-more" onclick="this.parentElement.parentElement.querySelector(\'.tags-overflow\').style.display=\'flex\';this.style.display=\'none\';">+{len(affected)-25} more (click to show)</span>'
                tags_html += '<div class="tags tags-overflow" style="display:none;">'
                tags_html += "".join(f'<span class="atag" title="{a}">{a}</span>' for a in affected[25:])
                tags_html += '</div>'

            rem        = f.get("remediation", "").replace("\n", "<br>")
            new_badge  = '<span class="new-badge">NEW</span>' if is_new else '<span class="rec-badge">RECURRING</span>'
            policy_badge = ""
            policy_status = f.get("policy_status", "")
            if policy_status == "in_remediation":
                policy_reason = f.get("policy_reason", "")
                _reason_attr = policy_reason.replace('"', '&quot;')
                policy_badge = (
                    f'<span class="policy-badge remediation-badge" '
                    f'title="In remediation: {_reason_attr}">&#128295; IN REMEDIATION</span>'
                )
            first_seen = (f.get("first_seen") or "")[:10] or "This scan"
            new_val    = "new" if is_new else "recurring"

            findings_html += f"""
            <div class="finding-card" id="{fid}" data-severity="{sev}" data-category="{cat}"
                 data-newstatus="{new_val}" data-findingid="{fid}">
              <div class="finding-top" style="background:{col};" onclick="toggleCard(this.parentElement)" title="Click to expand/collapse">
                <div class="finding-top-left">
                  <span class="sev-badge">{icon} {sev}</span>
                  <span class="cat-label">{cat}</span>
                </div>
                <div style="display:flex;align-items:center;gap:8px;">
                  {new_badge}
                  {policy_badge}
                  <span class="finding-title-preview">{f.get('title','')}</span>
                  <span class="chevron">&#9660;</span>
                </div>
              </div>
              <div class="finding-body" style="border-left:4px solid {col};background:{light};">
                <h3 class="finding-title">{f.get('title','')}</h3>
                {f'<p class="policy-note"><em>&#128295; In remediation: {f.get("policy_reason","")}'
                 f'{(" &mdash; expires " + f["policy_expires"]) if f.get("policy_expires") else ""}'
                 f'</em></p>' if f.get("policy_status") == "in_remediation" else ''}
                <p class="finding-desc">{f.get('description','')}</p>
                {"<div class='affected-block'><strong>Affected objects (" + str(len(affected)) + "):</strong><div class='tags'>" + tags_html + "</div></div>" if affected else ""}
                <div class="rem-block" onclick="event.stopPropagation();">
                  <div class="rem-label">Remediation</div>
                  <p class="rem-text">{rem}</p>
                </div>
                <div class="finding-foot">
                  Finding ID: <code>{fid}</code> &nbsp;&middot;&nbsp; First seen: {first_seen} &nbsp;&middot;&nbsp; {new_badge}
                  <a class="permalink" href="#{fid}" title="Permalink to this finding">&#128279; link</a>
                </div>
              </div>
            </div>"""

        domain_html = ""
        if domain_info:
            domain_html = f"""
            <div class="meta-row">
              <div class="meta-item"><span class="meta-k">Domain</span>
                <span class="meta-v">{domain_info.get('name') or domain_info.get('base_dn','--')}</span></div>
              <div class="meta-item"><span class="meta-k">Server</span>
                <span class="meta-v">{domain_info.get('server','--')}</span></div>
              <div class="meta-item"><span class="meta-k">Scan ID</span>
                <span class="meta-v"><code style="font-size:11px;">{run_id[:32]}...</code></span></div>
              <div class="meta-item"><span class="meta-k">Generated</span>
                <span class="meta-v">{now}</span></div>
            </div>"""

        new_count = sum(1 for f in findings if f.get("is_new", 1))

        # Category filter options
        cat_options = '<option value="ALL">All Categories</option>'
        for cat in categories:
            cat_options += f'<option value="{cat}">{cat}</option>'

        # Build audit trail for suppressed findings
        suppressed = suppressed or []
        audit_trail_html = ""
        if suppressed:
            rows = ""
            for f in suppressed:
                status = f.get("policy_status", "")
                reason = f.get("policy_reason", "")
                exp    = f.get("policy_expires") or "—"
                by     = f.get("policy_set_by") or "—"
                sev    = f.get("severity", "INFO")
                col    = SEVERITY_HEX.get(sev, "#666")
                rows += f"""
                <tr>
                  <td><code style="font-size:11px;">{f.get('finding_id','')}</code></td>
                  <td style="color:{col};font-weight:700;">{sev}</td>
                  <td>{f.get('title','')}</td>
                  <td><span class="policy-status-tag">{status.replace('_',' ').upper()}</span></td>
                  <td>{reason}</td>
                  <td>{by}</td>
                  <td>{exp}</td>
                </tr>"""
            audit_trail_html = f"""
            <div class="section-header" style="margin-top:40px;">
              <h2>Policy Audit Trail</h2>
              <span class="count-badge">{len(suppressed)} suppressed</span>
            </div>
            <div style="background:white;border-radius:10px;padding:20px;
                        box-shadow:0 2px 8px rgba(0,83,164,0.07);overflow-x:auto;margin-bottom:24px;">
              <p style="font-size:13px;color:#8a99b0;margin-bottom:12px;">
                These findings are suppressed by policy. Nothing is hidden from this report —
                all decisions are logged here for audit purposes.
              </p>
              <table style="width:100%;border-collapse:collapse;font-size:12px;">
                <thead>
                  <tr style="background:#f0f4f8;text-transform:uppercase;font-size:10px;
                             letter-spacing:0.5px;color:#8a99b0;">
                    <th style="padding:8px;text-align:left;">Finding ID</th>
                    <th style="padding:8px;text-align:left;">Severity</th>
                    <th style="padding:8px;text-align:left;">Title</th>
                    <th style="padding:8px;text-align:left;">Status</th>
                    <th style="padding:8px;text-align:left;">Reason</th>
                    <th style="padding:8px;text-align:left;">Set By</th>
                    <th style="padding:8px;text-align:left;">Expires</th>
                  </tr>
                </thead>
                <tbody>{rows}</tbody>
              </table>
            </div>"""

        css = f"""
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: 'IBM Plex Sans', 'Segoe UI', Arial, sans-serif;
  background: #f0f4f8; color: {CS_DARK}; min-height: 100vh;
}}
.header {{
  background: linear-gradient(135deg, {CS_DARK} 0%, {CS_MID} 60%, {CS_BLUE} 100%);
  position: relative; overflow: hidden;
}}
.header::before {{
  content: ''; position: absolute; inset: 0;
  background: repeating-linear-gradient(-45deg,
    transparent, transparent 40px, rgba(255,255,255,0.02) 40px, rgba(255,255,255,0.02) 80px);
}}
.header-inner {{
  position: relative; max-width: 1200px; margin: 0 auto;
  padding: 28px 40px 24px;
  display: flex; align-items: center; justify-content: space-between; gap: 24px;
}}
.header-text h1 {{
  font-size: 12px; font-weight: 700; color: rgba(255,255,255,0.5);
  letter-spacing: 3px; text-transform: uppercase; margin-bottom: 6px;
}}
.header-text h2 {{ font-size: 24px; font-weight: 700; color: white; margin-bottom: 3px; }}
.header-text p   {{ font-size: 12px; color: rgba(255,255,255,0.45); }}
.risk-pill {{
  background: {risk_col}; color: white;
  font-size: 12px; font-weight: 700; padding: 8px 18px;
  border-radius: 40px; white-space: nowrap; flex-shrink: 0;
}}
.orange-bar {{ height: 4px; background: linear-gradient(90deg, {CS_ORANGE} 0%, {CS_BLUE} 100%); }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 28px 40px; }}
.stats-row {{
  display: grid; grid-template-columns: repeat(5,1fr); gap: 14px; margin-bottom: 24px;
}}
.stat-card {{
  background: white; border-radius: 10px; padding: 18px 14px 14px;
  text-align: center; box-shadow: 0 2px 8px rgba(0,83,164,0.07);
  transition: transform 0.15s, box-shadow 0.15s, opacity 0.2s;
}}
.stat-card:hover {{ transform: translateY(-2px); box-shadow: 0 4px 16px rgba(0,83,164,0.15); }}
.stat-card.active {{ box-shadow: 0 0 0 3px {CS_ORANGE}, 0 4px 16px rgba(0,83,164,0.15); }}
.stat-card.dimmed {{ opacity: 0.4; }}
.stat-icon {{ font-size: 20px; margin-bottom: 6px; }}
.stat-num  {{ font-size: 34px; font-weight: 800; line-height: 1; margin-bottom: 4px; }}
.stat-lbl  {{
  font-size: 9px; font-weight: 700; letter-spacing: 1.5px;
  text-transform: uppercase; color: #8a99b0;
}}
.risk-box {{
  background: white; border-radius: 10px; padding: 16px 22px;
  display: flex; align-items: center; gap: 20px; margin-bottom: 24px;
  box-shadow: 0 2px 8px rgba(0,83,164,0.07);
}}
.risk-score-num {{ font-size: 46px; font-weight: 800; color: {risk_col}; line-height: 1; min-width: 80px; }}
.risk-bar-wrap  {{ flex: 1; }}
.risk-bar-label {{ font-size: 11px; color: #8a99b0; margin-bottom: 6px; font-weight: 600; letter-spacing: 1px; text-transform: uppercase; }}
.risk-bar-bg    {{ background: #e8eef5; border-radius: 4px; height: 10px; overflow: hidden; }}
.risk-bar-fill  {{ height: 100%; border-radius: 4px; background: {risk_col}; width: {risk_score}%; transition: width 0.4s; }}
.risk-label     {{ font-size: 15px; font-weight: 700; color: {risk_col}; }}
.meta-box {{
  background: white; border-radius: 10px; padding: 16px 22px;
  margin-bottom: 24px; box-shadow: 0 2px 8px rgba(0,83,164,0.07);
}}
.meta-row  {{ display: grid; grid-template-columns: repeat(4,1fr); gap: 12px; }}
.meta-item {{ display: flex; flex-direction: column; gap: 2px; }}
.meta-k    {{ font-size: 9px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #8a99b0; }}
.meta-v    {{ font-size: 13px; font-weight: 600; color: {CS_DARK}; }}

/* ── Toolbar ── */
.toolbar {{
  display: flex; align-items: center; gap: 12px; margin-bottom: 16px;
  flex-wrap: wrap;
}}
.search-box {{
  flex: 1; min-width: 200px; padding: 8px 14px; border: 1px solid #d0d8e4;
  border-radius: 8px; font-size: 13px; font-family: inherit;
  background: white; transition: border-color 0.2s;
}}
.search-box:focus {{ outline: none; border-color: {CS_BLUE}; box-shadow: 0 0 0 3px rgba(0,83,164,0.12); }}
.filter-select {{
  padding: 8px 12px; border: 1px solid #d0d8e4; border-radius: 8px;
  font-size: 12px; font-family: inherit; background: white; cursor: pointer;
}}
.filter-select:focus {{ outline: none; border-color: {CS_BLUE}; }}
.btn-reset {{
  padding: 8px 16px; border: none; border-radius: 8px;
  background: {CS_BLUE}; color: white; font-size: 12px; font-weight: 600;
  cursor: pointer; font-family: inherit; transition: background 0.15s;
}}
.btn-reset:hover {{ background: {CS_MID}; }}
.btn-collapse {{
  padding: 8px 16px; border: 1px solid #d0d8e4; border-radius: 8px;
  background: white; color: {CS_DARK}; font-size: 12px; font-weight: 600;
  cursor: pointer; font-family: inherit;
}}
.filter-count {{
  font-size: 12px; color: #8a99b0; font-weight: 600;
}}

.section-header {{ display: flex; align-items: center; gap: 12px; margin-bottom: 14px; }}
.section-header h2 {{ font-size: 17px; font-weight: 700; color: {CS_DARK}; }}
.count-badge {{
  background: {CS_BLUE}; color: white; font-size: 11px;
  font-weight: 700; padding: 2px 10px; border-radius: 12px;
}}
.new-info {{ font-size: 11px; color: {CS_ORANGE}; font-weight: 600; }}

/* ── Finding Cards ── */
.finding-card {{
  background: white; border-radius: 10px; overflow: hidden;
  margin-bottom: 12px; box-shadow: 0 2px 8px rgba(0,83,164,0.07);
  transition: opacity 0.2s, max-height 0.3s;
}}
.finding-card.hidden {{ display: none; }}
.finding-top {{
  display: flex; align-items: center;
  justify-content: space-between; padding: 8px 14px;
  cursor: pointer; user-select: none;
}}
.finding-top:hover {{ filter: brightness(1.08); }}
.finding-top-left {{ display: flex; align-items: center; gap: 10px; }}
.sev-badge {{ color: white; font-size: 11px; font-weight: 700; }}
.cat-label {{
  background: rgba(255,255,255,0.18); color: white;
  font-size: 10px; padding: 2px 8px; border-radius: 8px;
}}
.finding-title-preview {{
  color: rgba(255,255,255,0.85); font-size: 11px; font-weight: 500;
  max-width: 350px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  display: none;
}}
.finding-card.collapsed .finding-title-preview {{ display: inline; }}
.chevron {{
  color: rgba(255,255,255,0.6); font-size: 10px;
  transition: transform 0.2s; display: inline-block;
}}
.finding-card.collapsed .chevron {{ transform: rotate(-90deg); }}
.new-badge {{
  background: {CS_ORANGE}; color: white;
  font-size: 9px; font-weight: 700; padding: 2px 7px; border-radius: 8px;
}}
.rec-badge {{
  background: rgba(255,255,255,0.2); color: white;
  font-size: 9px; padding: 2px 7px; border-radius: 8px;
}}
.finding-body {{
  padding: 14px 18px 12px; border-left-width:4px; border-left-style:solid;
  transition: max-height 0.3s ease, padding 0.2s ease, opacity 0.2s ease;
  overflow: hidden;
}}
.finding-card.collapsed .finding-body {{
  max-height: 0 !important; padding: 0 18px; opacity: 0;
}}
.finding-title   {{ font-size: 14px; font-weight: 700; margin-bottom: 7px; color: {CS_DARK}; }}
.finding-desc    {{ font-size: 13px; color: #3a4a5e; line-height: 1.6; margin-bottom: 10px; }}
.affected-block  {{ margin-bottom: 10px; font-size: 12px; font-weight: 600; color: #4a5a6e; }}
.tags            {{ display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }}
.tags-overflow   {{ flex-wrap: wrap; gap: 4px; margin-top: 4px; }}
.atag {{
  background: #e8eef5; color: {CS_DARK}; padding: 2px 7px;
  border-radius: 4px; font-size: 10px; font-family: 'Courier New', monospace;
  cursor: default; transition: background 0.15s;
}}
.atag:hover {{ background: #d0dcea; }}
.atag-more {{ background: {CS_BLUE}; color: white; cursor: pointer; }}
.atag-more:hover {{ background: {CS_MID}; }}
.rem-block {{
  background: rgba(255,255,255,0.7); border: 1px solid #dde5ef;
  border-radius: 6px; padding: 10px 12px; margin-bottom: 8px;
}}
.rem-label {{
  font-size: 9px; font-weight: 700; text-transform: uppercase;
  letter-spacing: 1.5px; color: {CS_BLUE}; margin-bottom: 5px;
}}
.rem-text {{ font-size: 12px; color: #3a4a5e; line-height: 1.7; }}
.finding-foot {{ font-size: 9px; color: #aab5c5; padding-top: 7px; border-top: 1px solid rgba(0,0,0,0.05); }}
code {{
  font-family: 'Courier New', monospace; background: #edf1f7;
  padding: 1px 5px; border-radius: 3px; font-size: 11px;
}}
.footer {{
  text-align: center; padding: 28px 40px;
  font-size: 10px; color: #a0aabb;
  border-top: 1px solid #dde5ef; margin-top: 12px;
}}
.footer strong {{ color: {CS_BLUE}; }}
.no-findings {{
  background: white; border-radius: 10px; padding: 48px;
  text-align: center; color: #8a99b0;
  box-shadow: 0 2px 8px rgba(0,83,164,0.07);
}}

/* ── Tooltip for affected objects ── */
.atag[title] {{ position: relative; }}

/* ── Dark mode ── */
body.dark {{
  background: #0d1117; color: #c9d1d9;
}}
body.dark .stat-card, body.dark .risk-box, body.dark .meta-box,
body.dark .finding-card, body.dark .card {{ background: #161b22; box-shadow: 0 2px 8px rgba(0,0,0,0.3); }}
body.dark .search-box, body.dark .filter-select {{ background: #21262d; border-color: #30363d; color: #c9d1d9; }}
body.dark .btn-collapse {{ background: #21262d; border-color: #30363d; color: #c9d1d9; }}
body.dark .finding-body {{ background: #161b22 !important; }}
body.dark .rem-block {{ background: #0d1117; border-color: #30363d; }}
body.dark .atag {{ background: #21262d; color: #c9d1d9; }}
body.dark .finding-title, body.dark .section-header h2 {{ color: #e6edf3; }}
body.dark .finding-desc, body.dark .rem-text {{ color: #8b949e; }}
body.dark .stat-lbl, body.dark .meta-k, body.dark .finding-foot {{ color: #484f58; }}
body.dark .footer {{ border-color: #21262d; color: #484f58; }}
body.dark code {{ background: #21262d; color: #c9d1d9; }}
.dark-toggle {{
  padding: 6px 12px; border: 1px solid #d0d8e4; border-radius: 8px;
  background: white; cursor: pointer; font-size: 14px; font-family: inherit;
}}
body.dark .dark-toggle {{ background: #21262d; border-color: #30363d; color: #c9d1d9; }}
.clipboard-btn {{
  padding: 6px 14px; border: 1px solid #d0d8e4; border-radius: 8px;
  background: white; cursor: pointer; font-size: 11px; font-weight: 600;
  font-family: inherit; color: {CS_DARK};
}}
body.dark .clipboard-btn {{ background: #21262d; border-color: #30363d; color: #c9d1d9; }}
.clipboard-btn.copied {{ background: #1a7a3f; color: white; border-color: #1a7a3f; }}

/* ── Permalink anchors ── */
.permalink {{
  color: #8a99b0; text-decoration: none; font-size: 11px; margin-left: 8px; opacity: 0;
  transition: opacity 0.15s;
}}
.finding-card:hover .permalink {{ opacity: 1; }}

/* ── Print styles ── */
@media print {{
  .toolbar, .dark-toggle, .clipboard-btn {{ display: none; }}
  .finding-card.collapsed .finding-body {{ max-height: none !important; padding: 14px 18px 12px; opacity: 1; }}
  .stat-card {{ cursor: default; }}
  body.dark {{ background: white; color: #0a1628; }}
  body.dark .stat-card, body.dark .risk-box, body.dark .meta-box,
  body.dark .finding-card {{ background: white; box-shadow: none; border: 1px solid #ddd; }}
}}

@media (max-width:900px) {{
  .stats-row {{ grid-template-columns: repeat(3,1fr); }}
  .meta-row  {{ grid-template-columns: repeat(2,1fr); }}
  .header-inner {{ flex-direction: column; align-items: flex-start; }}
  .toolbar {{ flex-direction: column; }}
  .search-box {{ min-width: 100%; }}
}}

/* ── Policy badges ── */
.policy-badge {{
  font-size: 9px; font-weight: 700; letter-spacing: 0.8px; text-transform: uppercase;
  padding: 3px 8px; border-radius: 20px; white-space: nowrap;
}}
.remediation-badge {{
  background: #e8f4fd; color: #0053A4; border: 1px solid #b3d9f7;
}}
.policy-note {{
  font-size: 12px; color: #0053A4; background: #e8f4fd;
  border-left: 3px solid #0053A4; padding: 6px 10px;
  border-radius: 0 4px 4px 0; margin-bottom: 10px;
}}
.policy-status-tag {{
  font-size: 10px; font-weight: 700; padding: 2px 6px;
  border-radius: 10px; background: #f0f4f8; color: #0053A4;
}}"""

        js = """
/* ── Interactive Report Logic ── */
var activeSev = null;
var activeCategory = 'ALL';
var activeNewFilter = 'ALL';
var searchQuery = '';
var allCollapsed = false;

function toggleCard(card) {
  card.classList.toggle('collapsed');
}

function toggleSevFilter(sev) {
  var cards = document.querySelectorAll('.stat-card');
  if (activeSev === sev) {
    activeSev = null;
    cards.forEach(function(c) { c.classList.remove('active','dimmed'); });
  } else {
    activeSev = sev;
    cards.forEach(function(c) {
      if (c.getAttribute('data-sev-filter') === sev) {
        c.classList.add('active');
        c.classList.remove('dimmed');
      } else {
        c.classList.remove('active');
        c.classList.add('dimmed');
      }
    });
  }
  applyFilters();
}

function applyFilters() {
  var cards = document.querySelectorAll('.finding-card');
  var visible = 0;
  cards.forEach(function(card) {
    var show = true;
    if (activeSev && card.getAttribute('data-severity') !== activeSev) show = false;
    if (activeCategory !== 'ALL' && card.getAttribute('data-category') !== activeCategory) show = false;
    if (activeNewFilter !== 'ALL' && card.getAttribute('data-newstatus') !== activeNewFilter) show = false;
    if (searchQuery) {
      var text = card.textContent.toLowerCase();
      if (text.indexOf(searchQuery) === -1) show = false;
    }
    if (show) {
      card.classList.remove('hidden');
      visible++;
    } else {
      card.classList.add('hidden');
    }
  });
  var counter = document.getElementById('filter-count');
  var total = cards.length;
  if (counter) {
    if (activeSev || activeCategory !== 'ALL' || activeNewFilter !== 'ALL' || searchQuery) {
      counter.textContent = 'Showing ' + visible + ' of ' + total + ' findings';
    } else {
      counter.textContent = '';
    }
  }
}

function onSearchInput(e) {
  searchQuery = e.target.value.toLowerCase().trim();
  applyFilters();
}

function onCategoryChange(e) {
  activeCategory = e.target.value;
  applyFilters();
}

function onNewFilterChange(e) {
  activeNewFilter = e.target.value;
  applyFilters();
}

function resetFilters() {
  activeSev = null;
  activeCategory = 'ALL';
  activeNewFilter = 'ALL';
  searchQuery = '';
  document.getElementById('search-input').value = '';
  document.getElementById('cat-filter').value = 'ALL';
  document.getElementById('new-filter').value = 'ALL';
  document.querySelectorAll('.stat-card').forEach(function(c) {
    c.classList.remove('active','dimmed');
  });
  applyFilters();
}

function toggleAllCards() {
  allCollapsed = !allCollapsed;
  var cards = document.querySelectorAll('.finding-card');
  cards.forEach(function(card) {
    if (allCollapsed) {
      card.classList.add('collapsed');
    } else {
      card.classList.remove('collapsed');
    }
  });
  var btn = document.getElementById('btn-toggle');
  if (btn) btn.textContent = allCollapsed ? 'Expand All' : 'Collapse All';
}

function toggleDarkMode() {
  document.body.classList.toggle('dark');
  var btn = document.getElementById('dark-toggle');
  if (btn) btn.textContent = document.body.classList.contains('dark') ? '☀' : '🌙';
  try { localStorage.setItem('adpulse-dark', document.body.classList.contains('dark') ? '1' : '0'); } catch(e) {}
}

function copyToClipboard() {
  var cards = document.querySelectorAll('.finding-card:not(.hidden)');
  var lines = ['ADPulse Security Findings Summary', ''];
  cards.forEach(function(card) {
    var sev = card.getAttribute('data-severity');
    var title = card.querySelector('.finding-title');
    if (title) {
      lines.push('[' + sev + '] ' + title.textContent);
      var affected = card.querySelector('.affected-block strong');
      if (affected) lines.push('  ' + affected.textContent);
    }
  });
  lines.push('');
  lines.push('Copied from ADPulse HTML Report');
  var text = lines.join('\\n');
  navigator.clipboard.writeText(text).then(function() {
    var btn = document.getElementById('clipboard-btn');
    if (btn) { btn.classList.add('copied'); btn.textContent = 'Copied!'; }
    setTimeout(function() {
      if (btn) { btn.classList.remove('copied'); btn.textContent = 'Copy Summary'; }
    }, 2000);
  });
}

// Restore dark mode preference
try {
  if (localStorage.getItem('adpulse-dark') === '1') {
    document.body.classList.add('dark');
    var btn = document.getElementById('dark-toggle');
    if (btn) btn.textContent = '☀';
  }
} catch(e) {}

// Handle permalink hash on load
if (window.location.hash) {
  var target = document.getElementById(window.location.hash.slice(1));
  if (target) {
    target.classList.remove('collapsed');
    setTimeout(function() { target.scrollIntoView({behavior: 'smooth', block: 'center'}); }, 100);
  }
}
"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ADPulse Report - {company_name}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono&display=swap" rel="stylesheet">
<style>{css}</style>
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div class="logo">{ADPULSE_LOGO_SVG}</div>
    <div class="header-text">
      <h1>ADPulse Security Assessment</h1>
      <h2>{company_name}</h2>
      <p>Report generated: {now}</p>
    </div>
    <div class="risk-pill">Risk: {risk_label} &nbsp; {risk_score}/100</div>
  </div>
</div>
<div class="orange-bar"></div>

<div class="container">
  <div class="stats-row">{stat_cards}</div>

  <div class="risk-box">
    <div class="risk-score-num">{risk_score}</div>
    <div class="risk-bar-wrap">
      <div class="risk-bar-label">Overall Risk Score / 100</div>
      <div class="risk-bar-bg"><div class="risk-bar-fill"></div></div>
    </div>
    <div class="risk-label">{risk_label}</div>
  </div>

  {"<div class='meta-box'>" + domain_html + "</div>" if domain_html else ""}

  <div class="section-header">
    <h2>Security Findings</h2>
    <span class="count-badge">{len(findings)} total</span>
    {"<span class='new-info'>&#9888; " + str(new_count) + " new since last scan</span>" if new_count else ""}
  </div>

  <div class="toolbar">
    <input type="text" id="search-input" class="search-box" placeholder="Search findings (title, description, affected objects...)" oninput="onSearchInput(event)">
    <select id="cat-filter" class="filter-select" onchange="onCategoryChange(event)">{cat_options}</select>
    <select id="new-filter" class="filter-select" onchange="onNewFilterChange(event)">
      <option value="ALL">All Status</option>
      <option value="new">New Only</option>
      <option value="recurring">Recurring Only</option>
    </select>
    <button class="btn-collapse" id="btn-toggle" onclick="toggleAllCards()">Collapse All</button>
    <button class="btn-reset" onclick="resetFilters()">Reset Filters</button>
    <button class="clipboard-btn" id="clipboard-btn" onclick="copyToClipboard()">Copy Summary</button>
    <button class="dark-toggle" id="dark-toggle" onclick="toggleDarkMode()" title="Toggle dark mode">&#127769;</button>
    <span class="filter-count" id="filter-count"></span>
  </div>

  {findings_html if findings else "<div class='no-findings'><div style='font-size:48px;margin-bottom:12px;'>&#9989;</div><strong>No findings detected.</strong><br>Your environment looks clean.</div>"}

  {audit_trail_html}
</div>

<div class="footer">
  <strong>ADPulse</strong> &nbsp;&middot;&nbsp;
  Run ID: {run_id[:36]} &nbsp;&middot;&nbsp; {now}<br>
  <em>This report is confidential. Do not distribute outside your organisation.</em>
</div>

<script>{js}</script>
</body>
</html>"""


# =============================================================================
#  PDF Report
# =============================================================================

class PDFReportGenerator:

    def generate(self, findings, run_id, output_path, company_name="Your Organisation",
                 domain_info=None, suppressed=None):
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm, mm
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                HRFlowable, PageBreak, KeepTogether,
            )
            from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
        except ImportError:
            logger.error("reportlab not installed. pip install reportlab")
            return ""

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        now = datetime.now().strftime("%d %B %Y  %H:%M")

        cs_blue   = colors.HexColor(CS_BLUE)
        cs_orange = colors.HexColor(CS_ORANGE)
        cs_dark   = colors.HexColor(CS_DARK)
        cs_mid    = colors.HexColor(CS_MID)

        styles = getSampleStyleSheet()

        def S(name, **kw):
            base = kw.pop("parent", styles["Normal"])
            return ParagraphStyle(name, parent=base, **kw)

        H2   = S("H2",  fontSize=13, textColor=cs_dark, fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=8)
        BODY = S("BD",  fontSize=9.5, textColor=colors.HexColor("#2e3d50"), leading=14, spaceAfter=5)
        SM   = S("SM",  fontSize=8,   textColor=colors.HexColor("#4a5a6e"), leading=12)
        REM  = S("RM",  fontSize=8,   textColor=colors.HexColor("#2e3d50"), leading=12)
        FOOT = S("FT",  fontSize=7,   textColor=colors.HexColor("#8a99b0"), alignment=TA_CENTER)

        # Counts & risk
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            counts[f.get("severity","INFO")] = counts.get(f.get("severity","INFO"), 0) + 1
        risk_score = min(
            counts["CRITICAL"]*40 + counts["HIGH"]*15 + counts["MEDIUM"]*5 + counts["LOW"]*1, 100
        )
        risk_label = ("CRITICAL" if risk_score>=70 else "HIGH" if risk_score>=40 else "MEDIUM" if risk_score>=20 else "LOW")
        risk_col   = colors.HexColor(SEVERITY_HEX.get(risk_label, "#666"))

        def _page(canvas, doc):
            w, h = A4
            canvas.saveState()
            # Top bar
            canvas.setFillColor(cs_dark)
            canvas.rect(0, h-16*mm, w, 16*mm, fill=1, stroke=0)
            canvas.setFillColor(cs_orange)
            canvas.rect(0, h-17.5*mm, w, 1.5*mm, fill=1, stroke=0)
            # Shield icon (simplified for PDF header)
            sx, sy = 2*cm, h-14.5*mm
            canvas.setFillColor(colors.HexColor("#0053A4"))
            p = canvas.beginPath()
            p.moveTo(sx+6*mm, sy)
            p.lineTo(sx+12*mm, sy+2*mm)
            p.lineTo(sx+12*mm, sy+7*mm)
            p.curveTo(sx+12*mm, sy+10*mm, sx+6*mm, sy+11.5*mm, sx+6*mm, sy+11.5*mm)
            p.curveTo(sx+6*mm, sy+11.5*mm, sx, sy+10*mm, sx, sy+7*mm)
            p.lineTo(sx, sy+2*mm)
            p.close()
            canvas.drawPath(p, fill=1, stroke=0)
            # Pulse dot in shield
            canvas.setFillColor(colors.HexColor("#FF8800"))
            canvas.circle(sx+4.5*mm, sy+5*mm, 1*mm, fill=1, stroke=0)
            # Wordmark
            canvas.setFillColor(colors.white)
            canvas.setFont("Helvetica-Bold", 10)
            canvas.drawString(sx+14*mm, h-10.5*mm, "AD")
            canvas.setFillColor(colors.HexColor("#FF8800"))
            canvas.drawString(sx+24*mm, h-10.5*mm, "Pulse")
            canvas.setFillColor(colors.HexColor("#8aafd8"))
            canvas.setFont("Helvetica", 8)
            canvas.drawString(sx+46*mm, h-10.5*mm, "Active Directory Security Assessment")
            canvas.setFillColor(colors.white)
            canvas.drawRightString(w-2*cm, h-10.5*mm, company_name)
            # Bottom footer
            canvas.setFillColor(colors.HexColor("#e8eef5"))
            canvas.rect(0, 0, w, 11*mm, fill=1, stroke=0)
            canvas.setFillColor(colors.HexColor("#8a99b0"))
            canvas.setFont("Helvetica", 7)
            canvas.drawString(2*cm, 4*mm, f"CONFIDENTIAL  |  ADPulse  |  {now}")
            canvas.drawRightString(w-2*cm, 4*mm, f"Page {doc.page}")
            canvas.restoreState()

        doc = SimpleDocTemplate(
            str(path), pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2.2*cm, bottomMargin=1.7*cm,
        )

        story = []

        # ── Cover ────────────────────────────────────────────────────────
        story.append(Spacer(1, 1.2*cm))
        story.append(Paragraph(
            f"<font color='{CS_BLUE}'><b>ADPulse</b></font>",
            S("CV", fontSize=34, fontName="Helvetica-Bold", spaceAfter=4)
        ))
        story.append(Paragraph("Active Directory Security Assessment Report",
            S("CVS", fontSize=13, textColor=colors.HexColor("#4a6a8a"), spaceAfter=4)))
        story.append(Paragraph(company_name,
            S("CVD", fontSize=10, textColor=cs_dark, spaceAfter=2)))
        story.append(Paragraph(f"Generated: {now}",
            S("CVT", fontSize=9, textColor=colors.HexColor("#8a99b0"), spaceAfter=18)))
        story.append(HRFlowable(width="100%", thickness=3, color=cs_orange, spaceAfter=14))

        # Risk table
        rt = Table([
            ["Overall Risk Score", "Risk Level", "Total Findings"],
            [
                Paragraph(f"<b>{risk_score}/100</b>",
                    S("RS", fontSize=26, textColor=risk_col, fontName="Helvetica-Bold")),
                Paragraph(f"<b>{risk_label}</b>",
                    S("RL", fontSize=17, textColor=risk_col, fontName="Helvetica-Bold")),
                Paragraph(f"<b>{len(findings)}</b>",
                    S("RF", fontSize=26, textColor=cs_blue, fontName="Helvetica-Bold")),
            ]
        ], colWidths=[5.7*cm, 5.7*cm, 5.6*cm])
        rt.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), cs_dark),
            ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,0), 9),
            ("ALIGN",         (0,0), (-1,-1), "CENTER"),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 10),
            ("BOTTOMPADDING", (0,0), (-1,-1), 10),
            ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#dde5ef")),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white]),
        ]))
        story.append(rt)
        story.append(Spacer(1, 14))

        # Severity breakdown
        sev_descs = {
            "CRITICAL": "Immediate action required — domain compromise risk",
            "HIGH":     "Urgent remediation recommended",
            "MEDIUM":   "Address within your security review cycle",
            "LOW":      "Low risk — next maintenance window",
            "INFO":     "Informational — no immediate action required",
        }
        sev_data = [["Severity", "Count", "Guidance"]]
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            c = colors.HexColor(SEVERITY_HEX[sev])
            sev_data.append([
                Paragraph(f"<b>{sev}</b>",
                    S(f"SC{sev}", fontSize=9, textColor=c, fontName="Helvetica-Bold")),
                Paragraph(str(counts[sev]),
                    S(f"SN{sev}", fontSize=13, textColor=c, fontName="Helvetica-Bold",
                      alignment=TA_CENTER)),
                Paragraph(sev_descs[sev], SM),
            ])
        st = Table(sev_data, colWidths=[3.5*cm, 2.5*cm, 11*cm])
        st.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), colors.HexColor("#f0f4f8")),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,0), 8),
            ("TEXTCOLOR",     (0,0), (-1,0), colors.HexColor("#4a5a6e")),
            ("ALIGN",         (1,0), (1,-1), "CENTER"),
            ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
            ("TOPPADDING",    (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
            ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#dde5ef")),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story.append(st)

        if domain_info:
            story.append(Spacer(1, 14))
            info = [
                ["Domain", str(domain_info.get("name") or domain_info.get("base_dn","--"))],
                ["Server", str(domain_info.get("server","--"))],
                ["Run ID", run_id[:36]],
            ]
            it = Table(info, colWidths=[3*cm, 14*cm])
            it.setStyle(TableStyle([
                ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
                ("FONTSIZE",      (0,0), (-1,-1), 8),
                ("TEXTCOLOR",     (0,0), (0,-1), colors.HexColor("#4a5a6e")),
                ("TOPPADDING",    (0,0), (-1,-1), 5),
                ("BOTTOMPADDING", (0,0), (-1,-1), 5),
                ("ROWBACKGROUNDS",(0,0), (-1,-1), [colors.white, colors.HexColor("#f8fafc")]),
                ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#dde5ef")),
            ]))
            story.append(it)

        story.append(PageBreak())

        # ── Findings ─────────────────────────────────────────────────────
        story.append(Paragraph(f"Security Findings  ({len(findings)} total)", H2))
        story.append(HRFlowable(width="100%", thickness=2, color=cs_orange, spaceAfter=10))

        if not findings:
            story.append(Paragraph("No security findings detected in this scan.", BODY))
        else:
            for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity","INFO"),99)):
                sev   = f.get("severity","INFO")
                scol  = colors.HexColor(SEVERITY_HEX.get(sev,"#666"))
                lcol  = colors.HexColor(SEVERITY_LIGHT.get(sev,"#fafafa"))
                is_new = f.get("is_new",1)
                icon   = SEVERITY_ICON.get(sev,"")

                elems = []

                # Header bar
                hdr_label = "NEW" if is_new else "RECURRING"
                hdr_color = colors.HexColor("#ffd080") if is_new else colors.HexColor("#8aafd8")
                hdr = Table([[
                    Paragraph(f"<b>{icon} {sev}</b>",
                        S("FH", fontSize=9, textColor=colors.white, fontName="Helvetica-Bold")),
                    Paragraph(f.get("category",""),
                        S("FC", fontSize=8, textColor=colors.HexColor("#c8d8ea"))),
                    Paragraph(f"<b>{hdr_label}</b>",
                        S("FN", fontSize=8, textColor=hdr_color, fontName="Helvetica-Bold",
                          alignment=TA_RIGHT)),
                ]], colWidths=[3.5*cm, 9.5*cm, 4*cm])
                hdr.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0), (-1,-1), scol),
                    ("TOPPADDING",    (0,0), (-1,-1), 6),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                    ("LEFTPADDING",   (0,0), (-1,-1), 10),
                    ("RIGHTPADDING",  (-1,0),(-1,-1), 10),
                    ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
                ]))
                elems.append(hdr)

                # Title + desc
                body_rows = [
                    Paragraph(f"<b>{f.get('title','')}</b>",
                        S("FT", fontSize=11, textColor=CS_DARK, fontName="Helvetica-Bold", spaceAfter=5)),
                ]

                # Policy status note (in_remediation only)
                if f.get("policy_status") == "in_remediation":
                    pol_style = ParagraphStyle(
                        "PolicyNote",
                        parent=styles["Normal"],
                        fontSize=8,
                        textColor=colors.HexColor("#0053A4"),
                        leftIndent=6,
                        backColor=colors.HexColor("#e8f4fd"),
                        borderPad=4,
                        spaceAfter=4,
                    )
                    policy_reason = f.get("policy_reason", "")
                    policy_expires = f.get("policy_expires") or ""
                    exp_str = f" \u2014 expires {policy_expires}" if policy_expires else ""
                    body_rows.append(Paragraph(
                        f"&#128295; In remediation: {policy_reason}{exp_str}",
                        pol_style,
                    ))

                body_rows.append(Paragraph(f.get("description",""), BODY))
                affected = f.get("affected",[])
                if affected:
                    aff_str = ", ".join(str(a) for a in affected[:30])
                    if len(affected)>30: aff_str += f" (+{len(affected)-30} more)"
                    body_rows.append(Paragraph(f"<b>Affected ({len(affected)}):</b>  {aff_str}", SM))

                bt = Table([[row] for row in body_rows], colWidths=[17*cm])
                bt.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0), (-1,-1), lcol),
                    ("LEFTPADDING",   (0,0), (-1,-1), 12),
                    ("RIGHTPADDING",  (0,0), (-1,-1), 12),
                    ("TOPPADDING",    (0,0), (-1,-1), 8),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                    ("LINEAFTER",     (0,0), (0,-1), 3, scol),
                ]))
                elems.append(bt)

                # Remediation
                rem_text = f.get("remediation","").replace("\n","<br/>")
                rt2 = Table(
                    [[Paragraph(
                        f"<font color='{CS_BLUE}'><b>REMEDIATION</b></font><br/>{rem_text}", REM
                    )]],
                    colWidths=[17*cm],
                )
                rt2.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#f5f8fb")),
                    ("LEFTPADDING",   (0,0), (-1,-1), 12),
                    ("RIGHTPADDING",  (0,0), (-1,-1), 12),
                    ("TOPPADDING",    (0,0), (-1,-1), 8),
                    ("BOTTOMPADDING", (0,0), (-1,-1), 10),
                    ("LINEABOVE",     (0,0), (-1,0), 1, colors.HexColor("#dde5ef")),
                    ("LINEAFTER",     (0,0), (0,-1), 3, scol),
                ]))
                elems.append(rt2)
                elems.append(Spacer(1, 8))
                story.append(KeepTogether(elems))

        doc.build(story, onFirstPage=_page, onLaterPages=_page)
        logger.info(f"PDF report -> {output_path}")
        return str(path)


# =============================================================================
#  Trend Dashboard
# =============================================================================

class TrendDashboardGenerator:
    """Generates an interactive HTML trend dashboard from historical scan data."""

    def generate(self, trend_data, output_path, company_name="Your Organisation"):
        html = self._build(trend_data, company_name)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding="utf-8")
        logger.info(f"Trend dashboard -> {output_path}")
        return str(path)

    def _build(self, trend_data, company_name):
        now = datetime.now().strftime("%d %B %Y, %H:%M")

        # Prepare chart data
        labels = []
        risk_scores = []
        critical_counts = []
        high_counts = []
        medium_counts = []
        total_counts = []

        for t in trend_data:
            date = (t.get("finished_at") or "")[:10]
            labels.append(date)
            risk_scores.append(t.get("risk_score", 0))
            sc = t.get("severity_counts", {})
            critical_counts.append(sc.get("CRITICAL", 0))
            high_counts.append(sc.get("HIGH", 0))
            medium_counts.append(sc.get("MEDIUM", 0))
            total_counts.append(t.get("findings_count", 0))

        chart_data = {
            "labels": labels,
            "risk_scores": risk_scores,
            "critical": critical_counts,
            "high": high_counts,
            "medium": medium_counts,
            "total": total_counts,
        }

        import json
        chart_json = json.dumps(chart_data)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ADPulse Trend Dashboard - {company_name}</title>
<style>
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: 'Segoe UI', Arial, sans-serif;
  background: #f0f4f8; color: #0a1628; min-height: 100vh;
}}
.header {{
  background: linear-gradient(135deg, #0a1628 0%, #1a3a6b 60%, #0053A4 100%);
  padding: 24px 40px; color: white;
}}
.header h1 {{ font-size: 22px; font-weight: 700; }}
.header p {{ font-size: 12px; color: rgba(255,255,255,0.5); margin-top: 4px; }}
.bar {{ height: 4px; background: linear-gradient(90deg, #FF8800 0%, #0053A4 100%); }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 28px 40px; }}
.card {{
  background: white; border-radius: 10px; padding: 24px;
  box-shadow: 0 2px 8px rgba(0,83,164,0.07); margin-bottom: 20px;
}}
.card h2 {{ font-size: 15px; font-weight: 700; margin-bottom: 16px; color: #0a1628; }}
canvas {{ width: 100% !important; height: 300px !important; }}
.grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
.summary-cards {{
  display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 20px;
}}
.s-card {{
  background: white; border-radius: 10px; padding: 16px; text-align: center;
  box-shadow: 0 2px 8px rgba(0,83,164,0.07);
}}
.s-card .num {{ font-size: 32px; font-weight: 800; line-height: 1; }}
.s-card .lbl {{ font-size: 10px; color: #8a99b0; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
.trend-table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
.trend-table th {{ background: #f0f4f8; padding: 8px 12px; text-align: left; font-weight: 700; color: #4a5a6e; }}
.trend-table td {{ padding: 8px 12px; border-bottom: 1px solid #eef2f7; }}
.trend-table tr:hover {{ background: #f8fafc; }}
@media (max-width: 900px) {{ .grid {{ grid-template-columns: 1fr; }} .summary-cards {{ grid-template-columns: repeat(2,1fr); }} }}
</style>
</head>
<body>
<div class="header">
  <h1>ADPulse Trend Dashboard</h1>
  <p>{company_name} | Generated: {now} | {len(trend_data)} scans</p>
</div>
<div class="bar"></div>
<div class="container">

  <div class="summary-cards">
    <div class="s-card">
      <div class="num" style="color:#0053A4;">{len(trend_data)}</div>
      <div class="lbl">Total Scans</div>
    </div>
    <div class="s-card">
      <div class="num" style="color:{SEVERITY_HEX.get('CRITICAL','#c0152a')};">{risk_scores[-1] if risk_scores else 0}</div>
      <div class="lbl">Latest Risk Score</div>
    </div>
    <div class="s-card">
      <div class="num" style="color:#1a7a3f;">{"+" if len(risk_scores)>=2 and risk_scores[-1] <= risk_scores[-2] else ""}{risk_scores[-1] - risk_scores[-2] if len(risk_scores)>=2 else 0}</div>
      <div class="lbl">Score Change</div>
    </div>
    <div class="s-card">
      <div class="num" style="color:#0053A4;">{total_counts[-1] if total_counts else 0}</div>
      <div class="lbl">Latest Findings</div>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h2>Risk Score Trend</h2>
      <canvas id="riskChart"></canvas>
    </div>
    <div class="card">
      <h2>Findings by Severity</h2>
      <canvas id="sevChart"></canvas>
    </div>
  </div>

  <div class="card">
    <h2>Scan History</h2>
    <table class="trend-table">
      <thead><tr><th>Date</th><th>Risk Score</th><th>Critical</th><th>High</th><th>Medium</th><th>Total</th></tr></thead>
      <tbody id="histTable"></tbody>
    </table>
  </div>

</div>

<script>
var D = {chart_json};

// Simple canvas chart renderer (no external dependencies)
function drawLineChart(canvasId, labels, datasets) {{
  var c = document.getElementById(canvasId);
  var ctx = c.getContext('2d');
  var w = c.width = c.offsetWidth;
  var h = c.height = c.offsetHeight;
  var pad = {{top: 20, right: 20, bottom: 40, left: 50}};
  var cw = w - pad.left - pad.right;
  var ch = h - pad.top - pad.bottom;

  var allVals = [];
  datasets.forEach(function(ds) {{ allVals = allVals.concat(ds.data); }});
  var maxVal = Math.max.apply(null, allVals) || 100;
  maxVal = Math.ceil(maxVal / 10) * 10 || 10;

  // Grid
  ctx.strokeStyle = '#e8eef5';
  ctx.lineWidth = 1;
  for (var i = 0; i <= 5; i++) {{
    var y = pad.top + ch - (ch * i / 5);
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke();
    ctx.fillStyle = '#8a99b0'; ctx.font = '10px sans-serif'; ctx.textAlign = 'right';
    ctx.fillText(Math.round(maxVal * i / 5), pad.left - 8, y + 4);
  }}

  // X labels
  ctx.fillStyle = '#8a99b0'; ctx.font = '10px sans-serif'; ctx.textAlign = 'center';
  var step = Math.max(1, Math.floor(labels.length / 8));
  for (var i = 0; i < labels.length; i += step) {{
    var x = pad.left + (cw * i / (labels.length - 1 || 1));
    ctx.fillText(labels[i], x, h - pad.bottom + 18);
  }}

  // Lines
  datasets.forEach(function(ds) {{
    ctx.strokeStyle = ds.color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    for (var i = 0; i < ds.data.length; i++) {{
      var x = pad.left + (cw * i / (ds.data.length - 1 || 1));
      var y = pad.top + ch - (ch * ds.data[i] / maxVal);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }}
    ctx.stroke();
    // Dots
    for (var i = 0; i < ds.data.length; i++) {{
      var x = pad.left + (cw * i / (ds.data.length - 1 || 1));
      var y = pad.top + ch - (ch * ds.data[i] / maxVal);
      ctx.fillStyle = ds.color;
      ctx.beginPath(); ctx.arc(x, y, 3, 0, Math.PI * 2); ctx.fill();
    }}
  }});
}}

function drawBarChart(canvasId, labels, datasets) {{
  var c = document.getElementById(canvasId);
  var ctx = c.getContext('2d');
  var w = c.width = c.offsetWidth;
  var h = c.height = c.offsetHeight;
  var pad = {{top: 20, right: 20, bottom: 40, left: 50}};
  var cw = w - pad.left - pad.right;
  var ch = h - pad.top - pad.bottom;

  var maxVal = 0;
  for (var i = 0; i < labels.length; i++) {{
    var sum = 0;
    datasets.forEach(function(ds) {{ sum += ds.data[i] || 0; }});
    if (sum > maxVal) maxVal = sum;
  }}
  maxVal = Math.ceil(maxVal / 5) * 5 || 10;

  // Grid
  ctx.strokeStyle = '#e8eef5'; ctx.lineWidth = 1;
  for (var i = 0; i <= 5; i++) {{
    var y = pad.top + ch - (ch * i / 5);
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke();
    ctx.fillStyle = '#8a99b0'; ctx.font = '10px sans-serif'; ctx.textAlign = 'right';
    ctx.fillText(Math.round(maxVal * i / 5), pad.left - 8, y + 4);
  }}

  var barW = (cw / labels.length) * 0.6;
  var gap = (cw / labels.length) * 0.4;

  for (var i = 0; i < labels.length; i++) {{
    var x = pad.left + (cw * i / labels.length) + gap / 2;
    var yOffset = 0;
    datasets.forEach(function(ds) {{
      var val = ds.data[i] || 0;
      var barH = (ch * val / maxVal);
      var y = pad.top + ch - yOffset - barH;
      ctx.fillStyle = ds.color;
      ctx.fillRect(x, y, barW, barH);
      yOffset += barH;
    }});
    // X label
    ctx.fillStyle = '#8a99b0'; ctx.font = '10px sans-serif'; ctx.textAlign = 'center';
    if (i % Math.max(1, Math.floor(labels.length / 8)) === 0) {{
      ctx.fillText(labels[i], x + barW / 2, h - pad.bottom + 18);
    }}
  }}
}}

// Render charts
window.addEventListener('load', function() {{
  drawLineChart('riskChart', D.labels, [
    {{data: D.risk_scores, color: '#0053A4'}}
  ]);
  drawBarChart('sevChart', D.labels, [
    {{data: D.critical, color: '#c0152a'}},
    {{data: D.high, color: '#d9500a'}},
    {{data: D.medium, color: '#b07d00'}}
  ]);

  // Table
  var tbody = document.getElementById('histTable');
  for (var i = D.labels.length - 1; i >= 0; i--) {{
    var tr = document.createElement('tr');
    tr.innerHTML = '<td>' + D.labels[i] + '</td>' +
      '<td><strong>' + D.risk_scores[i] + '/100</strong></td>' +
      '<td style="color:#c0152a;font-weight:700;">' + D.critical[i] + '</td>' +
      '<td style="color:#d9500a;font-weight:700;">' + D.high[i] + '</td>' +
      '<td style="color:#b07d00;font-weight:700;">' + D.medium[i] + '</td>' +
      '<td>' + D.total[i] + '</td>';
    tbody.appendChild(tr);
  }}
}});
</script>
</body>
</html>"""


# =============================================================================
#  Report Manager
# =============================================================================

class ReportManager:

    def __init__(self, config: dict):
        self.output_dir   = Path(config.get("output_dir", "./output"))
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.gen_pdf      = config.get("generate_pdf",  "true").lower() == "true"
        self.gen_html     = config.get("generate_html", "true").lower() == "true"
        self.gen_trend    = config.get("generate_trend_dashboard", "false").lower() == "true"
        self.company_name = config.get("company_name", "Your Organisation")

    def generate_all(self, findings, run_id, domain_info=None, baseline=None, suppressed=None):
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        paths = {}

        if self.gen_html:
            p = str(self.output_dir / f"ADPulse_Report_{ts}.html")
            try:
                paths["html"] = HTMLReportGenerator().generate(
                    findings, run_id, p, self.company_name, domain_info,
                    suppressed=suppressed or [])
            except Exception as e:
                logger.error(f"HTML generation failed: {e}")

        if self.gen_pdf:
            p = str(self.output_dir / f"ADPulse_Report_{ts}.pdf")
            try:
                paths["pdf"] = PDFReportGenerator().generate(
                    findings, run_id, p, self.company_name, domain_info,
                    suppressed=suppressed or [])
            except Exception as e:
                logger.error(f"PDF generation failed: {e}")

        if self.gen_trend and baseline:
            p = str(self.output_dir / f"ADPulse_Trends_{ts}.html")
            try:
                trend_data = baseline.get_trend_data(limit=30)
                if trend_data:
                    paths["trend"] = TrendDashboardGenerator().generate(
                        trend_data, p, self.company_name)
            except Exception as e:
                logger.error(f"Trend dashboard generation failed: {e}")

        return paths
