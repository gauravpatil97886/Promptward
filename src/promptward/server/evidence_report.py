"""
Render a signed evidence pack to a standalone, print-to-PDF HTML document.

Auditors want a *document*, not JSON. This produces a single self-contained HTML
file (inline CSS, no assets, no JS) that prints cleanly to PDF from any browser
— the deliverable you attach to a security questionnaire or audit response.

The rendered document restates the manifest digest + signature so a reviewer can
independently re-verify the machine-readable pack against the printed one.
"""

import html
from typing import Optional

from .evidence import FRAMEWORK_MAP, GAP, PARTIAL, PASS

_STATUS_COLOR = {PASS: "#15803d", PARTIAL: "#b45309", GAP: "#b91c1c"}
_STATUS_BG = {PASS: "#dcfce7", PARTIAL: "#fef3c7", GAP: "#fee2e2"}
_SEV_LABEL = {1: "Low", 2: "Medium", 3: "High"}


def _e(v: object) -> str:
    return html.escape(str(v if v is not None else "—"))


def _badge(status: str) -> str:
    return (f'<span class="badge" style="color:{_STATUS_COLOR.get(status, "#475569")};'
            f'background:{_STATUS_BG.get(status, "#e2e8f0")}">{_e(status)}</span>')


def _control_rows(controls: list[dict]) -> str:
    return "".join(
        f"<tr><td><b>{_e(c['title'])}</b><div class='mut'>{_e(c['detail'])}</div></td>"
        f"<td class='nowrap'>{_badge(c['status'])}</td>"
        f"<td class='mut'><code>{_e(c['evidence'])}</code></td></tr>"
        for c in controls
    )


def _framework_blocks(frameworks: dict) -> str:
    out = []
    for fw, clauses in FRAMEWORK_MAP.items():
        data = frameworks.get(fw, {})
        rows = "".join(
            f"<tr><td>{_e(cl['clause'])}</td>"
            f"<td class='mut'><code>{_e(cl['control'])}</code></td>"
            f"<td class='nowrap'>{_badge(cl['status'])}</td></tr>"
            for cl in data.get("clauses", [])
        )
        out.append(
            f"<div class='fw'><div class='fw-head'><h3>{_e(fw)}</h3>"
            f"{_badge(data.get('coverage', GAP))}</div>"
            f"<table><thead><tr><th>Clause / control objective</th><th>Mapped control</th>"
            f"<th>Status</th></tr></thead><tbody>{rows}</tbody></table></div>"
        )
    return "".join(out)


def _inventory_rows(agents: list[dict]) -> str:
    if not agents:
        return "<tr><td colspan='5' class='mut'>No agents enrolled.</td></tr>"
    return "".join(
        f"<tr><td>{_e(a.get('device_name'))}</td><td>{_e(a.get('os'))}</td>"
        f"<td>{_e(a.get('sys_user'))}</td><td>{_e(a.get('status'))}</td>"
        f"<td class='mut'>{_e((a.get('last_seen') or '')[:19])}</td></tr>"
        for a in agents
    )


def render_html(signed: dict) -> str:
    """Render a signed pack (envelope with `pack` + `manifest`) to an HTML string."""
    pack = signed.get("pack", signed)
    manifest = signed.get("manifest", {})
    meta = pack.get("metadata", {})
    posture = pack.get("posture", {})
    reg = pack.get("violation_register", {})
    audit = pack.get("audit_trail", {})
    inv = pack.get("inventory", {})

    sev = reg.get("by_severity", {}) or {}
    sev_line = " · ".join(f"{_SEV_LABEL.get(int(k), k)}: {v}" for k, v in sorted(sev.items())) or "none"
    cat = reg.get("by_category", {}) or {}
    cat_line = ", ".join(f"{_e(k)} ({v})" for k, v in cat.items()) or "none"

    audit_ok = audit.get("verified")
    audit_badge = _badge(PASS if audit_ok else GAP)
    audit_note = ("Hash chain intact — log has not been altered."
                  if audit_ok else
                  f"CHAIN BROKEN at entry {audit.get('first_broken_id')} — possible tampering.")

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(meta.get('org_name'))} — AI Governance Evidence Pack</title>
<style>
  @page {{ margin: 18mm; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         color: #0f172a; margin: 0; padding: 32px; max-width: 960px; margin: 0 auto;
         line-height: 1.5; font-size: 13px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  h2 {{ font-size: 15px; margin: 28px 0 10px; padding-bottom: 6px;
        border-bottom: 2px solid #e2e8f0; }}
  h3 {{ font-size: 14px; margin: 0; }}
  .mut {{ color: #64748b; font-size: 12px; }}
  .head {{ display: flex; justify-content: space-between; align-items: flex-start;
          border-bottom: 3px solid #2563eb; padding-bottom: 14px; }}
  .brand {{ color: #2563eb; font-weight: 700; letter-spacing: .04em; }}
  .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin: 14px 0; }}
  .stat {{ border: 1px solid #e2e8f0; border-radius: 10px; padding: 12px; }}
  .stat .n {{ font-size: 24px; font-weight: 700; }}
  table {{ width: 100%; border-collapse: collapse; margin: 8px 0 4px; }}
  th, td {{ text-align: left; padding: 7px 9px; border-bottom: 1px solid #eef2f7;
           vertical-align: top; }}
  th {{ font-size: 11px; text-transform: uppercase; letter-spacing: .03em; color: #64748b; }}
  code {{ font-size: 11px; background: #f1f5f9; padding: 1px 5px; border-radius: 4px; }}
  .badge {{ font-weight: 700; font-size: 11px; padding: 2px 9px; border-radius: 999px;
           white-space: nowrap; }}
  .nowrap {{ white-space: nowrap; }}
  .fw {{ border: 1px solid #e2e8f0; border-radius: 10px; padding: 6px 14px 12px; margin: 12px 0; }}
  .fw-head {{ display: flex; justify-content: space-between; align-items: center;
             margin-top: 8px; }}
  .manifest {{ background: #0f172a; color: #cbd5e1; border-radius: 10px; padding: 14px 16px;
              font-size: 11px; word-break: break-all; margin-top: 8px; }}
  .manifest b {{ color: #fff; }}
  footer {{ margin-top: 30px; color: #94a3b8; font-size: 11px;
           border-top: 1px solid #e2e8f0; padding-top: 10px; }}
</style></head><body>

<div class="head">
  <div>
    <h1>AI Governance Evidence Pack</h1>
    <div class="mut">{_e(meta.get('org_name'))} · reporting window {_e(meta.get('period_days'))} days</div>
  </div>
  <div style="text-align:right">
    <div class="brand">PROMPTWARD</div>
    <div class="mut">Generated {_e((meta.get('generated_at') or '')[:19])}<br>by {_e(meta.get('generated_by'))}</div>
  </div>
</div>

<h2>Control posture summary</h2>
<div class="grid">
  <div class="stat"><div class="n" style="color:#15803d">{_e(posture.get('pass', 0))}</div>controls PASS</div>
  <div class="stat"><div class="n" style="color:#b45309">{_e(posture.get('partial', 0))}</div>controls PARTIAL</div>
  <div class="stat"><div class="n" style="color:#b91c1c">{_e(posture.get('gap', 0))}</div>controls GAP</div>
  <div class="stat"><div class="n">{_e(reg.get('flagged', 0))}</div>flagged interactions</div>
</div>

<h2>Audit trail integrity</h2>
<p>{audit_badge} &nbsp; {_e(audit_note)}
<span class="mut">({_e(audit.get('entries_sampled', 0))} recent entries sampled.)</span></p>

<h2>Violation register</h2>
<table>
  <tr><td style="width:40%">Total interactions logged</td><td>{_e(reg.get('total_interactions', 0))}</td></tr>
  <tr><td>Flagged interactions</td><td>{_e(reg.get('flagged', 0))}</td></tr>
  <tr><td>By severity</td><td>{_e(sev_line)}</td></tr>
  <tr><td>By category</td><td>{_e(cat_line)}</td></tr>
</table>

<h2>Control attestation</h2>
<table><thead><tr><th>Control</th><th>Status</th><th>Evidence</th></tr></thead>
<tbody>{_control_rows(pack.get('controls', []))}</tbody></table>

<h2>Framework mapping</h2>
{_framework_blocks(pack.get('frameworks', {}))}

<h2>AI use inventory</h2>
<table><thead><tr><th>Device</th><th>OS</th><th>User</th><th>Status</th><th>Last seen</th></tr></thead>
<tbody>{_inventory_rows(inv.get('agents', []))}</tbody></table>

<h2>Authenticity manifest</h2>
<div class="manifest">
  <div><b>Algorithm:</b> {_e(manifest.get('alg', 'unsigned'))}</div>
  <div><b>Content SHA-256:</b> {_e(manifest.get('pack_sha256', '—'))}</div>
  <div><b>Signature:</b> {_e(manifest.get('signature', '—'))}</div>
  <div class="mut" style="margin-top:6px">Re-verify the machine-readable pack with
  <code>pw evidence --verify pack.json</code>. Any edit to the JSON invalidates this signature.</div>
</div>

<footer>Generated by Promptward — self-hosted AI usage governance. This document
reflects live system state at generation time and is not a substitute for a formal audit.</footer>
</body></html>"""


def render_report(signed: dict, settings: Optional[object] = None) -> str:
    """Public entry — kept thin so callers don't import internals."""
    return render_html(signed)
