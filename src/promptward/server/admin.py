"""
Admin / compliance control plane for the IT-security/compliance team.

Registered onto the dashboard app, so every route here is behind the dashboard
token (Phase 3 RBAC will swap the single token for per-user roles without changing
these paths). Mutations are written to the tamper-evident audit log.

Routes:
    GET   /admin                          compact admin + compliance UI
    GET   /api/compliance                 violation register summary + frameworks
    GET   /api/admin/agents               enrolled agents
    POST  /api/admin/agents/{id}/revoke   revoke an agent key
    GET   /api/admin/settings             runtime settings (key/value)
    PATCH /api/admin/settings             update settings
    GET   /api/admin/audit                audit log + chain verification
    POST  /api/admin/notify               push a notification to a device
    GET   /api/admin/export.csv           CSV export (metadata) for SIEM/audit
"""

from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from ..common.config import Settings
from ..common.storage import Store
from . import evidence, evidence_report, reports
from .audit import AuditLog
from .server_store import ServerStore


def register_admin(app: FastAPI, settings: Settings) -> None:
    sstore = ServerStore(settings)
    audit = AuditLog(settings)
    store = Store(settings)

    def _actor(request: Request) -> str:
        return request.client.host if request.client else "admin"

    @app.get("/admin", response_class=HTMLResponse)
    async def admin_page() -> HTMLResponse:
        return HTMLResponse(_ADMIN_HTML)

    @app.get("/api/compliance")
    async def compliance() -> dict:
        return reports.compliance_summary()

    @app.get("/api/admin/agents")
    async def agents() -> list[dict]:
        return sstore.list_agents()

    @app.post("/api/admin/agents/{agent_id}/revoke")
    async def revoke(agent_id: str, request: Request) -> dict:
        sstore.revoke_agent(agent_id)
        audit.record(_actor(request), "agent.revoke", agent_id)
        return {"ok": True}

    @app.post("/api/admin/agents/{agent_id}/rotate")
    async def rotate_agent(agent_id: str, request: Request) -> dict:
        new_key = sstore.rotate_agent_key(agent_id)
        audit.record(_actor(request), "agent.rotate-key", agent_id)
        return {"ok": new_key is not None, "agent_key": new_key}

    @app.post("/api/admin/org-token/rotate")
    async def rotate_org_token(request: Request) -> dict:
        token = sstore.rotate_enroll_token()
        audit.record(_actor(request), "org-token.rotate")
        return {"ok": True, "enroll_token": token}

    @app.post("/api/admin/erase")
    async def erase(payload: dict, request: Request) -> dict:
        """Right-to-erasure (GDPR Art. 17): delete a subject's interactions."""
        removed = store.delete_by_subject(
            sys_user=payload.get("sys_user") or None,
            device_name=payload.get("device_name") or None,
        )
        audit.record(_actor(request), "data.erase",
                     payload.get("sys_user") or payload.get("device_name") or "", f"{removed} rows")
        return {"ok": True, "removed": removed}

    @app.get("/api/admin/settings")
    async def get_settings_kv() -> dict:
        return sstore.all_settings()

    @app.patch("/api/admin/settings")
    async def patch_settings(payload: dict, request: Request) -> dict:
        for k, v in payload.items():
            sstore.set_setting(str(k), str(v))
        audit.record(_actor(request), "settings.update", ",".join(payload.keys()))
        return {"ok": True, "settings": sstore.all_settings()}

    @app.get("/api/admin/audit")
    async def audit_log() -> dict:
        ok, broken_at = audit.verify()
        return {"verified": ok, "broken_at": broken_at, "entries": audit.list_recent()}

    @app.post("/api/admin/notify")
    async def notify(payload: dict, request: Request) -> dict:
        nid = sstore.add_notification(
            device=payload.get("device", ""),
            title=payload.get("title", "Security Notification"),
            message=payload.get("message", ""),
            severity=int(payload.get("severity", 2)),
            sent_by=payload.get("sent_by", "Security Team"),
        )
        audit.record(_actor(request), "notify.send", payload.get("device", ""))
        return {"ok": True, "id": nid}

    @app.get("/api/admin/export.csv", response_class=PlainTextResponse)
    async def export_csv(request: Request, content: bool = False) -> PlainTextResponse:
        audit.record(_actor(request), "report.export", "interactions.csv")
        return PlainTextResponse(
            reports.interactions_csv(include_content=content),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=pw-interactions.csv"},
        )

    @app.get("/api/admin/evidence-pack")
    async def evidence_pack(request: Request, period_days: int = 30) -> JSONResponse:
        """
        Generate a signed compliance evidence pack: inventory + violation register
        + audit verification + per-control attestation mapped to EU AI Act / NIST
        AI RMF / ISO 42001 / SOC 2 / GDPR. The export action is itself audited.
        """
        now = datetime.now(timezone.utc).isoformat()
        pack = evidence.build_pack(settings, period_days=period_days,
                                   generated_at=now, actor=_actor(request))
        signed = evidence.sign_pack(pack, settings)
        audit.record(_actor(request), "evidence.export",
                     "evidence-pack", f"period_days={period_days}")
        return JSONResponse(
            signed,
            headers={"Content-Disposition": "attachment; filename=promptward-evidence-pack.json"},
        )

    @app.get("/api/admin/evidence-pack.html", response_class=HTMLResponse)
    async def evidence_pack_html(request: Request, period_days: int = 30) -> HTMLResponse:
        """Same evidence pack, rendered as a print-to-PDF HTML document for auditors."""
        now = datetime.now(timezone.utc).isoformat()
        pack = evidence.build_pack(settings, period_days=period_days,
                                   generated_at=now, actor=_actor(request))
        signed = evidence.sign_pack(pack, settings)
        audit.record(_actor(request), "evidence.export", "evidence-pack.html",
                     f"period_days={period_days}")
        return HTMLResponse(evidence_report.render_html(signed))

    @app.post("/api/admin/evidence-pack/verify")
    async def evidence_pack_verify(payload: dict) -> dict:
        """Verify a previously-issued pack's signature + content hash."""
        ok, reason = evidence.verify_pack(payload, settings)
        return {"verified": ok, "reason": reason}


_ADMIN_HTML = r"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Promptward — Admin & Compliance</title><style>
:root{--bg:#0b0e14;--card:#141925;--bd:#232a3a;--mut:#8b95a7;--fg:#e6e6e6;
--red:#ef4444;--amb:#f59e0b;--blue:#3b82f6;--grn:#22c55e}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font-family:system-ui,Segoe UI,sans-serif;font-size:14px}
header{padding:16px 24px;border-bottom:1px solid var(--bd);display:flex;
align-items:center;gap:16px}h1{font-size:16px;margin:0}
nav{display:flex;gap:6px;margin-left:auto}nav button{background:#0e1220;color:var(--mut);
border:1px solid var(--bd);padding:7px 14px;border-radius:8px;cursor:pointer}
nav button.on{background:var(--blue);color:#fff;border-color:var(--blue)}
main{padding:24px;max-width:1100px;margin:0 auto}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;
padding:18px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.kpi{background:#0e1220;border:1px solid var(--bd);border-radius:10px;padding:14px}
.kpi b{font-size:24px;display:block}.mut{color:var(--mut)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;
border-bottom:1px solid var(--bd);font-size:13px}th{color:var(--mut);font-weight:600}
.pill{padding:2px 8px;border-radius:99px;font-size:11px}
.s3{background:rgba(239,68,68,.15);color:var(--red)}.s2{background:rgba(245,158,11,.15);color:var(--amb)}
.s1{background:rgba(59,130,246,.15);color:var(--blue)}.ok{color:var(--grn)}.bad{color:var(--red)}
.b{font-weight:700;font-size:11px;padding:2px 9px;border-radius:99px;white-space:nowrap}
.bPASS{background:rgba(34,197,94,.15);color:var(--grn)}
.bPARTIAL{background:rgba(245,158,11,.15);color:var(--amb)}
.bGAP{background:rgba(239,68,68,.15);color:var(--red)}
button.act{background:var(--blue);color:#fff;border:0;border-radius:7px;padding:6px 12px;cursor:pointer}
a.act{color:var(--blue)}
.tab{display:none}.tab.on{display:block}
</style></head><body>
<header><h1>🛡 Promptward — Admin &amp; Compliance</h1>
<nav>
<button class="on" onclick="show('compliance',this)">Compliance</button>
<button onclick="show('evidence',this)">Evidence pack</button>
<button onclick="show('agents',this)">Agents</button>
<button onclick="show('audit',this)">Audit</button>
<button onclick="show('settings',this)">Settings</button>
</nav></header><main>

<section id="compliance" class="tab on">
  <div class="card"><div class="grid" id="kpis"></div></div>
  <div class="card"><h3>Violation register (by category)</h3><table id="cats"></table></div>
  <div class="card"><h3>Framework alignment</h3><table id="fw"></table>
    <p class="mut">Export evidence: <a class="act" href="/api/admin/export.csv">interactions.csv</a></p></div>
</section>

<section id="evidence" class="tab">
  <div class="card">
    <h3>Compliance evidence pack</h3>
    <p class="mut">A signed, self-contained governance artifact mapped to EU AI Act / NIST AI RMF /
      ISO 42001 / SOC 2 / GDPR. Control statuses below are derived from live system state.</p>
    <p>
      <a class="act" href="/api/admin/evidence-pack.html" target="_blank">📄 Open printable report (PDF)</a> &nbsp;
      <a class="act" href="/api/admin/evidence-pack" download>⬇ Download signed JSON</a>
    </p>
    <div class="grid" id="ev-kpis" style="margin-top:14px"></div>
  </div>
  <div class="card"><h3>Control attestation</h3><table id="ev-controls"></table></div>
  <div class="card"><h3>Framework coverage</h3><table id="ev-fw"></table></div>
</section>

<section id="agents" class="tab">
  <div class="card"><h3>Enrolled agents</h3><table id="agents-t"></table></div>
</section>

<section id="audit" class="tab">
  <div class="card"><h3>Audit log <span id="chain"></span></h3><table id="audit-t"></table></div>
</section>

<section id="settings" class="tab">
  <div class="card"><h3>Runtime settings</h3>
    <p class="mut">Detection thresholds, retention, redaction, model governance. Saved server-side; applied without restart.</p>
    <table id="settings-t"></table>
    <p><button class="act" onclick="saveSettings()">Save changes</button></p></div>
  <div class="card"><h3>Right to erasure (GDPR Art. 17)</h3>
    <p class="mut">Permanently delete all stored interactions for a user or device. Audited.</p>
    <input id="erase-user" placeholder="sys_user" style="background:#0e1220;color:#fff;border:1px solid var(--bd);border-radius:6px;padding:6px;margin-right:8px">
    <input id="erase-device" placeholder="device_name" style="background:#0e1220;color:#fff;border:1px solid var(--bd);border-radius:6px;padding:6px;margin-right:8px">
    <button class="act" onclick="erase()">Erase</button></div>
</section>
</main><script>
const $=s=>document.querySelector(s);
async function j(u,o){const r=await fetch(u,o);return r.json()}
function sev(n){return '<span class="pill s'+n+'">'+(['','LOW','MEDIUM','HIGH'][n]||n)+'</span>'}
function show(id,btn){document.querySelectorAll('.tab').forEach(t=>t.classList.remove('on'));
  $('#'+id).classList.add('on');document.querySelectorAll('nav button').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');load(id)}
async function load(id){
  if(id==='compliance'){const c=await j('/api/compliance');
    $('#kpis').innerHTML=`<div class="kpi"><span class="mut">Interactions</span><b>${c.total}</b></div>
      <div class="kpi"><span class="mut">Flagged</span><b>${c.flagged}</b></div>
      <div class="kpi"><span class="mut">High</span><b class="bad">${c.by_severity[3]||0}</b></div>
      <div class="kpi"><span class="mut">Medium</span><b>${c.by_severity[2]||0}</b></div>`;
    $('#cats').innerHTML='<tr><th>Category</th><th>Count</th></tr>'+
      (Object.entries(c.by_category).map(([k,v])=>`<tr><td>${k}</td><td>${v}</td></tr>`).join('')||'<tr><td class=mut colspan=2>No violations recorded</td></tr>');
    $('#fw').innerHTML='<tr><th>Framework</th><th>Controls covered</th></tr>'+
      Object.entries(c.frameworks).map(([k,v])=>`<tr><td>${k}</td><td class=mut>${v.join(' · ')}</td></tr>`).join('');
  }
  if(id==='evidence'){const e=await j('/api/admin/evidence-pack');const p=e.pack;const po=p.posture;
    $('#ev-kpis').innerHTML=`<div class="kpi"><span class="mut">Controls PASS</span><b class="ok">${po.pass}</b></div>
      <div class="kpi"><span class="mut">PARTIAL</span><b style="color:var(--amb)">${po.partial}</b></div>
      <div class="kpi"><span class="mut">GAP</span><b class="bad">${po.gap}</b></div>
      <div class="kpi"><span class="mut">Audit chain</span><b class="${p.audit_trail.verified?'ok':'bad'}" style="font-size:15px">${p.audit_trail.verified?'verified ✓':'BROKEN'}</b></div>`;
    const bd=s=>`<span class="b b${s}">${s}</span>`;
    $('#ev-controls').innerHTML='<tr><th>Control</th><th>Status</th><th>Detail</th></tr>'+
      p.controls.map(c=>`<tr><td><b>${c.title}</b></td><td>${bd(c.status)}</td><td class=mut>${c.detail}</td></tr>`).join('');
    $('#ev-fw').innerHTML='<tr><th>Framework</th><th>Coverage</th><th>Clauses</th></tr>'+
      Object.entries(p.frameworks).map(([k,v])=>`<tr><td>${k}</td><td>${bd(v.coverage)}</td><td class=mut>${v.clauses.map(c=>c.clause+' '+bd(c.status)).join('<br>')}</td></tr>`).join('');
  }
  if(id==='agents'){const a=await j('/api/admin/agents');
    $('#agents-t').innerHTML='<tr><th>Agent</th><th>Device</th><th>OS</th><th>Status</th><th>Last seen</th><th></th></tr>'+
      (a.map(x=>`<tr><td>${x.agent_id}</td><td>${x.device_name||'—'}</td><td>${x.os||'—'}</td>
      <td>${x.status==='active'?'<span class=ok>active</span>':'<span class=bad>revoked</span>'}</td>
      <td class=mut>${(x.last_seen||'—').slice(0,19)}</td>
      <td>${x.status==='active'?`<button class=act onclick="rotate('${x.agent_id}')">Rotate</button> <button class=act onclick="revoke('${x.agent_id}')">Revoke</button>`:''}</td></tr>`).join('')||'<tr><td class=mut colspan=6>No agents enrolled</td></tr>');
  }
  if(id==='audit'){const a=await j('/api/admin/audit');
    $('#chain').innerHTML=a.verified?'<span class="ok">chain verified ✓</span>':'<span class="bad">TAMPERED at #'+a.broken_at+'</span>';
    $('#audit-t').innerHTML='<tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th></tr>'+
      (a.entries.map(e=>`<tr><td class=mut>${(e.ts||'').slice(0,19)}</td><td>${e.actor}</td><td>${e.action}</td><td class=mut>${e.target||''}</td></tr>`).join('')||'<tr><td class=mut colspan=4>No entries</td></tr>');
  }
  if(id==='settings'){const s=await j('/api/admin/settings');
    const keys=[['redact_secrets','Mask secrets (true/false)'],['redact_pii','Mask PII/PHI/PCI (true/false)'],
      ['require_https','Require HTTPS to collector (true/false)'],['retention_days','Retention days'],
      ['large_prompt_tokens','Large-prompt token threshold'],['model_allow','Allowed models (comma)'],
      ['model_deny','Denied models (comma)'],['consent_banner','Employee consent/notice text']];
    $('#settings-t').innerHTML='<tr><th>Setting</th><th>Value</th></tr>'+keys.map(([k,label])=>
      `<tr><td>${label}<br><span class=mut style="font-size:11px">${k}</span></td><td><input data-k="${k}" value="${s[k]??''}" style="width:100%;background:#0e1220;color:#fff;border:1px solid var(--bd);border-radius:6px;padding:6px"></td></tr>`).join('');
  }
}
async function revoke(id){await fetch('/api/admin/agents/'+id+'/revoke',{method:'POST'});load('agents')}
async function rotate(id){const r=await(await fetch('/api/admin/agents/'+id+'/rotate',{method:'POST'})).json();
  if(r.agent_key)prompt('New agent key (give to that machine, shown once):',r.agent_key);load('agents')}
async function erase(){const u=$('#erase-user').value,d=$('#erase-device').value;
  if(!u&&!d)return alert('Enter a user or device');
  if(!confirm('Permanently delete all interactions for '+(u||d)+'?'))return;
  const r=await(await fetch('/api/admin/erase',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sys_user:u,device_name:d})})).json();
  alert('Erased '+r.removed+' interaction(s)')}
async function saveSettings(){const p={};document.querySelectorAll('#settings-t input').forEach(i=>p[i.dataset.k]=i.value);
  await fetch('/api/admin/settings',{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(p)});alert('Saved')}
load('compliance');
</script></body></html>"""
