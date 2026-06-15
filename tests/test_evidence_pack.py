"""Compliance evidence pack: attestation, framework mapping, and signing."""

import httpx

from promptward.common.config import get_settings
from promptward.server import evidence, evidence_report
from promptward.server.audit import AuditLog
from promptward.server.collector import build_collector
from promptward.server.dashboard import _app as build_dashboard
from promptward.server.server_store import ServerStore


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


def test_attestation_reflects_real_state(settings):
    controls = {c["key"]: c for c in evidence.attest_controls(
        settings, audit_ok=True, audit_break=None, agent_count=2, total_interactions=5)}
    assert controls["audit-trail"]["status"] == evidence.PASS
    assert controls["inventory"]["status"] == evidence.PASS
    # Redaction is on by default → PASS.
    assert controls["redaction"]["status"] == evidence.PASS
    # Honest by construction: the test fixture disables encryption (PW_ENCRYPT_LOGS=false),
    # so the pack must report a GAP rather than over-claiming.
    assert settings.encrypt_logs is False
    assert controls["encryption-at-rest"]["status"] == evidence.GAP
    # Shared token is honestly attested as PARTIAL, never PASS (RBAC pending).
    assert controls["access-control"]["status"] == evidence.PARTIAL


def test_attestation_flags_broken_chain_and_empty_inventory(settings):
    controls = {c["key"]: c for c in evidence.attest_controls(
        settings, audit_ok=False, audit_break=7, agent_count=0, total_interactions=0)}
    assert controls["audit-trail"]["status"] == evidence.GAP
    assert "id=7" in controls["audit-trail"]["detail"]
    assert controls["inventory"]["status"] == evidence.GAP


def test_build_pack_has_frameworks_and_posture(settings):
    pack = evidence.build_pack(settings, period_days=14, generated_at="2026-06-15T00:00:00Z")
    assert pack["pack_version"] == evidence.PACK_VERSION
    assert set(pack["frameworks"]) >= {"EU AI Act", "NIST AI RMF", "ISO/IEC 42001", "SOC 2", "GDPR"}
    assert pack["posture"]["controls_total"] == len(pack["controls"])
    # Every framework clause resolves to a real attested status.
    for fw in pack["frameworks"].values():
        assert fw["coverage"] in (evidence.PASS, evidence.PARTIAL, evidence.GAP)
        assert fw["clauses"]


def test_sign_and_verify_roundtrip(settings):
    pack = evidence.build_pack(settings, generated_at="2026-06-15T00:00:00Z")
    signed = evidence.sign_pack(pack, settings)
    ok, reason = evidence.verify_pack(signed, settings)
    assert ok, reason


def test_tampered_pack_fails_verification(settings):
    pack = evidence.build_pack(settings, generated_at="2026-06-15T00:00:00Z")
    signed = evidence.sign_pack(pack, settings)
    # Forge a clean posture after signing.
    signed["pack"]["posture"]["gap"] = 0
    ok, reason = evidence.verify_pack(signed, settings)
    assert not ok
    assert "hash mismatch" in reason


def test_malformed_envelope_rejected(settings):
    ok, reason = evidence.verify_pack({"not": "a pack"}, settings)
    assert not ok and reason == "malformed envelope"


def test_html_report_renders_self_contained(settings):
    pack = evidence.build_pack(settings, generated_at="2026-06-15T00:00:00Z")
    signed = evidence.sign_pack(pack, settings)
    doc = evidence_report.render_html(signed)
    assert doc.startswith("<!DOCTYPE html>")
    assert "AI Governance Evidence Pack" in doc
    # Self-contained: no external asset references.
    assert "http://" not in doc and "src=" not in doc
    # All five frameworks + the authenticity manifest digest are present.
    for fw in ("EU AI Act", "NIST AI RMF", "ISO/IEC 42001", "SOC 2", "GDPR"):
        assert fw in doc
    assert signed["manifest"]["pack_sha256"] in doc


def test_html_report_escapes_org_name(settings, monkeypatch):
    monkeypatch.setenv("PW_ORG_NAME", "<script>alert(1)</script>")
    s = get_settings()
    pack = evidence.build_pack(s, generated_at="2026-06-15T00:00:00Z")
    doc = evidence_report.render_html(evidence.sign_pack(pack, s))
    assert "<script>alert(1)</script>" not in doc
    assert "&lt;script&gt;" in doc


async def test_admin_endpoint_generates_signed_pack(settings):
    # Seed one enrolled agent so the inventory control reports PASS.
    sstore = ServerStore(settings)
    token = sstore.rotate_enroll_token()
    col = build_collector()
    async with _client(col) as c:
        await c.post("/api/v1/enroll", json={"enroll_token": token, "device_name": "dev1", "os": "Linux"})

    dash = build_dashboard()
    headers = {"X-Dashboard-Token": "test-token"}
    async with _client(dash) as c:
        r = await c.get("/api/admin/evidence-pack?period_days=7", headers=headers)
        assert r.status_code == 200
        signed = r.json()
        assert signed["manifest"]["alg"] == "HMAC-SHA256"
        # Round-trip through the verify endpoint.
        v = await c.post("/api/admin/evidence-pack/verify", headers=headers, json=signed)
        assert v.json()["verified"] is True

    # The export must itself be recorded in the tamper-evident audit log.
    actions = {e["action"] for e in AuditLog(settings).list_recent()}
    assert "evidence.export" in actions
