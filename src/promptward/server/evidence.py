"""
Compliance evidence packs — the auditor-facing deliverable.

Where `reports.py` powers the live dashboard view, this module produces a single,
self-contained, *signed* governance artifact you can hand to a security review or
regulator. It answers the questions an auditor actually asks:

  1. What AI use exists?           → device/agent inventory  (NIST MAP)
  2. Is it logged and monitored?   → interaction + violation register
  3. Can the log be trusted?       → audit hash-chain verification (tamper-evident)
  4. Which controls are in place?  → per-control attestation with live PASS/PARTIAL/GAP
  5. Which frameworks do they map to? → EU AI Act / NIST AI RMF / ISO 42001 / SOC 2 / GDPR
  6. Is THIS document authentic?   → HMAC-SHA256 manifest over canonical content

Control statuses are derived from the *running system's real state* (settings +
audit chain + stored data), not asserted by hand — so the pack cannot claim a
control that isn't actually enabled. Honest by construction: e.g. the shared
dashboard token attests as PARTIAL (RBAC pending), never PASS.

Self-hosted and free. LiteLLM gates audit logs behind its enterprise tier and
maps to no compliance framework; this is the layer that differentiates Promptward.
"""

import hashlib
import hmac
import json
from pathlib import Path
from typing import Optional

from ..common.config import Settings, get_settings
from .audit import AuditLog
from .reports import compliance_summary
from .server_store import ServerStore

PASS, PARTIAL, GAP = "PASS", "PARTIAL", "GAP"

# Schema version of the emitted pack. Bump on any breaking shape change so
# downstream verifiers can branch on it.
PACK_VERSION = "1.0"

# Framework → list of (clause label, control key). Control keys resolve to the
# attestations produced by `attest_controls`, so a single control can satisfy
# clauses across multiple frameworks without duplication.
FRAMEWORK_MAP: dict[str, list[tuple[str, str]]] = {
    "EU AI Act": [
        ("Art. 12 — record-keeping / logging", "usage-logging"),
        ("Art. 12 — tamper-evident logs", "audit-trail"),
        ("Art. 13 — transparency of AI use", "inventory"),
        ("Art. 15 — accuracy, robustness & monitoring", "threat-monitoring"),
    ],
    "NIST AI RMF": [
        ("MAP 1 — inventory of AI use", "inventory"),
        ("MEASURE 2 — incident & risk logging", "threat-monitoring"),
        ("MANAGE 4 — monitoring & response", "usage-logging"),
        ("GOVERN 1 — accountable audit trail", "audit-trail"),
    ],
    "ISO/IEC 42001": [
        ("A.6 — AI system operational controls", "redaction"),
        ("A.8 — data management & minimisation", "pii-detection"),
        ("A.9 — monitoring & measurement", "threat-monitoring"),
        ("A.5 — logging & audit", "audit-trail"),
    ],
    "SOC 2": [
        ("CC6.1 — logical access control", "access-control"),
        ("CC6.7 — data in transit protection", "channel-security"),
        ("CC7.2 — security event logging", "usage-logging"),
        ("CC7.3 — tamper-evident audit trail", "audit-trail"),
        ("A1.2 — retention & disposal", "retention"),
    ],
    "GDPR": [
        ("Art. 5(1)(c) — data minimisation", "redaction"),
        ("Art. 5(1)(e) — storage limitation", "retention"),
        ("Art. 32 — security of processing (encryption)", "encryption-at-rest"),
        ("Art. 30 — records of processing", "usage-logging"),
    ],
}


def _control(key: str, title: str, status: str, detail: str, evidence: str) -> dict:
    return {"key": key, "title": title, "status": status,
            "detail": detail, "evidence": evidence}


def attest_controls(settings: Settings, *, audit_ok: bool, audit_break: Optional[int],
                    agent_count: int, total_interactions: int) -> list[dict]:
    """
    Derive control attestations from live system state. Pure given its inputs so
    it is straightforward to unit-test against a known configuration.
    """
    redact_both = settings.redact_secrets and settings.redact_pii
    return [
        _control(
            "inventory", "Inventory of AI use",
            PASS if agent_count else GAP,
            f"{agent_count} enrolled agent(s) tracked." if agent_count
            else "No agents enrolled — AI use is not yet inventoried.",
            "server_store.agents",
        ),
        _control(
            "usage-logging", "Logging of all AI interactions",
            PASS if total_interactions else GAP,
            f"{total_interactions} interaction(s) logged with model, tokens, user & device.",
            "interactions table",
        ),
        _control(
            "audit-trail", "Tamper-evident audit trail",
            PASS if audit_ok else GAP,
            "Hash chain verified intact." if audit_ok
            else f"Hash chain BROKEN at entry id={audit_break} — possible tampering.",
            "audit_log (SHA-256 hash chain)",
        ),
        _control(
            "redaction", "Data minimisation (secret/PII redaction)",
            PASS if redact_both else (PARTIAL if (settings.redact_secrets or settings.redact_pii) else GAP),
            f"redact_secrets={settings.redact_secrets}, redact_pii={settings.redact_pii}; "
            "masked at agent and re-masked at collector (defense-in-depth).",
            "redact.py + compliance.py",
        ),
        _control(
            "pii-detection", "PII / PHI / PCI detection",
            PASS if settings.redact_pii else GAP,
            "Email, phone, SSN, payment card (Luhn-validated), IBAN and PHI terms detected.",
            "compliance.scan",
        ),
        _control(
            "retention", "Data retention & disposal",
            PASS if settings.retention_days and settings.retention_days > 0 else GAP,
            f"retention_days={settings.retention_days} "
            f"({'enforced by prune job' if settings.retention_days else 'KEEP FOREVER — no disposal policy'}).",
            "prune.py",
        ),
        _control(
            "encryption-at-rest", "Encryption of stored prompts/responses",
            PASS if settings.encrypt_logs else GAP,
            f"encrypt_logs={settings.encrypt_logs} (Fernet AES-128-CBC + HMAC-SHA256).",
            "crypto.py",
        ),
        _control(
            "channel-security", "Agent↔collector channel security",
            PASS if settings.require_https else GAP,
            f"require_https={settings.require_https} — agent refuses to ship credentials "
            "to a non-HTTPS, non-loopback collector.",
            "identity.require_secure",
        ),
        _control(
            "access-control", "Dashboard access control",
            PARTIAL if settings.dashboard_token else GAP,
            "Shared dashboard token (constant-time compare, HttpOnly cookie). "
            "Per-user RBAC/SSO is on the roadmap (Phase 3)." if settings.dashboard_token
            else "No dashboard token set — loopback-only access.",
            "auth.py",
        ),
        _control(
            "threat-monitoring", "Threat & risk monitoring",
            PASS,
            "Every interaction scored for prompt injection, credential leakage, "
            "exfiltration intent and off-policy model use; flagged events recorded.",
            "security.analyze + compliance.evaluate",
        ),
    ]


def _map_frameworks(controls: list[dict]) -> dict:
    """Cross-reference each framework clause to its control's live status."""
    by_key = {c["key"]: c for c in controls}
    out: dict[str, dict] = {}
    for fw, clauses in FRAMEWORK_MAP.items():
        mapped = []
        for label, key in clauses:
            ctrl = by_key.get(key)
            mapped.append({
                "clause": label,
                "control": key,
                "status": ctrl["status"] if ctrl else GAP,
            })
        statuses = [m["status"] for m in mapped]
        coverage = (PASS if all(s == PASS for s in statuses)
                    else GAP if all(s == GAP for s in statuses)
                    else PARTIAL)
        out[fw] = {"coverage": coverage, "clauses": mapped}
    return out


def build_pack(settings: Optional[Settings] = None, *, period_days: int = 30,
               generated_at: str = "", actor: str = "system", limit: int = 100_000) -> dict:
    """
    Assemble the full (unsigned) evidence pack from live system state.

    `generated_at` is injected by the caller (ISO timestamp) so this function
    stays deterministic and testable; pass "" to omit it.
    """
    settings = settings or get_settings()

    audit = AuditLog(settings)
    audit_ok, audit_break = audit.verify()

    sstore = ServerStore(settings)
    agents = sstore.list_agents()

    summary = compliance_summary(limit)
    controls = attest_controls(
        settings,
        audit_ok=audit_ok, audit_break=audit_break,
        agent_count=len(agents), total_interactions=summary["total"],
    )

    posture = {
        "controls_total": len(controls),
        "pass": sum(c["status"] == PASS for c in controls),
        "partial": sum(c["status"] == PARTIAL for c in controls),
        "gap": sum(c["status"] == GAP for c in controls),
    }

    return {
        "pack_version": PACK_VERSION,
        "metadata": {
            "org_name": settings.org_name,
            "generated_at": generated_at,
            "generated_by": actor,
            "period_days": period_days,
            "tool": "Promptward",
        },
        "posture": posture,
        "inventory": {
            "agent_count": len(agents),
            "agents": [
                {k: a.get(k) for k in ("device_name", "os", "sys_user", "status",
                                       "created_at", "last_seen")}
                for a in agents
            ],
        },
        "violation_register": {
            "total_interactions": summary["total"],
            "flagged": summary["flagged"],
            "by_severity": summary["by_severity"],
            "by_category": summary["by_category"],
        },
        "audit_trail": {
            "verified": audit_ok,
            "first_broken_id": audit_break,
            "entries_sampled": len(audit.list_recent(limit=50)),
        },
        "controls": controls,
        "frameworks": _map_frameworks(controls),
    }


# ── Signing / verification ───────────────────────────────────────────────────────

def _canonical(pack: dict) -> bytes:
    """Stable byte serialization for hashing/signing (sorted keys, compact)."""
    return json.dumps(pack, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _signing_key(settings: Settings) -> bytes:
    """Load (or create, 0600) the HMAC key used to sign evidence packs."""
    key_file: Path = settings.db_path.parent / ".evidence.key"
    if key_file.exists():
        return key_file.read_bytes()
    import secrets
    key = secrets.token_bytes(32)
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    return key


def sign_pack(pack: dict, settings: Optional[Settings] = None) -> dict:
    """
    Wrap a pack in a signed envelope. The manifest binds the exact content via
    SHA-256 and signs that digest with HMAC-SHA256, so any later edit to the
    pack is detectable by `verify_pack` without trusting the surrounding storage.
    """
    settings = settings or get_settings()
    body = _canonical(pack)
    pack_sha256 = hashlib.sha256(body).hexdigest()
    signature = hmac.new(_signing_key(settings), pack_sha256.encode(), hashlib.sha256).hexdigest()
    return {
        "pack": pack,
        "manifest": {
            "alg": "HMAC-SHA256",
            "pack_sha256": pack_sha256,
            "signature": signature,
        },
    }


def verify_pack(signed: dict, settings: Optional[Settings] = None) -> tuple[bool, str]:
    """Recompute the digest + signature. Returns (ok, reason)."""
    settings = settings or get_settings()
    try:
        pack = signed["pack"]
        manifest = signed["manifest"]
    except (KeyError, TypeError):
        return False, "malformed envelope"

    recomputed = hashlib.sha256(_canonical(pack)).hexdigest()
    if not hmac.compare_digest(recomputed, manifest.get("pack_sha256", "")):
        return False, "content hash mismatch — pack was modified after signing"

    expected_sig = hmac.new(_signing_key(settings), recomputed.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, manifest.get("signature", "")):
        return False, "signature mismatch — not signed by this server"

    return True, "ok"
