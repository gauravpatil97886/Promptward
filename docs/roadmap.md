# Promptward — Roadmap

> Strategy in one line: **don't compete with LLM gateways (LiteLLM, Portkey, Cloudflare AI Gateway) on routing — own the layer they can't reach: governance of people using their own individual Claude accounts, with auditor-grade compliance evidence.** See [`docs/security.md`](security.md) and the README's "Why not just use an LLM gateway" section.

## Where we are (done)

- Thin fail-open agent → central collector → token-gated dashboard + admin panel.
- Detection (injection / credential / exfiltration) + DLP (PII/PHI/PCI, Luhn) with redaction at agent **and** collector.
- Tamper-evident hash-chained audit log; runtime settings; GDPR erasure + retention.
- **Signed, framework-mapped compliance evidence packs** (JSON + print-to-PDF HTML), surfaced in CLI (`pw evidence`), admin API, and an admin **Evidence pack** tab. *This is the current differentiator.*

## Guiding priorities

1. **Widen the moat** (compliance artifact + shadow-AI governance) before adding breadth.
2. **Close the credibility gaps** a security team will probe first (RBAC, DLP quality).
3. **Never overstate** — Promptward is monitoring, not hard enforcement (the `ANTHROPIC_BASE_URL` path is bypassable). Enforcement is a deliberate, later, opt-in step.

---

## Phase A — Harden the foundation (next, ~4–6 weeks)

| Item | Why | Acceptance |
|------|-----|-----------|
| **Per-user accounts + RBAC** (admin / analyst / read-only) | Single shared dashboard token is the #1 security gap; it holds everyone's prompts. Flips the evidence pack's `access-control` control from PARTIAL → PASS. | Login with per-user creds; role gates admin mutations; audit log records the real user, not an IP. |
| **OIDC / SAML SSO** | Enterprises require it; identity-aware logging beats device-only. | Okta/Azure AD/Google login; sessions tied to SSO identity. |
| **Evidence pack polish** | It's the headline — make it undeniable. | Period filtering actually scopes the register; per-pack signing key documented + rotatable; "verify" tab in the admin UI. |
| **Doc refresh** | `CLAUDE.md` still describes the old flat layout / non-local-IP rule. | CLAUDE.md matches the agent/server/common split and current detection rules. |

## Phase B — Sharpen detection & DLP (~6–10 weeks)

| Item | Why | Acceptance |
|------|-----|-----------|
| **Presidio-grade DLP** (swap/augment regex) | Matches LiteLLM's strongest *free* feature; multi-entity, multi-language; far fewer false positives. | `compliance.scan` backed by Presidio when available, regex fallback; benchmark vs current on a fixture set. |
| **Async semantic detection (Claude-as-judge)** | Beats regex/Lakera-config guardrails on intent; runs **off the hot path** so latency stays zero — our fail-open architecture makes this natural. | Optional collector-side analyzer; configurable model; graceful degradation when no key. |
| **Behavioral baselines** | Per-user/-team anomaly (exfil-pattern spike, off-hours bulk prompting) — where ML actually earns its place. | Rolling stats per identity; alert on deviation. |

## Phase C — Expand the category (quarter+)

| Item | Why |
|------|-----|
| **Cost & productivity analytics** | CFO-facing buyer; easier sell on data we already capture (spend per team/model, ROI, spend anomalies). |
| **Multi-provider** (OpenAI / Gemini / Copilot) | Same shadow-AI problem exists everywhere; the forwarder is already generic. Bigger TAM than Claude-only. |
| **Optional enforcement mode** | `auto-block HIGH → 403` + **MDM-managed config** so `ANTHROPIC_BASE_URL` can't be trivially unset. Turns "visibility" into "control" — opt-in, clearly bounded. |
| **Postgres backend** | Org-scale central deployment (drop-in for the SQLite store). |
| **SIEM/SOAR depth** | Beyond CSV/webhook: native Splunk/Sentinel/Elastic connectors. |

---

## Validation gate (before investing in Phase C breadth)

Talk to 5–10 target orgs (on **individual** Claude accounts, facing an audit). Confirm they'd pay for the **evidence artifact** specifically. If the answer is "we'd just upgrade to Anthropic Enterprise," the wedge is closing — pivot to **multi-provider** faster. Track this as a real decision, not an assumption.

## Explicitly *not* doing

- Competing on routing / load-balancing / 100-provider breadth as a primary feature (gateways win that).
- Marketing regex detection as "threat prevention" (it's a tripwire; semantic layer is the real detector).
- Claiming insider-threat *prevention* while the proxy path is bypassable.
