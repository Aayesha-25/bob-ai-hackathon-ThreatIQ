"""
bluf_generator.py — LLM-driven BLUF (Bottom Line Up Front) report generator.

Design: LLM-first with deterministic fallback
----------------------------------------------
The LLM produces richer, context-aware narrative than any template can. It
receives the full cluster context — risk score, ATT&CK techniques, every alert's
title and raw text — and returns a structured JSON report.

The deterministic fallback guarantees commanders always receive a report:
if both LLM providers are down (llm_client raises RuntimeError) or the response
cannot be parsed as valid JSON, the fallback builds the same BlufReport fields
directly from cluster data. No garbage, no empty fields, no crash.

This module is per-cluster and on-demand — callers invoke generate_bluf() for a
single cluster when a report is needed, not as a batch sweep over all clusters.
"""

import json
from datetime import datetime, timezone

from app.models.alert import BlufReport, CorrelatedCluster, NormalizedAlert
from app.services.llm_client import generate

# Maximum characters of raw_text included per alert in the prompt.
# Caps prompt length regardless of cluster size while keeping every alert
# represented as evidence — no alerts are dropped, only truncated.
RAW_TEXT_PROMPT_LIMIT = 300

# Deterministic recommended_action strings, keyed by risk_level value.
# Used by both the fallback and as a hint in the prompt schema.
_RECOMMENDED_ACTIONS: dict[str, str] = {
    "CRITICAL": "Immediate isolation and incident response",
    "HIGH":     "Escalate to SOC lead for investigation",
    "MEDIUM":   "Monitor and log for pattern recurrence",
    "LOW":      "Review during next scheduled triage",
    "LIKELY_FALSE_POSITIVE": "Review during next scheduled triage",
}


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _resolve_alerts(
    cluster: CorrelatedCluster,
    alerts_by_id: dict[str, NormalizedAlert],
) -> list[NormalizedAlert]:
    """
    Return the NormalizedAlert objects that belong to this cluster.

    Alert IDs present in the cluster but absent from alerts_by_id are silently
    skipped — guards against partial datasets or test stubs.
    """
    return [alerts_by_id[aid] for aid in cluster.alert_ids if aid in alerts_by_id]


def _build_system_prompt() -> str:
    """Return the fixed analyst persona instruction sent to the LLM."""
    return (
        "You are a defense intelligence analyst producing a BLUF (Bottom Line Up Front) "
        "report for a commander. Be concise, factual, and actionable. Commanders need "
        "the conclusion in the first line, not buried in analysis."
    )


def _build_user_prompt(
    cluster: CorrelatedCluster,
    alerts: list[NormalizedAlert],
) -> str:
    """
    Build the user-facing prompt containing full cluster context and a strict
    JSON schema instruction.

    Each alert's raw_text is truncated to RAW_TEXT_PROMPT_LIMIT characters so
    prompt length stays bounded regardless of cluster size. All alerts are
    included — none are dropped.
    """
    # --- Cluster metadata block ---
    techniques_text = "\n".join(
        f"  - {t['technique_id']} {t['technique_name']} "
        f"(confidence {t['confidence']:.0%}, via {t['method']})"
        for t in cluster.attack_techniques
    ) or "  None identified"

    cluster_block = (
        f"CLUSTER ID: {cluster.cluster_id}\n"
        f"Risk Score: {cluster.risk_score}/100\n"
        f"Risk Level: {cluster.risk_level}\n"
        f"Correlation Basis: {', '.join(cluster.correlation_basis)}\n"
        f"Correlation Confidence: {cluster.confidence:.0%}\n"
        f"ATT&CK Techniques:\n{techniques_text}\n"
    )

    # --- Alert evidence block (all alerts, raw_text capped at 300 chars) ---
    alert_lines = []
    for i, alert in enumerate(alerts, start=1):
        raw_preview = alert.raw_text[:RAW_TEXT_PROMPT_LIMIT]
        if len(alert.raw_text) > RAW_TEXT_PROMPT_LIMIT:
            raw_preview += "…"
        alert_lines.append(
            f"{i}. [{alert.source}] {alert.timestamp.isoformat()} — {alert.title}\n"
            f"   {raw_preview}"
        )
    evidence_block = "\n".join(alert_lines)

    # --- JSON schema instruction ---
    schema_instruction = """
Respond with ONLY a JSON object — no markdown fences, no prose before or after.
The JSON must contain exactly these keys:

{
  "bottom_line": "<one sentence: the most important conclusion for a commander>",
  "threat_classification": "<brief threat category, e.g. 'C2 Beaconing' or 'Credential Brute Force'>",
  "confidence_percent": <integer 0-100>,
  "attack_techniques_summary": ["<short human-readable description of each mapped technique>"],
  "recommended_action": "<single actionable directive>",
  "supporting_evidence": ["<one brief item per alert that supports the assessment>"]
}"""

    return f"{cluster_block}\nALERT EVIDENCE:\n{evidence_block}\n{schema_instruction}"


def _parse_llm_response(raw: str) -> dict | None:
    """
    Defensively extract the six LLM-owned BlufReport fields from the raw response.

    Strips markdown code fences if present — LLMs frequently wrap JSON in
    ```json ... ``` even when instructed not to. Falls back to None on any
    parse error or missing required key, so the caller can route to the
    deterministic fallback without raising.
    """
    # Strip ```json ... ``` or ``` ... ``` fences
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("```", 2)[-1] if text.count("```") >= 2 else text
        # Remove leading language tag (e.g. "json\n")
        if "\n" in text:
            first_line, rest = text.split("\n", 1)
            if first_line.strip().lower() in ("json", ""):
                text = rest
        text = text.rsplit("```", 1)[0].strip()

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None

    required_keys = {
        "bottom_line", "threat_classification", "confidence_percent",
        "attack_techniques_summary", "recommended_action", "supporting_evidence",
    }
    if not required_keys.issubset(data.keys()):
        return None

    return data


def _fallback_bluf(
    cluster: CorrelatedCluster,
    alerts: list[NormalizedAlert],
) -> dict:
    """
    Build all six LLM-owned BlufReport fields deterministically from cluster data.

    Called when both LLM providers fail OR when the LLM response cannot be
    parsed. Always returns a complete, valid dict — commanders always get a
    report, regardless of API availability.
    """
    # threat_classification: join matched technique names, or "Unclassified"
    technique_names = [
        t["technique_name"]
        for t in cluster.attack_techniques
        if t.get("technique_name") and t.get("technique_name") != "Unclassified"
    ]
    threat_classification = ", ".join(dict.fromkeys(technique_names)) or "Unclassified"

    # attack_techniques_summary: one readable string per technique
    techniques_summary = [
        f"{t['technique_id']} — {t['technique_name']}"
        for t in cluster.attack_techniques
    ] or ["No techniques identified"]

    # recommended_action: tiered by risk level
    risk_value = cluster.risk_level if isinstance(cluster.risk_level, str) else (
        cluster.risk_level.value if cluster.risk_level else "LOW"
    )
    recommended_action = _RECOMMENDED_ACTIONS.get(risk_value, _RECOMMENDED_ACTIONS["LOW"])

    return {
        "bottom_line": (
            f"Cluster {cluster.cluster_id}: {cluster.risk_level} risk "
            f"(score {cluster.risk_score}/100) — {threat_classification} activity detected."
        ),
        "threat_classification": threat_classification,
        "confidence_percent": int(cluster.confidence * 100),
        "attack_techniques_summary": techniques_summary,
        "recommended_action": recommended_action,
        "supporting_evidence": [a.title for a in alerts],
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_bluf(
    cluster: CorrelatedCluster,
    alerts_by_id: dict[str, NormalizedAlert],
) -> BlufReport:
    """
    Generate a BLUF report for a single correlated, scored, ATT&CK-mapped cluster.

    Parameters
    ----------
    cluster:
        A fully processed CorrelatedCluster — risk_score, risk_level, and
        attack_techniques must already be populated before calling this.
    alerts_by_id:
        Mapping of alert_id → NormalizedAlert for evidence text lookup.

    Returns
    -------
    A BlufReport in all cases. If both LLM providers fail or the response cannot
    be parsed, the report is built deterministically from cluster data instead.
    """
    alerts = _resolve_alerts(cluster, alerts_by_id)

    # --- Attempt LLM generation ---
    llm_fields: dict | None = None
    try:
        raw_response = generate(
            prompt=_build_user_prompt(cluster, alerts),
            system=_build_system_prompt(),
        )
        llm_fields = _parse_llm_response(raw_response)
        if llm_fields is None:
            print(
                f"BLUF: LLM response for {cluster.cluster_id} failed JSON parse — "
                "using deterministic fallback"
            )
    except RuntimeError as e:
        print(f"BLUF: LLM unavailable for {cluster.cluster_id} ({e}) — using deterministic fallback")

    # --- Fall back to deterministic if LLM path didn't produce valid fields ---
    fields = llm_fields if llm_fields is not None else _fallback_bluf(cluster, alerts)

    return BlufReport(
        # Always set in code — never sourced from the LLM
        report_id=f"BLUF-{cluster.cluster_id}",
        cluster_id=cluster.cluster_id,
        generated_at=datetime.now(timezone.utc),
        # LLM-populated or deterministic fallback
        bottom_line=fields["bottom_line"],
        threat_classification=fields["threat_classification"],
        confidence_percent=int(fields["confidence_percent"]),
        attack_techniques_summary=fields["attack_techniques_summary"],
        recommended_action=fields["recommended_action"],
        supporting_evidence=fields["supporting_evidence"],
    )
