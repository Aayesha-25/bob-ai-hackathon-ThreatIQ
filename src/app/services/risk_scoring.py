"""
risk_scoring.py — Weighted point-based risk scoring for correlated alert clusters.

Philosophy
----------
Correlation groups alerts by *what* they share (indicator, entity, time).
Scoring answers *how dangerous* each cluster is by accumulating evidence points
from multiple independent signals.

Each signal is worth a fixed number of points (a named constant). The rationale
for each weight is documented alongside the constant so the scoring model is
auditable and tunable without touching any logic.

The final score is clamped to [0, 100] and mapped to a RiskLevel bucket.
"""

from datetime import datetime, timedelta, timezone

from app.models.alert import CorrelatedCluster, NormalizedAlert, RiskLevel
from app.services.ingestion import load_allowlist, load_known_bad_indicators

# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------

# A confirmed known-bad indicator (IP, domain, or hash on the threat-intel
# blocklist) is the strongest single signal available — it means at least one
# tool has already attributed this IOC to malicious activity. Outweighs all
# other individual signals combined (except source diversity across many sources).
KNOWN_BAD_INDICATOR_POINTS = 30

# Each *distinct* source that flags the same cluster is an independent sensor
# corroborating the threat. Applied as a multiplier so that a cluster seen by
# SIEM + firewall + network_sensor scores much higher than one seen by a single
# source — real threats tend to leave traces across multiple detection layers.
SOURCE_DIVERSITY_POINTS = 10

# Recent activity means the threat may still be active and actionable. Older
# activity is still worth investigating, but urgency is lower.
RECENCY_POINTS = 15

# How far back "recent" means. Alerts within this many hours of now are treated
# as potentially live activity.
RECENCY_WINDOW_HOURS = 24

# The source's own severity label is a noisy-but-useful hint. CRITICAL outweighs
# HIGH because the source tool presumably applied its own triage logic. Applied
# once per cluster regardless of how many alerts carry the label — repeated
# detections of the same rule firing are not independent evidence (see below).
CRITICAL_SEVERITY_HINT_POINTS = 10

# Applied only if no CRITICAL alert exists in the cluster. One-or-the-other per
# cluster: severity_hint is a single-source label, not independently verified.
# Stacking the same severity hint across duplicate alerts would inflate scores
# from retriggers rather than from real additional evidence.
HIGH_SEVERITY_HINT_POINTS = 5

# If any indicator in the cluster appears on the allowlist (known-benign
# infrastructure), subtract points — the cluster is more likely noise.
# Negative value; added to the running total like any other term.
ALLOWLIST_PENALTY = -25

# ---------------------------------------------------------------------------
# Risk-level thresholds (applied to the final clamped score)
# ---------------------------------------------------------------------------

RISK_CRITICAL_THRESHOLD = 80  # >= 80 → CRITICAL
RISK_HIGH_THRESHOLD = 60      # >= 60 → HIGH
RISK_MEDIUM_THRESHOLD = 40    # >= 40 → MEDIUM
RISK_LOW_THRESHOLD = 20       # >= 20 → LOW
                               # <  20 → LIKELY_FALSE_POSITIVE


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _resolve_alerts(
    cluster: CorrelatedCluster,
    alerts_by_id: dict[str, NormalizedAlert],
) -> list[NormalizedAlert]:
    """
    Return the NormalizedAlert objects that belong to this cluster.

    Alert IDs present in the cluster but missing from alerts_by_id are silently
    skipped — this guards against partial datasets or test stubs without crashing
    the whole scoring run.
    """
    return [alerts_by_id[aid] for aid in cluster.alert_ids if aid in alerts_by_id]


def _build_indicator_sets() -> tuple[set[str], set[str]]:
    """
    Load and flatten the known-bad and allowlist indicator files into sets.

    Returns a tuple of (known_bad, allowlisted) where each is a flat set[str]
    of indicator values (IPs, domains, hashes mixed together). Set membership
    is O(1), so these are built once per score_clusters() call and reused for
    every cluster — not reloaded per cluster.

    Uses .get(key, []) on every list key so the function degrades gracefully if
    the JSON files gain or lose keys in the future. The allowlist's "note" string
    key is never iterated.
    """
    known_bad_raw = load_known_bad_indicators()
    known_bad: set[str] = (
        set(known_bad_raw.get("ips", []))
        | set(known_bad_raw.get("domains", []))
        | set(known_bad_raw.get("hashes", []))
    )

    allowlist_raw = load_allowlist()
    allowlisted: set[str] = (
        set(allowlist_raw.get("ips", []))
        | set(allowlist_raw.get("domains", []))
        | set(allowlist_raw.get("hashes", []))
    )

    return known_bad, allowlisted


def _score_cluster(
    alerts: list[NormalizedAlert],
    known_bad: set[str],
    allowlisted: set[str],
) -> tuple[int, dict[str, int]]:
    """
    Compute the raw risk score and per-signal breakdown for one cluster.

    Signals applied in order (each is a named constant; see module top):

    1. Known-bad indicator (+30)
       Strongest signal. If any alert's indicator is on the threat-intel
       blocklist the cluster is almost certainly malicious. Applied once per
       cluster — the indicator either is or isn't known-bad.

    2. Source diversity (+10 per distinct source)
       Each distinct sensor type independently corroborating the same activity
       is real additional evidence. Three different systems flagging the same
       cluster is far more significant than one system firing three times.

    3. Recency (+15)
       Alerts within RECENCY_WINDOW_HOURS of now may represent live, actionable
       threats. Applied once — the cluster is either currently active or it isn't.

    4. Severity hint (+10 if any CRITICAL, else +5 if any HIGH)
       Source severity labels are noisy and unverified. Applied once per cluster
       regardless of how many alerts carry the label — repeated firings of the
       same detection rule are not independent evidence, just the same signal
       counted multiple times. CRITICAL is checked first; HIGH only applies if
       no CRITICAL alert exists in the cluster.

    5. Allowlist penalty (-25)
       If any indicator is on the known-benign list, subtract points. The cluster
       may be legitimate infrastructure that tripped a detection rule.

    Returns
    -------
    (clamped_score, breakdown) where:
    - clamped_score is the final risk_score clamped to [0, 100].
    - breakdown holds the raw, unclamped contribution of each signal.
      The breakdown values intentionally do NOT reflect clamping — their sum
      may exceed 100 or go below 0. This lets a judge or UI see the true
      signal weights and confirm that clamping occurred (e.g. raw total 115
      becomes score 100, but breakdown reveals the full picture).
    """
    breakdown: dict[str, int] = {
        "known_bad_indicator": 0,
        "source_diversity":    0,
        "recency":             0,
        "severity_hint":       0,
        "allowlist_penalty":   0,
    }

    # --- Signal 1: Known-bad indicator ---
    if any(a.indicator in known_bad for a in alerts):
        breakdown["known_bad_indicator"] = KNOWN_BAD_INDICATOR_POINTS

    # --- Signal 2: Source diversity ---
    distinct_sources = {a.source for a in alerts}
    breakdown["source_diversity"] = len(distinct_sources) * SOURCE_DIVERSITY_POINTS

    # --- Signal 3: Recency ---
    now = datetime.now(timezone.utc)
    recency_window = timedelta(hours=RECENCY_WINDOW_HOURS)

    def _as_aware(ts: datetime) -> datetime:
        """Attach UTC to a naive timestamp so timedelta subtraction never raises."""
        return ts if ts.tzinfo is not None else ts.replace(tzinfo=timezone.utc)

    if any(now - _as_aware(a.timestamp) <= recency_window for a in alerts):
        breakdown["recency"] = RECENCY_POINTS

    # --- Signal 4: Severity hint (one bonus per cluster, CRITICAL takes priority) ---
    hints = {
        (a.severity_hint.upper() if a.severity_hint is not None else None)
        for a in alerts
    }
    if "CRITICAL" in hints:
        breakdown["severity_hint"] = CRITICAL_SEVERITY_HINT_POINTS
    elif "HIGH" in hints:
        breakdown["severity_hint"] = HIGH_SEVERITY_HINT_POINTS

    # --- Signal 5: Allowlist penalty ---
    if any(a.indicator in allowlisted for a in alerts):
        breakdown["allowlist_penalty"] = ALLOWLIST_PENALTY  # negative constant

    # Sum the raw signal contributions, then clamp only the final total.
    # The breakdown values are left unclamped so their sum reflects true signal
    # weight — useful for explaining why a score was capped or floored.
    raw_total = sum(breakdown.values())
    clamped_score = max(0, min(100, raw_total))
    return clamped_score, breakdown


def _score_to_level(score: int) -> RiskLevel:
    """
    Map a clamped integer score to a RiskLevel bucket.

    Thresholds are named constants (RISK_*_THRESHOLD) so they can be adjusted
    without touching this function. Evaluated highest-first so the first
    matching threshold wins.
    """
    if score >= RISK_CRITICAL_THRESHOLD:
        return RiskLevel.CRITICAL
    if score >= RISK_HIGH_THRESHOLD:
        return RiskLevel.HIGH
    if score >= RISK_MEDIUM_THRESHOLD:
        return RiskLevel.MEDIUM
    if score >= RISK_LOW_THRESHOLD:
        return RiskLevel.LOW
    return RiskLevel.LIKELY_FALSE_POSITIVE


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def score_clusters(
    clusters: list[CorrelatedCluster],
    alerts_by_id: dict[str, NormalizedAlert],
) -> list[CorrelatedCluster]:
    """
    Fill in risk_score and risk_level for each cluster.

    Parameters
    ----------
    clusters:
        Output of correlate() — clusters with risk_score=0 and risk_level=None.
    alerts_by_id:
        Mapping of alert_id → NormalizedAlert for fast lookup. Build this from
        the same list[NormalizedAlert] passed to correlate(), e.g.:
            alerts_by_id = {a.alert_id: a for a in alerts}

    Returns
    -------
    A new list of CorrelatedCluster objects with risk_score and risk_level
    populated. All other fields (cluster_id, alert_ids, correlation_basis,
    confidence) are carried over unchanged. Input clusters are not mutated —
    new instances are returned via model_copy().
    """
    known_bad, allowlisted = _build_indicator_sets()

    scored: list[CorrelatedCluster] = []
    for cluster in clusters:
        alerts = _resolve_alerts(cluster, alerts_by_id)
        risk_score, risk_breakdown = _score_cluster(alerts, known_bad, allowlisted)
        risk_level = _score_to_level(risk_score)
        scored.append(
            cluster.model_copy(update={
                "risk_score":     risk_score,
                "risk_level":     risk_level,
                "risk_breakdown": risk_breakdown,
            })
        )

    return scored
