"""
attack_mapping.py — MITRE ATT&CK technique mapping for correlated alert clusters.

Strategy: pattern-match first, LLM fallback second
---------------------------------------------------
Deterministic keyword matching runs first and handles the majority of clusters
whose alerts contain recognisable IOC language (PowerShell, Cobalt Strike, brute
force, etc.). This keeps the demo resilient to LLM downtime, rate-limits, and
latency — the pipeline never blocks on an external API call for clusters it can
already classify with high confidence.

The LLM fallback is invoked only for clusters that produce zero pattern matches —
the genuinely ambiguous cases where free-form reasoning adds value. Swapping in
a real LLM call requires changing only _llm_classify(); nothing else in this file
needs to change.
"""

from app.models.alert import CorrelatedCluster, NormalizedAlert

# ---------------------------------------------------------------------------
# Static ATT&CK technique pattern table
# ---------------------------------------------------------------------------
# Each entry: (keyword_to_match, technique_id, technique_name)
#
# Keywords are matched as substrings against the lowercased concatenation of an
# alert's title and raw_text. A cluster accumulates all distinct technique IDs
# matched across its alerts — multiple techniques per cluster are valid.
#
# Ordering within a parent group (e.g. T1071 before T1071.001) doesn't matter
# for correctness: sub-technique suppression in _pattern_match() removes a
# parent if any of its sub-techniques also matched.
# ---------------------------------------------------------------------------
TECHNIQUE_PATTERNS: list[tuple[str, str, str]] = [
    # Execution — scripting
    ("powershell",          "T1059.001", "PowerShell"),

    # Command & Control — application layer (sub-technique first, parent second)
    ("cobalt strike",       "T1071.001", "Application Layer Protocol: Web Protocols"),
    ("beacon",              "T1071.001", "Application Layer Protocol: Web Protocols"),
    ("outbound connection", "T1071",     "Application Layer Protocol"),
    ("c2",                  "T1071",     "Application Layer Protocol"),

    # Persistence — autostart execution
    ("registry",            "T1547",     "Boot or Logon Autostart Execution"),
    ("persistence",         "T1547",     "Boot or Logon Autostart Execution"),

    # Credential Access — brute force
    ("auth fail",           "T1110",     "Brute Force"),
    ("brute force",         "T1110",     "Brute Force"),
    ("ssh",                 "T1110",     "Brute Force"),

    # Reconnaissance — active scanning
    ("port scan",           "T1595",     "Active Scanning"),
]

# Confidence assigned to every pattern-match result.
# High but not 1.0 — a keyword hit confirms relevance, not confirmed execution.
PATTERN_MATCH_CONFIDENCE = 0.85


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
    skipped — guards against partial datasets or test stubs without crashing the
    whole mapping run.
    """
    return [alerts_by_id[aid] for aid in cluster.alert_ids if aid in alerts_by_id]


def _suppress_parents(matched: dict[str, str]) -> dict[str, str]:
    """
    Remove parent technique IDs when a more specific sub-technique also matched.

    In the ATT&CK framework a sub-technique (e.g. T1071.001) already implies its
    parent (T1071). Showing both would double-count the same tactic and clutter
    the output. A technique ID is treated as a parent if it contains no '.' and
    at least one other matched ID starts with '<parent_id>.'.

    Returns a filtered copy of the input dict (technique_id → technique_name).
    """
    ids = set(matched.keys())
    return {
        tid: name
        for tid, name in matched.items()
        if "." in tid  # sub-techniques are always kept
        or not any(other.startswith(tid + ".") for other in ids)
    }


def _pattern_match(alerts: list[NormalizedAlert]) -> list[dict]:
    """
    Scan each alert's title and raw_text for ATT&CK keyword patterns.

    Matching strategy:
    - Concatenate title + raw_text, lowercase — covers both the human summary
      and the original source message.
    - Check every entry in TECHNIQUE_PATTERNS as a substring.
    - Deduplicate by technique_id across all alerts in the cluster (same technique
      matched by three alerts → one result entry, not three).
    - Apply sub-technique suppression: if T1071.001 matched, drop T1071.

    Returns a list of technique dicts, or [] if nothing matched.
    """
    # Accumulate unique technique_id → technique_name matches across all alerts.
    matched: dict[str, str] = {}
    for alert in alerts:
        haystack = (alert.title + " " + alert.raw_text).lower()
        for keyword, technique_id, technique_name in TECHNIQUE_PATTERNS:
            if keyword in haystack:
                matched[technique_id] = technique_name

    if not matched:
        return []

    # Drop parent technique IDs superseded by a matched sub-technique.
    matched = _suppress_parents(matched)

    return [
        {
            "technique_id":   tid,
            "technique_name": name,
            "confidence":     PATTERN_MATCH_CONFIDENCE,
            "method":         "pattern_match",
        }
        for tid, name in matched.items()
    ]


def _llm_classify(
    cluster: CorrelatedCluster,
    alerts: list[NormalizedAlert],
) -> list[dict]:
    """
    LLM-based ATT&CK classification for clusters that pattern matching couldn't
    resolve.

    This function receives the full cluster context and its resolved alerts so
    that a real implementation has everything it needs — alert titles, raw_text,
    entity, indicator, risk_score — to construct a prompt without changing this
    function's interface or any call site.

    Current status: stub. Returns UNCLASSIFIED until an API key is configured.
    To implement: replace the stub body with an LLM call (e.g. watsonx.ai or
    OpenAI) that prompts with cluster summary + alert raw_text and parses a
    structured ATT&CK technique response.
    """
    # TODO: replace with real LLM call once API key is configured.
    # Suggested prompt input: cluster.cluster_id, cluster.risk_score,
    # [a.title + a.raw_text for a in alerts] — all available on the parameters.
    return [
        {
            "technique_id":   "UNCLASSIFIED",
            "technique_name": "Unclassified",
            "confidence":     0.0,
            "method":         "unclassified",
        }
    ]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def map_attack_techniques(
    clusters: list[CorrelatedCluster],
    alerts_by_id: dict[str, NormalizedAlert],
) -> list[CorrelatedCluster]:
    """
    Populate attack_techniques on each cluster.

    For each cluster:
    1. Resolve alert objects from alerts_by_id.
    2. Run deterministic pattern matching against title + raw_text.
    3. If no patterns matched, fall back to _llm_classify() (currently a stub).
    4. Return a new CorrelatedCluster with attack_techniques set; all other
       fields are carried over unchanged via model_copy().

    Input clusters are never mutated — new instances are returned.

    Parameters
    ----------
    clusters:
        Output of score_clusters() (or correlate() directly) — clusters whose
        attack_techniques field is currently the default empty list.
    alerts_by_id:
        Mapping of alert_id → NormalizedAlert. Build from the same alert list
        passed to correlate():  alerts_by_id = {a.alert_id: a for a in alerts}
    """
    mapped: list[CorrelatedCluster] = []
    for cluster in clusters:
        alerts = _resolve_alerts(cluster, alerts_by_id)

        # --- Step 1: deterministic pattern match ---
        techniques = _pattern_match(alerts)

        # --- Step 2: LLM fallback for genuinely ambiguous clusters ---
        if not techniques:
            techniques = _llm_classify(cluster, alerts)

        mapped.append(
            cluster.model_copy(update={"attack_techniques": techniques})
        )

    return mapped
