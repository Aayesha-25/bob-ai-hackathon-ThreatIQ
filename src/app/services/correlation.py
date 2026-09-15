"""
correlation.py — Two-pass threat alert correlation engine.

Strategy
--------
Pass 1 — Indicator match (high confidence, 0.9):
    Group alerts that share the exact same indicator value (IP, hash, domain)
    into a single cluster. Strong signal: same indicator almost certainly means
    the same threat event.

Pass 2 — Entity + time-window match (lower confidence, 0.6):
    Merge clusters that involve the same host/asset AND whose alerts fall within
    TIME_WINDOW_MINUTES of each other. Weaker signal: same host, close in time,
    probably related — but not certain.

Anything still unclustered after both passes becomes its own singleton cluster
(confidence 1.0 — we are certain it stands alone; there is simply nothing to
correlate it with).
"""

import uuid
from collections import defaultdict
from datetime import timedelta

from app.models.alert import CorrelatedCluster, NormalizedAlert

# How close two clusters' timestamps must be (in minutes) for a time-window
# merge to be considered. Tune this constant without touching any logic below.
TIME_WINDOW_MINUTES = 120


# ---------------------------------------------------------------------------
# Internal cluster dict shape (mutable; converted to CorrelatedCluster at end)
# ---------------------------------------------------------------------------
# {
#   "alert_ids":          list[str],
#   "entities":           set[str],   -- for Pass 2 entity matching
#   "timestamps":         list[datetime], -- for Pass 2 time-window check
#   "correlation_basis":  list[str],
#   "confidence":         float | None,  -- None = unresolved singleton candidate
# }
# ---------------------------------------------------------------------------


def _pass1_indicator_clusters(alerts: list[NormalizedAlert]) -> list[dict]:
    """
    Pass 1 — group alerts by exact indicator value.

    Every unique indicator string becomes one cluster. Clusters with two or more
    alerts get confidence=0.9 and basis=['indicator']. Clusters with exactly one
    alert leave confidence=None — they are still candidates for Pass 2 merging or
    will be resolved as singletons in the finalise step.
    """
    # Bucket alerts by their indicator value (IP, hash, domain, etc.)
    buckets: dict[str, list[NormalizedAlert]] = defaultdict(list)
    for alert in alerts:
        buckets[alert.indicator].append(alert)

    clusters: list[dict] = []
    for indicator, group in buckets.items():
        is_multi = len(group) >= 2
        clusters.append(
            {
                "alert_ids": [a.alert_id for a in group],
                # entities and timestamps are carried forward for Pass 2
                "entities": {a.entity for a in group},
                "timestamps": [a.timestamp for a in group],
                "correlation_basis": ["indicator"] if is_multi else [],
                # 0.9 — high confidence: same indicator is a strong threat signal.
                # None — single alert: confidence is undecided until after Pass 2.
                "confidence": 0.9 if is_multi else None,
            }
        )

    return clusters


def _timestamps_within_window(
    timestamps_a: list,
    timestamps_b: list,
    minutes: int,
) -> bool:
    """
    Return True if any timestamp in timestamps_a is within `minutes` of any
    timestamp in timestamps_b.

    Checking every pair is O(m*n) but cluster timestamp lists are small in
    practice (typically single-digit length), so this stays readable and correct.
    """
    window = timedelta(minutes=minutes)
    return any(
        abs(ts_a - ts_b) <= window
        for ts_a in timestamps_a
        for ts_b in timestamps_b
    )


def _pass2_entity_time_merge(clusters: list[dict]) -> list[dict]:
    """
    Pass 2 — merge clusters that share an entity AND overlap in time.

    Uses a union-find (disjoint-set) structure to identify all connected
    components in one sweep, then collapses each component into a single cluster.

    Two clusters are candidates to merge when:
      - Their `entities` sets intersect (same host/asset appears in both), AND
      - At least one pair of timestamps (one from each cluster) falls within
        TIME_WINDOW_MINUTES of each other.

    Confidence rule: max(confidence_a or 0, confidence_b or 0, 0.6).
    None is treated as 0 so two singleton candidates (both None) can merge
    without a TypeError; the result is always at least 0.6.
    """
    n = len(clusters)

    # --- Union-Find helpers (inline for readability) ---
    parent = list(range(n))

    def find(i: int) -> int:
        """Chase parent pointers to the root, with path compression."""
        while parent[i] != i:
            parent[i] = parent[parent[i]]  # path compression (halving)
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        """Merge the sets containing i and j."""
        parent[find(i)] = find(j)

    # --- Identify merge pairs ---
    for i in range(n):
        for j in range(i + 1, n):
            shares_entity = bool(clusters[i]["entities"] & clusters[j]["entities"])
            shares_time = _timestamps_within_window(
                clusters[i]["timestamps"],
                clusters[j]["timestamps"],
                TIME_WINDOW_MINUTES,
            )
            if shares_entity and shares_time:
                union(i, j)

    # --- Collapse each connected component into one cluster ---
    components: dict[int, list[int]] = defaultdict(list)
    for i in range(n):
        components[find(i)].append(i)

    merged_clusters: list[dict] = []
    for member_indices in components.values():
        if len(member_indices) == 1:
            # No merge happened — pass the cluster through unchanged.
            merged_clusters.append(clusters[member_indices[0]])
            continue

        # Collapse all members of this component into one cluster.
        combined_alert_ids: list[str] = []
        combined_entities: set[str] = set()
        combined_timestamps: list = []
        combined_basis: list[str] = []
        combined_confidence: float | None = None

        for idx in member_indices:
            c = clusters[idx]
            combined_alert_ids.extend(c["alert_ids"])
            combined_entities |= c["entities"]
            combined_timestamps.extend(c["timestamps"])
            combined_basis.extend(c["correlation_basis"])
            # Treat None as 0 before comparing — two unresolved singletons
            # merging each other is legitimate and must not raise a TypeError.
            combined_confidence = max(
                combined_confidence or 0,
                c["confidence"] or 0,
                0.6,  # 0.6 — floor for any entity+time merge; weaker than indicator match
            )

        # Add the Pass 2 merge signals to the basis (deduplicated, order-stable).
        for tag in ("entity", "time_window"):
            if tag not in combined_basis:
                combined_basis.append(tag)

        merged_clusters.append(
            {
                "alert_ids": combined_alert_ids,
                "entities": combined_entities,
                "timestamps": combined_timestamps,
                "correlation_basis": combined_basis,
                "confidence": combined_confidence,
            }
        )

    return merged_clusters


def _finalize_clusters(cluster_dicts: list[dict]) -> list[CorrelatedCluster]:
    """
    Convert internal cluster dicts into CorrelatedCluster model instances.

    Clusters whose confidence is still None at this point were never merged in
    either pass — they contain exactly one alert and stand alone. They become
    singletons: basis=['singleton'], confidence=1.0 (certain they are isolated;
    there is simply nothing to correlate them with).

    risk_score and risk_level are left at model defaults (0 and None) — a
    separate scoring module is responsible for populating those fields.
    """
    results: list[CorrelatedCluster] = []

    for c in cluster_dicts:
        if c["confidence"] is None:
            # Single alert, never matched by either pass — it stands alone.
            basis = ["singleton"]
            confidence = 1.0  # 1.0 — certain it is isolated; nothing to correlate with
        else:
            basis = c["correlation_basis"]
            confidence = c["confidence"]

        results.append(
            CorrelatedCluster(
                cluster_id=f"cluster-{uuid.uuid4()}",
                alert_ids=c["alert_ids"],
                correlation_basis=basis,
                confidence=confidence,
                # risk_score and risk_level intentionally omitted — defaults apply.
            )
        )

    return results


def correlate(alerts: list[NormalizedAlert]) -> list[CorrelatedCluster]:
    """
    Correlate a flat list of NormalizedAlert objects into CorrelatedClusters.

    Two-pass algorithm:
      1. Group by exact indicator value → high-confidence clusters (0.9).
      2. Merge by shared entity + overlapping time window → medium-confidence (0.6).
         Confidence is never *lowered* by a merge; max() wins.
      3. Any alert still alone becomes a singleton cluster (confidence 1.0).

    Returns one CorrelatedCluster per group. risk_score and risk_level are left
    at their model defaults — a separate scoring module fills those in later.
    """
    # --- Pass 1 ---
    clusters = _pass1_indicator_clusters(alerts)

    # --- Pass 2 ---
    clusters = _pass2_entity_time_merge(clusters)

    # --- Finalize ---
    return _finalize_clusters(clusters)
