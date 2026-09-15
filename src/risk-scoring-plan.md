# Risk Scoring Module Plan

## Top-Level Overview

Build `app/services/risk_scoring.py` — a weighted point-based scoring module that
takes `list[CorrelatedCluster]` from `correlate()` and fills in `risk_score` and
`risk_level` on each cluster.

**Entry point:**
```
def score_clusters(
    clusters: list[CorrelatedCluster],
    alerts_by_id: dict[str, NormalizedAlert],
) -> list[CorrelatedCluster]
```

**Non-goals:**
- Do not modify `correlation.py`, `ingestion.py`, or `app/models/alert.py`.
- Do not touch `correlation_basis` or `confidence` — scoring's only job is
  `risk_score` and `risk_level`.

---

## Data Source Notes (from code research)

- `load_known_bad_indicators()` returns `{"ips": [...], "domains": [...], "hashes": [...]}`
- `load_allowlist()` returns `{"ips": [...], "note": "..."}` — only `"ips"` is a
  list; no `"domains"` or `"hashes"`. The module must use `.get(key, [])` so it
  degrades gracefully if the allowlist gains or loses keys in the future.
- `NormalizedAlert.source` is stored as the enum's string value
  (`use_enum_values = True`), so distinct-source counting compares strings.
- `NormalizedAlert.severity_hint` is `str | None`; must null-check before
  `.upper()`.

---

## Scoring Formula

```
score = 0

+ KNOWN_BAD_INDICATOR_POINTS (30)   if any alert.indicator in known_bad set
+ SOURCE_DIVERSITY_POINTS (10)       × count of distinct source values
+ RECENCY_POINTS (15)                if any alert.timestamp within RECENCY_WINDOW_HOURS (24h) of now
+ CRITICAL_SEVERITY_HINT_POINTS (10) if any alert has severity_hint == "CRITICAL"
  OR
+ HIGH_SEVERITY_HINT_POINTS (5)      if any alert has severity_hint == "HIGH"
  (check CRITICAL first; only one severity bonus per cluster)

+ ALLOWLIST_PENALTY (-25)            if any alert.indicator in allowlist set

score = clamp(score, 0, 100)
```

Risk level thresholds:
```
>= RISK_CRITICAL_THRESHOLD (80) → CRITICAL
>= RISK_HIGH_THRESHOLD    (60) → HIGH
>= RISK_MEDIUM_THRESHOLD  (40) → MEDIUM
>= RISK_LOW_THRESHOLD     (20) → LOW
<  RISK_LOW_THRESHOLD     (20) → LIKELY_FALSE_POSITIVE
```

---

## Sub-Tasks

---

### Sub-task 1 — Scaffold the module

**Intent**
Create the file with all imports, every named constant, and the public
`score_clusters()` stub. Nothing computed yet — just the contract and the
tuneable configuration surface.

**Expected Outcomes**
- File `app/services/risk_scoring.py` exists.
- All 10 point/penalty constants defined with explanatory inline comments.
- All 4 threshold constants defined.
- `RECENCY_WINDOW_HOURS = 24` defined.
- `score_clusters()` stub exists (returns empty list) with a module-level and
  function-level docstring explaining the scoring philosophy.

**Todo List**
- [ ] Create `app/services/risk_scoring.py`.
- [ ] Add imports: `datetime`, `timezone`, `CorrelatedCluster`, `NormalizedAlert`,
      `RiskLevel`, `load_known_bad_indicators`, `load_allowlist`.
- [ ] Define all point/penalty constants with inline rationale comments.
- [ ] Define all threshold constants.
- [ ] Define `RECENCY_WINDOW_HOURS = 24`.
- [ ] Add `score_clusters()` stub.

**Relevant Context**
- `app/models/alert.py` — `CorrelatedCluster`, `NormalizedAlert`, `RiskLevel`
- `app/services/ingestion.py` — `load_known_bad_indicators()`, `load_allowlist()`

**Status:** [ ] pending

---

### Sub-task 2 — Build the indicator lookup sets

**Intent**
Before scoring any cluster, flatten the known-bad and allowlist dicts into plain
Python sets for O(1) membership checks. Extract this into a private helper
`_build_indicator_sets()` so the data-loading concern is separate from scoring
logic. The helper returns two sets: `known_bad` and `allowlisted`.

**Expected Outcomes**
- `_build_indicator_sets()` calls `load_known_bad_indicators()` and
  `load_allowlist()`.
- Combines `ips + domains + hashes` from known-bad into one flat set.
- Uses `.get(key, [])` on both dicts so missing keys (e.g. allowlist has no
  `"domains"` or `"hashes"`) never raise a KeyError.
- Returns `(known_bad_set, allowlist_set)` as a tuple of two `set[str]`.
- Called once at the top of `score_clusters()` — not per-cluster.

**Todo List**
- [ ] Add `_build_indicator_sets() -> tuple[set[str], set[str]]`.
- [ ] Union `known_bad["ips"]`, `known_bad["domains"]`, `known_bad["hashes"]`
      using `.get(key, [])`.
- [ ] Union `allowlist["ips"]` (and any future keys) using `.get(key, [])`.
- [ ] Wire the call into `score_clusters()`.

**Relevant Context**
- `load_known_bad_indicators()` → `{"ips": [...], "domains": [...], "hashes": [...]}`
- `load_allowlist()` → `{"ips": [...], "note": "..."}` — `"note"` is a string, not
  a list; must NOT be iterated.

**Status:** [ ] pending

---

### Sub-task 3 — Implement `_score_cluster()`

**Intent**
Add a private helper `_score_cluster(cluster, alerts, known_bad, allowlisted)`
that computes and returns the integer `risk_score` for one cluster. Each scoring
signal is applied in a distinct, labeled step so the logic reads like an auditable
checklist. This helper contains all the arithmetic; `score_clusters()` stays a
simple loop.

**Expected Outcomes**
- `_score_cluster()` applies each signal in order: known-bad, source diversity,
  recency, severity hint, allowlist penalty.
- Source diversity: count distinct `alert.source` values across the cluster's
  alerts; multiply by `SOURCE_DIVERSITY_POINTS`.
- Severity: check CRITICAL first across all alerts; if any alert is CRITICAL add
  `CRITICAL_SEVERITY_HINT_POINTS` and skip the HIGH check entirely. Only if no
  CRITICAL alert exists check for HIGH. This is the "only apply one" rule.
- `severity_hint` is `str | None` — null-check before `.upper()`.
- Recency: compare `alert.timestamp` to `datetime.now(timezone.utc)` —
  `alert.timestamp` must be timezone-aware for this subtraction to work. If it
  is naive, attach UTC before comparing (defensive).
- Allowlist penalty is added (negative value); final score clamped `[0, 100]`.
- Returns `int`.

**Todo List**
- [ ] Add `_score_cluster(cluster, alerts_in_cluster, known_bad, allowlisted)`
      with a docstring enumerating each signal and why it's weighted as it is.
- [ ] Known-bad check: `any(a.indicator in known_bad for a in alerts_in_cluster)`.
- [ ] Source diversity: `len({a.source for a in alerts_in_cluster}) * SOURCE_DIVERSITY_POINTS`.
- [ ] Recency: build `now = datetime.now(timezone.utc)`, compare with
      `timedelta(hours=RECENCY_WINDOW_HOURS)`; handle naive timestamps defensively.
- [ ] Severity: CRITICAL-first scan, then HIGH-only-if-no-CRITICAL scan.
- [ ] Allowlist: `any(a.indicator in allowlisted for a in alerts_in_cluster)`.
- [ ] Clamp: `max(0, min(100, score))`.

**Relevant Context**
- `NormalizedAlert.severity_hint: str | None`
- `NormalizedAlert.source` — stored as string value due to `use_enum_values=True`
- Recency window: `RECENCY_WINDOW_HOURS = 24`

**Status:** [ ] pending

---

### Sub-task 4 — Implement `_score_to_level()` and wire everything into `score_clusters()`

**Intent**
Add a pure mapping function `_score_to_level(score: int) -> RiskLevel` that
applies the threshold constants in descending order. Then wire `_score_cluster()`
and `_score_to_level()` into `score_clusters()`, which resolves alerts for each
cluster, computes the score, and returns new `CorrelatedCluster` instances with
`risk_score` and `risk_level` populated. All other fields are carried over
unchanged using `model_copy(update=...)`.

**Expected Outcomes**
- `_score_to_level()` is a clean ladder: `>= 80 → CRITICAL`, etc.
- `score_clusters()` resolves each cluster's alerts from `alerts_by_id` and calls
  `_score_cluster()`.
- Returns `list[CorrelatedCluster]` with `risk_score` and `risk_level` set.
- Uses `cluster.model_copy(update={"risk_score": ..., "risk_level": ...})` —
  Pydantic v2 pattern — so nothing else on the cluster is mutated.
- Handles missing alert IDs in `alerts_by_id` gracefully (skip/warn, not crash).

**Todo List**
- [ ] Add `_score_to_level(score: int) -> RiskLevel`.
- [ ] Update `score_clusters()` to loop over clusters, resolve alerts, call
      `_score_cluster()`, call `_score_to_level()`, and produce updated clusters.
- [ ] Use `model_copy(update=...)` to avoid mutating the originals.
- [ ] Add guard: skip alert IDs not found in `alerts_by_id` (log-friendly comment).
- [ ] Return the complete updated list.

**Relevant Context**
- Pydantic v2: `model.model_copy(update={...})` creates a shallow copy with
  specified fields overridden.
- `RiskLevel` values: CRITICAL, HIGH, MEDIUM, LOW, LIKELY_FALSE_POSITIVE.

**Status:** [ ] pending

---

### Sub-task 5 — Docstring and rationale pass

**Intent**
Every scoring decision must be defensible in a judge Q&A. After the logic is
complete, do a focused pass to ensure the module-level docstring, each constant's
inline comment, and `_score_cluster()`'s docstring together answer:
"Why is this signal worth this many points?"

**Expected Outcomes**
- Module docstring explains overall philosophy: why a point system, what the
  inputs are, and what the output represents.
- Each constant has a one-line inline comment (already added in Sub-task 1, but
  verify they are present and accurate after the logic is written).
- `_score_cluster()` docstring enumerates each signal with the rationale, not
  just the mechanics.
- `_score_to_level()` docstring notes that thresholds are named constants and
  explains the mapping.
- No magic numbers anywhere in the file.

**Todo List**
- [ ] Verify every constant has an inline rationale comment.
- [ ] Confirm `_score_cluster()` docstring is interview-grade.
- [ ] Confirm `score_clusters()` docstring explains inputs/outputs clearly.
- [ ] Check no literal integers appear outside constant definitions.

**Status:** [ ] pending

---

## Files Changed

| File | Action |
|------|--------|
| `app/services/risk_scoring.py` | Create (new file) |

No other files are modified.
