# Correlation Engine Plan

## Top-Level Overview

Build `app/services/correlation.py` — a two-pass correlation engine that groups
`NormalizedAlert` objects (from `app/services/ingestion.py`) into
`CorrelatedCluster` objects (from `app/models/alert.py`).

The file must be interview-readable: clear constants, explicit intermediate data
structures, short focused helper functions, and comments that explain *why* each
pass exists, not just *what* it does.

**Non-goals:**
- Do not touch `app/models/alert.py` or `app/services/ingestion.py`.
- Do not populate `risk_score` or `risk_level` — those belong to a later scoring
  module; leave them at the model defaults (`0` and `None`).

---

## Algorithm Overview

```
Input: list[NormalizedAlert]
       │
       ▼
┌─────────────────────────────────┐
│  Pass 1 — Indicator Match       │  Group by exact indicator value.
│  confidence = 0.9               │  Each unique indicator → one cluster.
│  basis = ["indicator"]          │
└──────────────┬──────────────────┘
               │  Remaining singletons + multi-alert clusters
               ▼
┌─────────────────────────────────┐
│  Pass 2 — Entity + Time Window  │  Merge clusters that share entity
│  confidence = max(existing,0.6) │  AND overlap within TIME_WINDOW_MINUTES.
│  basis += ["entity","time_window"]│
└──────────────┬──────────────────┘
               │  Anything still alone
               ▼
┌─────────────────────────────────┐
│  Singletons                     │  basis = ["singleton"], confidence = 1.0
└─────────────────────────────────┘
               │
               ▼
       list[CorrelatedCluster]
```

---

## Sub-Tasks

---

### Sub-task 1 — Scaffold the module

**Intent**
Create `app/services/correlation.py` with all imports, the named constant, and
the public entry-point signature. No logic yet — just the skeleton that
establishes the module's contract.

**Expected Outcomes**
- File exists at `app/services/correlation.py`.
- `TIME_WINDOW_MINUTES = 120` is defined at module top.
- `def correlate(alerts: list[NormalizedAlert]) -> list[CorrelatedCluster]:`
  exists and returns an empty list (stub).
- A docstring on `correlate` explains the two-pass strategy in plain language.

**Todo List**
- [ ] Create `app/services/correlation.py`.
- [ ] Add imports: `uuid`, `datetime`, `timedelta`, `collections.defaultdict`,
      `NormalizedAlert`, `CorrelatedCluster` from `app.models.alert`.
- [ ] Define `TIME_WINDOW_MINUTES = 120` with an inline comment.
- [ ] Define `correlate()` stub with docstring.

**Relevant Context**
- `app/models/alert.py` — `NormalizedAlert`, `CorrelatedCluster` field shapes.
- `app/services/ingestion.py` — `normalize_all()` as the caller pattern.

**Status:** [ ] pending

---

### Sub-task 2 — Pass 1: Indicator grouping

**Intent**
Implement a private helper `_pass1_indicator_clusters` that groups alerts by
exact `indicator` value and returns a list of in-progress cluster dicts (not yet
`CorrelatedCluster` instances — using plain dicts here keeps the intermediate
state mutable and easy to merge in Pass 2).

**Expected Outcomes**
- All alerts that share the same `indicator` string land in the same group.
- Each group becomes a dict with keys: `alert_ids`, `correlation_basis`,
  `confidence`, `timestamps`, `entities` (the last two carried forward for
  Pass 2 comparisons).
- Groups with more than one alert get `confidence = 0.9`,
  `correlation_basis = ["indicator"]`.
- Groups of exactly one alert are still produced here — they become candidates
  for Pass 2 merging (not yet labelled "singleton").

**Todo List**
- [ ] Add `_pass1_indicator_clusters(alerts)` using `defaultdict(list)` keyed on
      `alert.indicator`.
- [ ] Build one intermediate cluster dict per unique indicator.
- [ ] Set `confidence = 0.9` only when the group has >= 2 alerts (single-alert
      groups carry `confidence = None` at this stage to signal "not yet settled").
- [ ] Carry `timestamps` list and `entities` set into the dict for Pass 2 use.
- [ ] Call this helper from `correlate()` and capture results.

**Relevant Context**
- `NormalizedAlert.indicator` — the exact string to group on.
- `NormalizedAlert.timestamp` — `datetime` object.
- `NormalizedAlert.entity` — string (host/asset).

**Status:** [ ] pending

---

### Sub-task 3 — Pass 2: Entity + time-window merging

**Intent**
Implement `_pass2_entity_time_merge` that takes the list of intermediate cluster
dicts from Pass 1 and merges any two clusters whose `entities` sets intersect AND
whose timestamp ranges overlap within `TIME_WINDOW_MINUTES`.

Union-find (disjoint-set) is the cleanest merge strategy here: build a graph of
"should merge" pairs, find connected components, then collapse each component into
one cluster. This is the approach to explain in an interview.

**Expected Outcomes**
- Two clusters are merged if: they share at least one entity value AND the gap
  between their closest timestamps is <= `TIME_WINDOW_MINUTES`.
- Merged cluster gets `correlation_basis` = union of both bases plus `"entity"`
  and `"time_window"` (deduped).
- Merged cluster gets `confidence = max(confidence_a or 0, confidence_b or 0, 0.6)` —
  treats `None` (unresolved singleton) as `0` before comparing, so two singleton
  candidates can merge without a TypeError. Never lowers an existing high-confidence cluster.
- Alert IDs from both clusters are combined (no duplicates).
- Timestamps and entities sets are also unioned (needed for chained merges).

**Todo List**
- [ ] Implement `_timestamps_within_window(ts_list_a, ts_list_b, minutes)` —
      returns True if any pair of timestamps (one from each list) is within the
      window. Keep this as a pure, testable helper.
- [ ] Implement `_pass2_entity_time_merge(clusters)` using a union-find approach:
  - Build list of merge-pairs (indices i, j where criteria met).
  - Use a parent array to find connected components.
  - Collapse each component into one merged cluster dict.
- [ ] Apply confidence and basis rules during collapse: `confidence = max(a or 0, b or 0, 0.6)`.
- [ ] Return merged cluster list.

**Relevant Context**
- `TIME_WINDOW_MINUTES` — use `timedelta(minutes=TIME_WINDOW_MINUTES)`.
- Pass 2 operates on cluster dicts (not raw alerts) so chained merges work
  naturally (a cluster from Pass 1 may already hold multiple alerts).

**Status:** [ ] pending

---

### Sub-task 4 — Finalize singletons and build CorrelatedCluster output

**Intent**
After both passes, convert every remaining cluster dict into a proper
`CorrelatedCluster` model instance. Assign `cluster_id` (a deterministic or UUID
string), finalize confidence for still-unresolved singletons
(`confidence = 1.0`, `correlation_basis = ["singleton"]`), and leave `risk_score`
and `risk_level` at defaults.

**Expected Outcomes**
- Every alert appears in exactly one `CorrelatedCluster`.
- Clusters with 1 alert and no Pass 2 merge get `correlation_basis=["singleton"]`,
  `confidence=1.0`.
- Clusters with >= 2 alerts from Pass 1 keep `confidence=0.9`,
  `correlation_basis=["indicator"]` (unless also merged in Pass 2).
- All `cluster_id` values are unique strings (e.g. `"cluster-<uuid4>"` prefix).
- `risk_score` defaults to `0`, `risk_level` defaults to `None`.
- Function returns `list[CorrelatedCluster]`.

**Todo List**
- [ ] Add `_finalize_clusters(cluster_dicts)` that iterates and builds
      `CorrelatedCluster` instances.
- [ ] For any cluster dict still carrying `confidence = None` (single-alert,
      unmergeable), set `confidence = 1.0` and `correlation_basis = ["singleton"]`.
- [ ] Generate `cluster_id = f"cluster-{uuid.uuid4()}"`.
- [ ] Wire `_finalize_clusters` into `correlate()` as the last step.
- [ ] Ensure `correlate()` now returns the real list.

**Relevant Context**
- `CorrelatedCluster` fields: `cluster_id`, `alert_ids`, `correlation_basis`,
  `confidence`, `risk_score` (default 0), `risk_level` (default None).
- `uuid` already imported in Sub-task 1.

**Status:** [ ] pending

---

### Sub-task 5 — Readability pass and inline commentary

**Intent**
This is a hackathon submission judged on explainability. After all logic is
working, do a focused readability pass: verify every function has a docstring
that explains its *role in the algorithm*, add section comments in `correlate()`
marking "Pass 1", "Pass 2", "Finalize", and ensure variable names are
self-documenting (no `x`, `tmp`, `d`).

**Expected Outcomes**
- `correlate()` reads like a narrative of the algorithm.
- Each private helper has a one-line docstring.
- `TIME_WINDOW_MINUTES` has a comment explaining what it controls.
- No magic numbers anywhere else in the file.
- A reader unfamiliar with the codebase can understand the algorithm by reading
  top-to-bottom.

**Todo List**
- [ ] Review `correlate()` body — add `# --- Pass 1 ---`, `# --- Pass 2 ---`,
      `# --- Finalize ---` section comments.
- [ ] Verify all helper docstrings are present and accurate.
- [ ] Check no magic numbers remain (e.g. `0.9`, `0.6`, `1.0` — these are
      algorithm-defined constants; add inline comments explaining their meaning).
- [ ] Confirm variable names read clearly in context.

**Status:** [ ] pending

---

## Files Changed

| File | Action |
|------|--------|
| `app/services/correlation.py` | Create (new file) |

No other files are modified.
