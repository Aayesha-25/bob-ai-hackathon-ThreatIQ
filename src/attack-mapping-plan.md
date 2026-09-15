# ATT&CK Mapping Module Plan

## Top-Level Overview

Two changes:
1. **Add `attack_techniques` field to `CorrelatedCluster`** in `app/models/alert.py`.
2. **Build `app/services/attack_mapping.py`** — pattern-match-first, LLM-fallback stub.

**Non-goals:** Do not touch any other field on any model. Do not modify correlation.py,
ingestion.py, or risk_scoring.py.

---

## Change 1 — Model update (`app/models/alert.py`)

Add one field to `CorrelatedCluster`:

```python
attack_techniques: list[dict] = Field(default_factory=list)
```

Each dict has the shape:
```python
{
    "technique_id":   str,    # e.g. "T1059.001"
    "technique_name": str,    # e.g. "PowerShell"
    "confidence":     float,  # 0.0–1.0
    "method":         str,    # "pattern_match" | "llm_fallback" | "unclassified"
}
```

`Field(default_factory=list)` means existing code that constructs `CorrelatedCluster`
without this field (correlation.py, risk_scoring.py) continues to work — the field
just defaults to `[]`. No other file needs to change.

---

## Architecture of `attack_mapping.py`

```
map_attack_techniques(clusters, alerts_by_id)
        │
        ▼
For each cluster:
  1. Resolve alerts → list[NormalizedAlert]
  2. _pattern_match(alerts) → list[dict]    (scans title + raw_text)
  3. If result is empty:
       _llm_classify(cluster, alerts) → list[dict]   (stub, returns UNCLASSIFIED)
  4. cluster.model_copy(update={"attack_techniques": techniques})
        │
        ▼
return list[CorrelatedCluster]
```

---

## Sub-Tasks

---

### Sub-task 1 — Add `attack_techniques` to `CorrelatedCluster`

**Intent**
Extend the model with the new field using `Field(default_factory=list)` so all
existing construction sites remain valid. `Field` is already imported.

**Expected Outcomes**
- `CorrelatedCluster` gains `attack_techniques: list[dict] = Field(default_factory=list)`.
- A docstring comment explains the expected dict shape inline.
- `correlation.py` and `risk_scoring.py` continue to construct clusters without
  supplying this field — no changes needed there.

**Todo List**
- [ ] Add the field to `CorrelatedCluster` after `risk_level`.
- [ ] Add an inline comment describing the dict shape.

**Relevant Context**
- `app/models/alert.py` line 53 — `risk_level` is the current last field.
- `Field` already imported from `pydantic`.

**Status:** [ ] pending

---

### Sub-task 2 — Scaffold `attack_mapping.py`

**Intent**
Create the file with imports, module docstring explaining the pattern-first / LLM-fallback
strategy, and the `map_attack_techniques()` stub.

**Expected Outcomes**
- File exists at `app/services/attack_mapping.py`.
- Module docstring explains: deterministic-first protects demo from LLM downtime;
  LLM only handles genuinely ambiguous clusters.
- `map_attack_techniques()` stub returns `[]`.

**Todo List**
- [ ] Create `app/services/attack_mapping.py`.
- [ ] Add imports: `CorrelatedCluster`, `NormalizedAlert` from `app.models.alert`.
- [ ] Add module docstring.
- [ ] Add `map_attack_techniques()` stub with parameter/return docstring.

**Relevant Context**
- Same signature and `model_copy()` pattern as `score_clusters()` in `risk_scoring.py`.

**Status:** [ ] pending

---

### Sub-task 3 — Build `TECHNIQUE_PATTERNS` and `_pattern_match()`

**Intent**
Define the static lookup table and the function that scans alert text against it.
Each entry is a `(keyword, technique_id, technique_name)` tuple. A cluster can
match multiple techniques — all distinct matches are returned.

**Expected Outcomes**
- `TECHNIQUE_PATTERNS: list[tuple[str, str, str]]` defined as a module-level
  constant (so it reads like a configuration table, not buried logic).
- Covers at minimum the six required techniques:
  - `"powershell"` → T1059.001 / "PowerShell"
  - `"cobalt strike"`, `"beacon"` → T1071.001 / "Application Layer Protocol: Web Protocols"
  - `"outbound connection"`, `"c2"` → T1071 / "Application Layer Protocol"
  - `"registry"`, `"persistence"` → T1547 / "Boot or Logon Autostart Execution"
  - `"auth fail"`, `"brute force"`, `"ssh"` → T1110 / "Brute Force"
  - `"port scan"` → T1595 / "Active Scanning"
- `_pattern_match(alerts: list[NormalizedAlert]) -> list[dict]`:
  - For each alert: concatenate `(alert.title + " " + alert.raw_text).lower()`.
  - For each pattern tuple: if keyword is a substring of the text, record the
    `(technique_id, technique_name)` pair.
  - Deduplicate by `technique_id` across all alerts in the cluster.
  - **Sub-technique suppression:** after deduplication, remove any technique whose
    `technique_id` is a prefix-parent of another matched technique. Parent is
    determined by prefix match on the part before the `.` — e.g. if both T1071
    and T1071.001 matched, drop T1071 because T1071.001 already implies it.
    Implementation: collect the set of matched IDs; for each ID that contains no
    `.`, drop it if any other matched ID starts with `that_id + "."`.
  - Return list of dicts: `{"technique_id", "technique_name", "confidence": 0.85, "method": "pattern_match"}`.
- Returns `[]` if no keywords match — caller decides what to do next.

**Todo List**
- [ ] Define `TECHNIQUE_PATTERNS` at module top with a comment explaining its role.
- [ ] Add `_pattern_match(alerts)` with a docstring covering matching strategy and
      deduplication.
- [ ] Keep the confidence value `0.85` referenced as an inline comment explaining
      the choice (high but not certain — keyword match doesn't confirm execution,
      only relevance).

**Relevant Context**
- `NormalizedAlert.title` and `NormalizedAlert.raw_text` are both `str` — safe to
  concatenate and lower() directly.
- Dedup on `technique_id` only — two alerts matching the same technique should
  produce one entry, not two.

**Status:** [ ] pending

---

### Sub-task 4 — Build `_llm_classify()` stub

**Intent**
Define the function that handles the LLM fallback path. It must have the correct
signature and return shape now so wiring it in later requires zero changes to
`map_attack_techniques()`.

**Expected Outcomes**
- `_llm_classify(cluster: CorrelatedCluster, alerts: list[NormalizedAlert]) -> list[dict]`
  exists.
- Currently returns `[{"technique_id": "UNCLASSIFIED", "technique_name": "Unclassified",
  "confidence": 0.0, "method": "unclassified"}]`.
- Has a clear `# TODO: replace with real LLM call once API key is configured`
  comment explaining exactly where the real logic goes.
- Docstring explains *why* this function exists as a fallback (not just what it does)
  and what an implementer would replace it with.

**Todo List**
- [ ] Add `_llm_classify()` with correct signature and stub return value.
- [ ] Add TODO comment pinned to the exact line where the real call would go.
- [ ] Docstring explains: "receives full cluster context and resolved alerts so a
      real implementation has everything it needs — title, raw_text, entity, indicator —
      to construct an LLM prompt without changing this function's interface."

**Status:** [ ] pending

---

### Sub-task 5 — Wire everything into `map_attack_techniques()`

**Intent**
Implement the full loop in `map_attack_techniques()`: resolve alerts, pattern-match,
fall back to LLM stub if empty, produce new clusters via `model_copy()`.

**Expected Outcomes**
- `map_attack_techniques()` is fully implemented and returns `list[CorrelatedCluster]`.
- For each cluster: resolve alerts → pattern match → if empty, llm_classify → model_copy.
- Input clusters are never mutated.
- Missing alert IDs in `alerts_by_id` are skipped (same guard as `risk_scoring.py`).

**Todo List**
- [ ] Implement the loop in `map_attack_techniques()`.
- [ ] Add `_resolve_alerts()` helper (same pattern as risk_scoring — or note that it
      could be shared; for now duplicate it locally to keep modules independent).
- [ ] Use `model_copy(update={"attack_techniques": techniques})`.
- [ ] Return the completed list.

**Relevant Context**
- `cluster.model_copy(update={...})` — Pydantic v2.
- `_resolve_alerts()` in `risk_scoring.py` is identical in logic; keep a local copy
  to avoid a cross-service import dependency.

**Status:** [ ] pending

---

## Files Changed

| File | Action |
|------|--------|
| `app/models/alert.py` | Edit — add `attack_techniques` field to `CorrelatedCluster` |
| `app/services/attack_mapping.py` | Create (new file) |

No other files are modified.
