# BLUF Generator Plan

## Top-Level Overview

Two changes:
1. **Add `BlufReport` model** to `app/models/alert.py`.
2. **Build `app/services/bluf_generator.py`** — LLM-driven BLUF report generation
   with a deterministic fallback on JSON parse failure.

**Non-goals:** Do not touch correlation.py, ingestion.py, risk_scoring.py,
attack_mapping.py, or llm_client.py. This is per-cluster, on-demand only.

---

## BlufReport field contract

| Field | Type | Source |
|---|---|---|
| report_id | str | Code: `f"BLUF-{cluster.cluster_id}"` |
| cluster_id | str | Code: `cluster.cluster_id` |
| generated_at | datetime | Code: `datetime.now(timezone.utc)` |
| bottom_line | str | LLM / fallback |
| threat_classification | str | LLM / fallback |
| confidence_percent | int | LLM / fallback |
| attack_techniques_summary | list[str] | LLM / fallback |
| recommended_action | str | LLM / fallback |
| supporting_evidence | list[str] | LLM / fallback |

---

## Architecture of `bluf_generator.py`

```
generate_bluf(cluster, alerts_by_id)
        │
        ├─ resolve alerts from alerts_by_id
        ├─ build system prompt (analyst persona)
        ├─ build user prompt (cluster context + strict JSON instruction)
        ├─ call llm_client.generate(prompt, system)
        │       │
        │       ├─ success → _parse_llm_response(raw) → BlufReport fields
        │       │       │
        │       │       ├─ valid JSON → assemble BlufReport
        │       │       └─ JSON error → _fallback_bluf(cluster, alerts)
        │       │
        │       └─ RuntimeError (both providers failed)
        │               └─ _fallback_bluf(cluster, alerts)
        │
        └─ return BlufReport
```

---

## Sub-Tasks

---

### Sub-task 1 — Add `BlufReport` to `app/models/alert.py`

**Intent**
Add the `BlufReport` Pydantic model. `datetime` is already imported. `timezone`
needs adding to the import. No other model changes.

**Expected Outcomes**
- `BlufReport` exists as the last class in `app/models/alert.py`.
- All nine fields present with correct types.
- `generated_at: datetime` — set in code, not by LLM, so no default needed.
- `timezone` added to the `from datetime import ...` line.

**Todo List**
- [ ] Add `timezone` to the existing `from datetime import datetime` line.
- [ ] Add `BlufReport(BaseModel)` after `CorrelatedCluster`.

**Relevant Context**
- `app/models/alert.py` line 12: `from datetime import datetime` — needs `timezone`.
- `Field` already imported from pydantic (used by `CorrelatedCluster`).

**Status:** [ ] pending

---

### Sub-task 2 — Scaffold `bluf_generator.py`

**Intent**
Create the file with imports, module docstring, and the `generate_bluf()` stub.

**Expected Outcomes**
- File exists at `app/services/bluf_generator.py`.
- Module docstring explains: LLM-first for richer narrative, deterministic fallback
  ensures commanders always get a report even if both LLM providers are down.
- `generate_bluf()` stub returns a placeholder `BlufReport`.
- Imports: `json`, `datetime`, `timezone`, `BlufReport`, `CorrelatedCluster`,
  `NormalizedAlert` from `app.models.alert`, `generate` from
  `app.services.llm_client`.

**Relevant Context**
- `app/services/llm_client.py` — `generate(prompt, system) -> str`.
- `app/models/alert.py` — `BlufReport`, `CorrelatedCluster`, `NormalizedAlert`.

**Status:** [ ] pending

---

### Sub-task 3 — Build the prompt construction helpers

**Intent**
Add two private functions: `_build_system_prompt()` and `_build_user_prompt()`.
Keeping prompt text in dedicated functions makes them easy to iterate without
touching control flow, and makes the prompts reviewable in isolation during a
judge Q&A.

**Expected Outcomes**
- `_build_system_prompt() -> str` — returns the fixed analyst persona string
  verbatim as specified.
- `_build_user_prompt(cluster, alerts) -> str` — includes:
  - `risk_score`, `risk_level`, `correlation_basis`, `confidence`
  - All `attack_techniques` (technique_id + technique_name + method)
  - Each alert's `source`, `timestamp`, `title`, `raw_text`
  - A strict JSON block schema at the end listing the five LLM-populated fields:
    `bottom_line`, `threat_classification`, `confidence_percent`,
    `attack_techniques_summary`, `recommended_action`, `supporting_evidence`.
- Prompt instructs the LLM to respond with **only** the JSON object, no prose
  wrapping — reduces parse failure rate.

**Todo List**
- [ ] Add `_build_system_prompt()` returning the specified string.
- [ ] Add `_build_user_prompt(cluster, alerts)` composing cluster context + JSON
      schema instruction.
- [ ] Format alert evidence as numbered lines (`1. [SOURCE] timestamp — title\nraw_text`).
- [ ] Truncate each alert's `raw_text` to 300 characters in the prompt — include
      all alerts in the cluster, just cap each one's text to keep prompt length
      bounded regardless of cluster size.

**Status:** [ ] pending

---

### Sub-task 4 — Build `_parse_llm_response()` and `_fallback_bluf()`

**Intent**
`_parse_llm_response()` defensively extracts the five LLM-owned fields from the
raw response string. `_fallback_bluf()` builds those same five fields directly
from cluster data — no LLM, no external call.

**Expected Outcomes**
- `_parse_llm_response(raw: str) -> dict | None`:
  - Strips markdown fences if present (LLMs often wrap JSON in ```json ... ```).
  - Calls `json.loads()`.
  - Returns the dict if all six required keys are present, `None` otherwise.
  - Never raises — all exceptions caught, returns `None` on any failure.
- `_fallback_bluf(cluster, alerts) -> dict`:
  - Always returns a complete dict with all six LLM-owned keys.
  - `bottom_line`: `f"Cluster {cluster.cluster_id} — risk {cluster.risk_level} (score {cluster.risk_score})"`.
  - `threat_classification`: joined attack technique names, or "Unclassified".
  - `confidence_percent`: `int(cluster.confidence * 100)`.
  - `attack_techniques_summary`: list of `"technique_id — technique_name"` strings.
  - `recommended_action`: tiered string based on `cluster.risk_level` value.
  - `supporting_evidence`: list of alert titles.

**Todo List**
- [ ] Add `_parse_llm_response(raw)` with fence-stripping and safe `json.loads()`.
- [ ] Add `_fallback_bluf(cluster, alerts)` covering all six fields.
- [ ] `recommended_action` tiers: CRITICAL → "Immediate isolation and incident response";
      HIGH → "Escalate to SOC lead for investigation"; MEDIUM → "Monitor and log for
      pattern recurrence"; LOW/default → "Review during next scheduled triage".

**Status:** [ ] pending

---

### Sub-task 5 — Wire everything into `generate_bluf()`

**Intent**
Implement the full control flow: resolve alerts → build prompts → call LLM →
parse or fall back → assemble and return `BlufReport`.

**Expected Outcomes**
- `generate_bluf()` is fully implemented.
- LLM failure (`RuntimeError` from `generate()`) is caught and routes to fallback.
- Parse failure (`_parse_llm_response` returns `None`) also routes to fallback.
- `report_id`, `cluster_id`, `generated_at` always set in code, never from LLM.
- Returns a valid `BlufReport` in all cases.

**Todo List**
- [ ] Add `_resolve_alerts()` local helper (same pattern as other service modules).
- [ ] Implement `generate_bluf()` full control flow.
- [ ] Catch `RuntimeError` from `generate()` and call `_fallback_bluf()`.
- [ ] On successful LLM response, attempt parse; if `None`, call `_fallback_bluf()`.
- [ ] Assemble `BlufReport` with code-set fields + LLM/fallback fields.

**Status:** [ ] pending

---

## Files Changed

| File | Action |
|------|--------|
| `app/models/alert.py` | Edit — add `BlufReport` model, add `timezone` to datetime import |
| `app/services/bluf_generator.py` | Create (new file) |
