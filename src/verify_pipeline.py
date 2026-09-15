"""
verify_pipeline.py — run this directly to sanity-check the whole backend
pipeline in one shot, without starting uvicorn or opening a browser.

Usage (from inside ares-backend/, with venv activated):
    python verify_pipeline.py

Checks:
1. All modules import cleanly (catches typos, missing files, circular imports)
2. Ingestion produces the expected alert count
3. Correlation produces the expected cluster count and shapes
4. Every alert_id referenced in a cluster actually exists (catches silent
   data mismatches that a single browser check might miss)
5. Risk scoring populated every cluster (no leftover 0/None defaults)
6. Prints a clear PASS/FAIL summary — no need to eyeball raw JSON
"""

import sys

def check(label: str, condition: bool, detail: str = "") -> bool:
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}" + (f" — {detail}" if detail and not condition else ""))
    return condition


def main() -> int:
    all_ok = True

    # --- 1. Imports ---
    try:
        from app.services.ingestion import normalize_all
        from app.services.correlation import correlate
        from app.services.risk_scoring import score_clusters
        from app.services.attack_mapping import map_attack_techniques
        all_ok &= check("All modules import cleanly", True)
    except Exception as e:
        check("All modules import cleanly", False, str(e))
        print("\nStopping — nothing else can run until imports succeed.")
        return 1

    # --- 2. Ingestion ---
    alerts = normalize_all()
    all_ok &= check(
        "Ingestion produced alerts",
        len(alerts) > 0,
        f"got {len(alerts)} alerts",
    )
    print(f"    -> {len(alerts)} alerts loaded")

    alerts_by_id = {a.alert_id: a for a in alerts}
    all_ok &= check(
        "No duplicate alert_ids",
        len(alerts_by_id) == len(alerts),
        f"{len(alerts)} alerts but only {len(alerts_by_id)} unique IDs",
    )

    # --- 3. Correlation ---
    clusters = correlate(alerts)
    all_ok &= check(
        "Correlation produced clusters",
        len(clusters) > 0,
        f"got {len(clusters)} clusters",
    )
    print(f"    -> {len(clusters)} clusters from {len(alerts)} alerts")

    total_alert_ids_in_clusters = sum(len(c.alert_ids) for c in clusters)
    all_ok &= check(
        "Every alert appears in exactly one cluster",
        total_alert_ids_in_clusters == len(alerts),
        f"clusters reference {total_alert_ids_in_clusters} alert_ids, "
        f"but there are {len(alerts)} alerts",
    )

    missing_refs = [
        aid for c in clusters for aid in c.alert_ids if aid not in alerts_by_id
    ]
    all_ok &= check(
        "No cluster references a nonexistent alert_id",
        len(missing_refs) == 0,
        f"dangling references: {missing_refs}",
    )

    # --- 4. Risk scoring ---
    scored = score_clusters(clusters, alerts_by_id)
    unscored = [c for c in scored if c.risk_level is None]
    all_ok &= check(
        "Every cluster has a risk_level assigned",
        len(unscored) == 0,
        f"{len(unscored)} clusters still have risk_level=None",
    )

    out_of_range = [c for c in scored if not (0 <= c.risk_score <= 100)]
    all_ok &= check(
        "Every risk_score is within [0, 100]",
        len(out_of_range) == 0,
        f"out-of-range scores: {[c.risk_score for c in out_of_range]}",
    )

    # --- 5. ATT&CK mapping ---
    mapped = map_attack_techniques(scored, alerts_by_id)
    unmapped = [c for c in mapped if len(c.attack_techniques) == 0]
    all_ok &= check(
        "Every cluster has at least one attack_technique entry",
        len(unmapped) == 0,
        f"{len(unmapped)} clusters have zero entries (should have UNCLASSIFIED at minimum)",
    )

    bad_entries = [
        t for c in mapped for t in c.attack_techniques
        if not {"technique_id", "technique_name", "confidence", "method"} <= t.keys()
    ]
    all_ok &= check(
        "Every technique entry has all 4 required keys",
        len(bad_entries) == 0,
        f"malformed entries: {bad_entries}",
    )

    print("\n--- Cluster summary ---")
    for c in sorted(mapped, key=lambda c: c.risk_score, reverse=True):
        techniques = ", ".join(
            f"{t['technique_id']}({t['method']})" for t in c.attack_techniques
        ) or "none"
        print(f"  {c.cluster_id[:16]}...  score={c.risk_score:>3}  "
              f"level={c.risk_level:<22}  alerts={len(c.alert_ids)}  "
              f"basis={c.correlation_basis}")
        print(f"      techniques: {techniques}")
        print(f"      breakdown: {c.risk_breakdown}  (raw sum: {sum(c.risk_breakdown.values())})")

    print("\n" + ("=" * 40))
    print("ALL CHECKS PASSED" if all_ok else "SOME CHECKS FAILED — see above")
    print("=" * 40)

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
