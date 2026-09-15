"""
Ingestion service.

Decision this encodes: mock JSON loaded at startup, not a live /ingest endpoint.
No real-time source is being simulated — everything is demo data — so a fake
"live" endpoint would add a failure point (something to break on stage) without
proving anything real. Startup load is simpler and never breaks mid-demo.

One normalizer function per source type. Each takes that source's raw shape
and returns a list[NormalizedAlert]. If you add a new source later, add one
function here and one line in normalize_all() — nothing else changes.
"""

import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import cast

from app.models.alert import NormalizedAlert, SourceType


DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _load(filename: str) -> dict | list[dict]:
    """Load a JSON file from the backend data directory."""
    path = DATA_DIR / filename

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _normalize_siem(raw: list[dict]) -> list[NormalizedAlert]:
    out = []

    for i, r in enumerate(raw):
        out.append(
            NormalizedAlert(
                alert_id=f"SIEM-{i:04d}",
                source=SourceType.SIEM,
                timestamp=datetime.fromisoformat(
                    r["detected_at"].replace("Z", "+00:00")
                ),
                entity=r["host"],
                indicator=r.get("src_ip") or r["host"],
                title=r["rule_name"],
                raw_text=(
                    f"{r['rule_name']} on {r['host']} "
                    f"(process: {r.get('process')})"
                ),
                severity_hint=r.get("severity"),
            )
        )

    return out


def _normalize_network_sensor(raw: list[dict]) -> list[NormalizedAlert]:
    out = []

    for i, r in enumerate(raw):
        out.append(
            NormalizedAlert(
                alert_id=f"NET-{i:04d}",
                source=SourceType.NETWORK_SENSOR,
                timestamp=datetime.fromisoformat(
                    r["timestamp"].replace("Z", "+00:00")
                ),
                entity=r["src_host"],
                indicator=r["dest_ip"],
                title=r["event"],
                raw_text=(
                    f"{r['event']} — {r['src_host']} -> {r['dest_ip']} "
                    f"({r['protocol']}, {r['bytes_transferred']} bytes)"
                ),
                severity_hint=None,
            )
        )

    return out


def _normalize_auth_logs(raw: list[dict]) -> list[NormalizedAlert]:
    out = []

    for i, r in enumerate(raw):
        title = (
            f"Auth {r['result']} — "
            f"{r['user']} via {r['auth_method']}"
        )

        out.append(
            NormalizedAlert(
                alert_id=f"AUTH-{i:04d}",
                source=SourceType.AUTH_LOG,
                timestamp=datetime.fromisoformat(
                    r["time"].replace("Z", "+00:00")
                ),
                entity=r["host"],
                indicator=r["src_ip"],
                title=title,
                raw_text=f"{title} on {r['host']}",
                severity_hint=(
                    "HIGH" if r["result"] == "fail" else None
                ),
            )
        )

    return out


def _normalize_firewall(raw: list[dict]) -> list[NormalizedAlert]:
    out = []

    for i, r in enumerate(raw):
        out.append(
            NormalizedAlert(
                alert_id=f"FW-{i:04d}",
                source=SourceType.FIREWALL,
                timestamp=datetime.fromisoformat(
                    r["log_time"].replace("Z", "+00:00")
                ),
                entity=r["src"],
                indicator=r["dst"],
                title=r["threat_name"],
                raw_text=(
                    f"{r['threat_name']} — "
                    f"{r['src']} -> {r['dst']} "
                    f"(action: {r['action_taken']})"
                ),
                severity_hint=(
                    r.get("severity", "").upper() or None
                ),
            )
        )

    return out


def _normalize_threat_intel(raw: list[dict]) -> list[NormalizedAlert]:
    out = []

    for i, r in enumerate(raw):
        out.append(
            NormalizedAlert(
                alert_id=f"TI-{i:04d}",
                source=SourceType.THREAT_INTEL,
                timestamp=datetime.fromisoformat(
                    r["published"].replace("Z", "+00:00")
                ),
                entity=r["related_indicator"],
                indicator=r["related_indicator"],
                title=f"Intel report {r['report_id']}",
                raw_text=r["summary"],
                severity_hint=(
                    r.get("confidence", "").upper() or None
                ),
            )
        )

    return out


def normalize_all() -> list[NormalizedAlert]:
    """
    Load every mock source and return one flat list of NormalizedAlert.

    Timestamps are shifted forward so the most recent alert always lands at
    the current time. This keeps mock data perpetually "live" — risk scoring's
    recency check fires correctly regardless of when the app is started,
    without any changes to the scoring logic itself.
    """

    alerts: list[NormalizedAlert] = []

    alerts += _normalize_siem(
        cast(list[dict], _load("siem_alerts.json"))
    )

    alerts += _normalize_network_sensor(
        cast(list[dict], _load("network_sensor_alerts.json"))
    )

    alerts += _normalize_auth_logs(
        cast(list[dict], _load("auth_logs.json"))
    )

    alerts += _normalize_firewall(
        cast(list[dict], _load("next_gen_firewall.json"))
    )

    alerts += _normalize_threat_intel(
        cast(list[dict], _load("threat_intel_reports.json"))
    )

    alerts = sorted(alerts, key=lambda a: a.timestamp)

    # Slide all timestamps forward so the newest alert is always "now".
    shift: timedelta = (
        datetime.now(timezone.utc) - max(a.timestamp for a in alerts)
    )

    alerts = [
        a.model_copy(update={"timestamp": a.timestamp + shift})
        for a in alerts
    ]

    return alerts


def load_known_bad_indicators() -> dict:
    """Load known-bad threat indicators."""
    return cast(dict, _load("known_bad_indicators.json"))


def load_allowlist() -> dict:
    """Load allowlisted indicators/entities."""
    return cast(dict, _load("allowlist.json"))