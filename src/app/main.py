
from collections import Counter
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.services.ingestion import normalize_all
from app.services.correlation import correlate
from app.services.risk_scoring import score_clusters
from app.services.attack_mapping import map_attack_techniques
from app.services.bluf_generator import generate_bluf


app = FastAPI(title="ARES — Threat Intelligence Command Center")


# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------

# Serve charts.js and any other static assets from app/frontend/static.
app.mount(
    "/static",
    StaticFiles(directory="app/frontend/static"),
    name="static",
)

templates = Jinja2Templates(directory="app/frontend/templates")


# ---------------------------------------------------------------------------
# Backend pipeline
#
# The complete mock intelligence pipeline is computed once at startup:
#
# 1. Ingestion / normalization
# 2. Correlation
# 3. Risk scoring
# 4. MITRE ATT&CK mapping
#
# This keeps cluster IDs and the shifted "now" stable for the running
# application session.
# ---------------------------------------------------------------------------

_ALERTS = normalize_all()

_ALERTS_BY_ID = {
    alert.alert_id: alert
    for alert in _ALERTS
}

_CLUSTERS = correlate(_ALERTS)

_CLUSTERS = score_clusters(
    _CLUSTERS,
    _ALERTS_BY_ID,
)

_CLUSTERS = map_attack_techniques(
    _CLUSTERS,
    _ALERTS_BY_ID,
)

_CLUSTERS_BY_ID = {
    cluster.cluster_id: cluster
    for cluster in _CLUSTERS
}

_BLUF_CACHE: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Intelligence source metadata
#
# Event counts and latest-event timestamps are derived from the actual
# normalized backend alerts.
#
# Reliability, descriptions, and event types are explicit DEMO metadata.
# They are not presented as measurements from a live production system.
# ---------------------------------------------------------------------------

_SOURCE_METADATA = {
    "siem": {
        "name": "SIEM Alerts",
        "short_name": "SIEM",
        "icon": "S",
        "reliability": 94,
        "description": (
            "Security Information and Event Management alerts."
        ),
        "event_types": [
            "Authentication",
            "Endpoint",
            "Policy Violation",
            "Privilege Activity",
        ],
    },

    "network_sensor": {
        "name": "Network Sensor Alerts",
        "short_name": "NET",
        "icon": "N",
        "reliability": 89,
        "description": (
            "Network telemetry and suspicious traffic detections."
        ),
        "event_types": [
            "Port Scan",
            "Suspicious Traffic",
            "DNS Anomaly",
            "Lateral Movement",
        ],
    },

    "auth_log": {
        "name": "Authentication Logs",
        "short_name": "AUTH",
        "icon": "A",
        "reliability": 96,
        "description": (
            "Authentication and account activity telemetry."
        ),
        "event_types": [
            "Failed Login",
            "Impossible Travel",
            "New Device",
            "Privilege Change",
        ],
    },

    "firewall": {
        "name": "Palo Alto Alerts",
        "short_name": "PA",
        "icon": "P",
        "reliability": 91,
        "description": (
            "Next-generation firewall security alerts."
        ),
        "event_types": [
            "Threat Prevention",
            "URL Filtering",
            "Command & Control",
            "Malware Detection",
        ],
    },

    "threat_intel": {
        "name": "Threat Intelligence Reports",
        "short_name": "TI",
        "icon": "T",
        "reliability": 87,
        "description": (
            "Threat intelligence indicators and contextual reports."
        ),
        "event_types": [
            "IP Indicator",
            "Domain Indicator",
            "Hash Indicator",
            "Campaign Context",
        ],
    },
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _cluster_with_alerts(cluster) -> dict:
    """
    Shape a cluster for API/template rendering.

    Returns the cluster fields plus expanded member alerts.
    """

    data = cluster.model_dump()

    data["alerts"] = [
        _ALERTS_BY_ID[alert_id].model_dump()
        for alert_id in cluster.alert_ids
        if alert_id in _ALERTS_BY_ID
    ]

    return data


def _get_or_generate_bluf(cluster_id: str) -> dict:
    """
    Generate a BLUF report for one cluster, or return the cached report.
    """

    if cluster_id not in _BLUF_CACHE:
        cluster = _CLUSTERS_BY_ID[cluster_id]

        report = generate_bluf(
            cluster,
            _ALERTS_BY_ID,
        )

        _BLUF_CACHE[cluster_id] = report.model_dump()

    return _BLUF_CACHE[cluster_id]


def _report_for_template(cluster) -> dict:
    """
    Join a cluster's BLUF report with cluster fields required by the
    BLUF reports template.
    """

    bluf = _get_or_generate_bluf(
        cluster.cluster_id
    )

    priority_map = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "LIKELY_FALSE_POSITIVE": "Low",
    }

    return {
        **bluf,

        "title": (
            getattr(cluster, "title", None)
            or bluf.get(
                "threat_classification",
                "Untitled Cluster",
            )
        ),

        "risk_score": cluster.risk_score,

        "priority": priority_map.get(
            cluster.risk_level,
            "Low",
        ),

        "status": "Published",

        "investigation_id": cluster.cluster_id,

        "analyst": "Unassigned",

        "evidence_count": len(
            bluf.get(
                "supporting_evidence",
                [],
            )
        ),

        "attack_techniques": cluster.attack_techniques,
    }


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
    )


@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request):
    # alerts.html fetches /api/clusters directly using client-side JS.
    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
    )


@app.get("/investigations", response_class=HTMLResponse)
def investigations_page(request: Request):
    """
    investigations.html currently expects a single investigation object.

    Until a separate investigation-management workflow exists, the page
    displays the highest-risk correlated cluster.
    """

    top_cluster = max(
        _CLUSTERS,
        key=lambda cluster: cluster.risk_score,
        default=None,
    )

    investigation = None

    if top_cluster:
        alerts = [
            _ALERTS_BY_ID[alert_id].model_dump()
            for alert_id in top_cluster.alert_ids
            if alert_id in _ALERTS_BY_ID
        ]

        investigation = {
            "id": top_cluster.cluster_id,

            "title": (
                getattr(top_cluster, "title", None)
                or f"Cluster — {top_cluster.risk_level}"
            ),

            "severity": top_cluster.risk_level,

            "status": "Investigating",

            "risk": top_cluster.risk_score,

            "alerts": len(alerts),

            "assets": len({
                alert["entity"]
                for alert in alerts
                if alert.get("entity")
            }),

            "mitre_count": len(
                top_cluster.attack_techniques
            ),

            "analyst": "Unassigned",

            "created": "Today",
        }

    return templates.TemplateResponse(
        request=request,
        name="investigations.html",
        context={
            "investigation": investigation,
        },
    )


@app.get(
    "/investigations/{cluster_id}",
    response_class=HTMLResponse,
)
def investigation_detail_page(
    request: Request,
    cluster_id: str,
):
    """
    Render an investigation detail page for the selected cluster.
    """

    cluster = _CLUSTERS_BY_ID.get(cluster_id)

    if cluster is None:
        return templates.TemplateResponse(
            request=request,
            name="investigation_detail.html",
            context={
                "investigation": {
                    "id": cluster_id,
                    "not_found": True,
                }
            },
            status_code=404,
        )

    alerts = [
        _ALERTS_BY_ID[alert_id].model_dump()
        for alert_id in cluster.alert_ids
        if alert_id in _ALERTS_BY_ID
    ]

    investigation = {
        "id": cluster.cluster_id,

        "title": (
            getattr(cluster, "title", None)
            or "Correlated Threat Investigation"
        ),

        "severity": cluster.risk_level,

        "status": "Investigating",

        "risk": cluster.risk_score,

        "alerts": len(alerts),

        "assets": len({
            alert.get("entity")
            for alert in alerts
            if alert.get("entity")
        }),

        "mitre_count": len(
            cluster.attack_techniques
        ),

        "analyst": "Unassigned",

        "created": "Today",
    }

    return templates.TemplateResponse(
        request=request,
        name="investigation_detail.html",
        context={
            "investigation": investigation,
            "cluster_id": cluster.cluster_id,
        },
    )


@app.get("/mitre", response_class=HTMLResponse)
def mitre_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="mitre.html",
    )


@app.get("/sources", response_class=HTMLResponse)
def sources_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="sources.html",
    )


@app.get("/bluf", response_class=HTMLResponse)
def bluf_reports_page(request: Request):
    reports = [
        _report_for_template(cluster)
        for cluster in _CLUSTERS
    ]

    return templates.TemplateResponse(
        request=request,
        name="bluf_reports.html",
        context={
            "reports": reports,
        },
    )


@app.get(
    "/bluf/{cluster_id}",
    response_class=HTMLResponse,
)
def bluf_report_detail_page(
    request: Request,
    cluster_id: str,
):
    # The current BLUF detail template is static demo content.
    # The API endpoint below remains available for actual cluster-specific
    # BLUF data.
    return templates.TemplateResponse(
        request=request,
        name="bluf_report_detail.html",
    )


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
    )


# ---------------------------------------------------------------------------
# JSON API
# ---------------------------------------------------------------------------

@app.get("/api/sources")
def get_sources():
    """
    Return intelligence-source information.

    Dynamic fields:
      - events
      - lastEvent
      - active_sources
      - events_ingested

    Demo metadata:
      - reliability
      - description
      - eventTypes
    """

    source_counts = Counter(
        alert.source
        for alert in _ALERTS
    )

    latest_by_source = {}

    for alert in _ALERTS:
        source_key = alert.source

        current_latest = latest_by_source.get(
            source_key
        )

        if (
            current_latest is None
            or alert.timestamp > current_latest
        ):
            latest_by_source[source_key] = alert.timestamp
    sources = []

    for source_id, metadata in _SOURCE_METADATA.items():
        latest_event = latest_by_source.get(
            source_id
        )

        sources.append({
            "id": source_id,
            "name": metadata["name"],
            "shortName": metadata["short_name"],
            "icon": metadata["icon"],
            "events": sum(1 for alert in _ALERTS if alert.source == source_id),
            "lastEvent": latest_event.isoformat() if latest_event else None,
            "reliability": metadata["reliability"],
            "description": metadata["description"],
            "eventTypes": metadata["event_types"],
        })

    return {
        "sources": sources,
        "active_sources": len(sources),

        "events_ingested": len(
            _ALERTS
        ),

        "demo": True,
    }
@app.get("/api/alerts")
def get_alerts():
    """
    Return all normalized alerts.
    """

    return [
        {
            "id": alert.alert_id,
            "source": alert.source,
            "timestamp": alert.timestamp.isoformat(),
            "entity": alert.entity,
            "indicator": alert.indicator,
            "title": alert.title,
            "description": alert.raw_text,
            "severity": alert.severity_hint,
        }
        for alert in _ALERTS
    ]
@app.get("/api/clusters")
def get_clusters():
    """
    Return all correlated clusters with their expanded alerts.
    """

    return [
        _cluster_with_alerts(cluster)
        for cluster in _CLUSTERS
    ]


@app.get("/api/clusters/{cluster_id}")
def get_cluster(cluster_id: str):
    """
    Return one cluster with its expanded alerts.
    """

    cluster = _CLUSTERS_BY_ID.get(
        cluster_id
    )

    if cluster is None:
        return {
            "error": "cluster not found"
        }, 404

    return _cluster_with_alerts(
        cluster
    )


@app.get("/api/clusters/{cluster_id}/bluf")
def get_bluf(cluster_id: str):
    """
    Return the generated/cached BLUF report for one cluster.
    """

    if cluster_id not in _CLUSTERS_BY_ID:
        return {
            "error": "cluster not found"
        }, 404

    return _get_or_generate_bluf(
        cluster_id
    )


@app.get("/api/status")
def status():
    """
    Basic backend health/status endpoint.
    """

    return {
        "status": "ARES backend running",

        "alert_count": len(
            _ALERTS
        ),

        "cluster_count": len(
            _CLUSTERS
        ),
    }

