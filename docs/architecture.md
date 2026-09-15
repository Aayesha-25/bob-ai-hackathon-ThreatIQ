ARES — System Architecture

ARES (Threat Intelligence Correlation & Alert Prioritisation Assistant) is a FastAPI-based security intelligence
application with a browser-based command-center interface. The system ingests simulated security telemetry from
multiple intelligence sources, normalizes events, correlates related alerts into investigation clusters, calculates
explainable risk scores, maps activity to MITRE ATT&CK techniques, and generates commander-ready BLUF reports
using an external LLM provider.

Prototype boundary: All telemetry and intelligence data is simulated. ARES does not connect to live defence, SOC,
SIEM, firewall, or intelligence infrastructure.

System Architecture

Analyst / Browser
|
HTTP
v
ARES Frontend (HTML, Jinja2, Tailwind CSS, JavaScript)
|
REST API
v
FastAPI Backend
|
v
Data Ingestion & Normalization
|
+--> Simulated SIEM
+--> Simulated Network Sensor
+--> Simulated Authentication Logs
+--> Simulated Firewall
+--> Simulated Threat Intelligence
|
v
Normalized Alert Schema
|
v
Correlation Engine
|
v
Investigation Clusters
|
+--> Risk Scoring Engine
| |
| v
| Risk Prioritisation
|
+--> MITRE ATT&CK Mapping
|
+--> BLUF Generation --> External LLM Provider
|
v
ARES Command Center / Analyst Views

## Components

| Component | Technology | Responsibility |
|---|---|---|
| Frontend | HTML, Jinja2, Tailwind CSS, JavaScript | Command-center UI, alert visualization, investigations, MITRE mapping, source monitoring, and BLUF reports |
| Backend API | Python, FastAPI | API routing, orchestration, data processing, correlation, scoring, ATT&CK mapping, and report generation |
| Data Ingestion | Python | Loads and normalizes simulated SIEM, network, authentication, firewall, and threat-intelligence events |
| Correlation Engine | Python | Groups related alerts using indicator matching and entity/time-window correlation |
| Risk Scoring | Python | Calculates explainable investigation risk scores using multiple weighted signals |
| MITRE ATT&CK Mapping | Python | Maps correlated activity to observed ATT&CK techniques using pattern-based detection and an LLM fallback path |
| AI / LLM | External LLM provider via configured API | Generates commander-ready BLUF summaries from correlated investigation evidence |
| Investigation Layer | FastAPI + frontend templates | Presents clusters, evidence, risk, techniques, and recommended actions to analysts |
| BLUF Reporting | Python + LLM | Converts investigation evidence into concise assessments and recommended actions |
| Data Storage | In-memory application data / simulated dataset | Provides deterministic demo telemetry and derived investigation results |
| Notifications | None | No external notification service is connected in the prototype |

## Data Flow

1. Simulated security events are loaded from SIEM, network sensor, authentication logs, firewall alerts, and threat intelligence.
2. The ingestion layer normalizes source-specific formats into a common alert schema.
3. The correlation engine performs indicator-based matching and entity/time-window correlation.
4. Related alerts are grouped into investigation clusters representing potential incidents.
5. The risk scoring engine evaluates severity, source diversity, recency, known-bad indicators, and allowlist penalties.
6. Each cluster receives an explainable risk score and priority classification.
7. The ATT&CK mapping layer identifies relevant MITRE ATT&CK techniques from observed behaviour.
8. Investigation results are exposed through FastAPI REST endpoints consumed by the frontend.
9. The frontend presents alerts, clusters, risk factors, source information, ATT&CK mappings, and analyst views.
10. For BLUF generation, the backend assembles investigation evidence and sends the relevant context to the configured LLM provider.
11. The generated BLUF is returned through the API and displayed as a commander-ready threat assessment.

## Core Pipeline

```text
Simulated Telemetry
        ↓
Ingestion & Normalization
        ↓
Alert Correlation
        ↓
Investigation Clusters
        ↓
Risk Scoring
        ↓
MITRE ATT&CK Mapping
        ↓
BLUF Generation
        ↓
Analyst / Commander View
```

## Security Considerations

- Prototype telemetry is explicitly simulated and does not represent live operational security data.
- External API credentials are configured through environment variables and should not be committed to source control.
- Backend processing is separated from the frontend through REST API boundaries.
- The API exposes only the simulated dataset used by the prototype.
- BLUF generation uses investigation evidence assembled by the backend.
- User-facing pages identify simulated/demo content where appropriate.
- The prototype does not claim production authentication, authorization, classified-data handling, or operational security controls.

## Scalability Notes

- Replace simulated ingestion with SIEM, EDR, firewall, authentication, network, and threat-intelligence connectors.
- Move alert and investigation persistence into PostgreSQL or another production database.
- Run ingestion and correlation as asynchronous background workers.
- Partition correlation workloads by time window, entity, or indicator.
- Cache frequently accessed investigation and BLUF results.
- Deploy stateless FastAPI instances horizontally behind a load balancer.
- Introduce authentication, role-based authorization, audit logging, and secure secret management.
- Use a controlled, versioned ATT&CK knowledge source.
- Persist analyst assignment, investigation status, notes, and case history.
- Add queues or streaming infrastructure for continuous telemetry ingestion.
- Monitor API latency, ingestion failures, correlation performance, LLM latency, and generation failures.
- Apply rate limiting and controlled concurrency around external LLM calls.
- Require human approval before automated response or containment actions.
