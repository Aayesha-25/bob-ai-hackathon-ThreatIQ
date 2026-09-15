````md
# ARES Source Code

This directory contains the source code for **ARES — Threat Intelligence Correlation & Alert Prioritisation Assistant**.

ARES is a prototype security intelligence platform that ingests simulated security telemetry, correlates related alerts, prioritises resulting threat clusters, maps observed behaviour to MITRE ATT&CK techniques, and generates commander-ready BLUF reports.

> ⚠️ **Demo / Simulation:** ARES currently operates on simulated security telemetry. It does not connect to live defence, SOC, SIEM, firewall, network-sensor, or threat-intelligence infrastructure.

## Structure

```text
src/
  app/
    main.py                 ← FastAPI application and API/page routes
    ...                     ← ARES processing modules and supporting code
  static/
    ...                     ← Frontend assets
  templates/
    ...                     ← Jinja2 HTML templates
````

The exact implementation structure may vary as the project evolves. The important separation is between the API/application layer, ARES intelligence-processing logic, and the frontend presentation layer.

## Core Processing Pipeline

ARES follows this processing flow:

```text
Simulated Security Sources
          ↓
Alert Normalisation
          ↓
Cross-Source Correlation
          ↓
Risk Scoring
          ↓
MITRE ATT&CK Mapping
          ↓
BLUF Intelligence Generation
          ↓
Command-Centre Presentation
```

### 1. Data Ingestion

Simulated alerts from multiple security sources are normalised into a common alert representation.

Current simulated sources include:

* SIEM
* Network Sensor
* Authentication Logs
* Firewall
* Threat Intelligence

### 2. Alert Correlation

The correlation engine groups related alerts using:

* Indicator matching
* Entity/asset relationships
* Time-window relationships

This converts individual alerts into higher-level investigation clusters.

### 3. Risk Scoring

Correlated clusters receive a risk score based on multiple signals, including:

* Known malicious indicators
* Source diversity
* Recency
* Severity indicators
* Allowlist/false-positive penalties

The resulting score is used to prioritise investigations.

### 4. MITRE ATT&CK Mapping

ARES maps observed alert behaviour to relevant MITRE ATT&CK techniques.

The prototype currently includes mappings such as:

* T1071.001 — Web Protocols
* T1059.001 — PowerShell
* T1110 — Brute Force
* T1547 — Boot or Logon Autostart Execution
* T1595 — Active Scanning

These mappings are generated from the simulated ARES correlation results and are not retrieved from the live MITRE ATT&CK platform.

### 5. BLUF Generation

ARES generates commander-oriented **Bottom Line Up Front (BLUF)** intelligence reports from the correlated threat context.

Reports include:

* Bottom line
* Threat classification
* Confidence
* Attack techniques
* Supporting evidence
* Recommended action

The LLM is used for intelligence synthesis and report generation; the underlying alert correlation and risk-scoring pipeline remains application-controlled.

## API Layer

The FastAPI application exposes endpoints for:

* System status
* Alerts
* Intelligence sources
* Correlated clusters
* Individual cluster details
* BLUF reports

Examples:

```text
GET /api/status
GET /api/alerts
GET /api/sources
GET /api/clusters
GET /api/clusters/{cluster_id}
GET /api/clusters/{cluster_id}/bluf
```

## Frontend

The frontend is served through the FastAPI application using Jinja2 templates and static assets.

The command-centre interface includes:

* Dashboard
* Alert Intelligence
* Investigations
* MITRE ATT&CK
* Intelligence Sources
* BLUF Reports
* Settings

The interface is designed as an enterprise security operations/intelligence command centre rather than a consumer-facing application.

## Configuration

Environment-specific configuration should be stored in `.env`.

A safe template is provided as:

```text
.env.example
```

**Never commit real API keys, credentials, database passwords, webhook URLs, or other secrets.**

## Dependencies

Python dependencies are defined in the project's dependency manifest, such as:

```text
requirements.txt
```

Install dependencies using the project's documented setup instructions before starting the application.

## Running the Application

From the project root:

```bash
uvicorn app.main:app --reload --port 8000
```

The application is then available at:

```text
http://127.0.0.1:8000
```

Refer to `docs/setup-guide.md` for the authoritative project setup and execution instructions.

## Demo Data

The prototype intentionally uses simulated security events so that the complete intelligence workflow can be demonstrated without access to real security infrastructure.

The current demonstration dataset contains:

* 13 simulated alerts
* 3 correlated investigation clusters
* Multiple risk priorities
* MITRE ATT&CK mappings
* Generated BLUF intelligence reports

## Security & Safety

ARES is a demonstration prototype.

It should **not** be connected to production security infrastructure without appropriate security engineering, authentication, authorisation, logging, secrets management, validation, and operational controls.

No production credentials or real classified/sensitive security information should be committed to this repository.

## Development Principles

When extending ARES:

1. Keep ingestion, correlation, scoring, mapping, and reporting logically separated.
2. Prefer backend-generated data over duplicated frontend mock data.
3. Keep simulated/demo data clearly labelled.
4. Never commit secrets.
5. Preserve the existing submission template and repository structure.
6. Document significant architectural or dependency changes.

```
