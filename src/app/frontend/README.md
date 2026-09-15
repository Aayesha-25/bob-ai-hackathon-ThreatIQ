# ARES — Threat Intelligence Command Center

ARES is a frontend prototype for a hackathon project:

**Threat Intelligence Correlation & Alert Prioritisation Assistant**

The platform is designed to help defence and SOC analysts manage large volumes of security alerts, correlate related events, prioritise risks, map suspicious activity to MITRE ATT&CK techniques, and generate commander-ready BLUF reports.

---

## Important Demo Notice

> **DEMO ENVIRONMENT — All data shown is simulated. No real-time system connectivity.**

ARES currently uses mock/simulated data only.

It does **not** connect to:

- Real SIEM platforms
- Real network sensors
- Real authentication systems
- Real Palo Alto infrastructure
- Real defence systems
- Real threat-intelligence feeds
- Real databases
- Production APIs

The interface is intended for demonstration and hackathon presentation purposes.

---

# Project Structure

```text
ARES_frontend/
│
├── README.md
│
└── src/
    └── frontend/
        │
        ├── index.html
        │
        ├── templates/
        │   ├── base.html
        │   ├── dashboard.html
        │   ├── alerts.html
        │   ├── investigations.html
        │   ├── investigation_detail.html
        │   ├── mitre.html
        │   ├── sources.html
        │   ├── bluf_reports.html
        │   ├── bluf_report_detail.html
        │   └── settings.html
        │
        ├── partials/
        │   ├── alert_row.html
        │   ├── alert_table.html
        │   ├── incident_card.html
        │   └── bluf_report.html
        │
        └── static/
            └── js/
                └── charts.js