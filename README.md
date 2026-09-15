# 🚀 ARES — Threat Intelligence Correlation & Alert Prioritisation Assistant

> **An AI-assisted security intelligence command center that transforms fragmented alerts into correlated investigations, explainable risk priorities, and commander-ready BLUF reports.**

---

## 👥 Team

| Field         | Value     |
| ------------- | --------- |
| ThreatIQ      | ThreatIQ  |
| **Track**     | AI / Open |
| **Team Lead** | Aayesha   |
| **Members**   | Aayesha,yashvi,krishali and keya   |

---

## 🎯 Problem Statement

Security analysts face large volumes of fragmented alerts across SIEM, authentication, network, firewall, and threat-intelligence sources. The challenge is not simply detecting alerts, but determining which events belong to the same threat, how serious the combined activity is, and how to communicate the resulting assessment quickly to decision-makers.

ARES addresses this alert-overload problem by correlating multi-source security evidence into prioritised investigations, reducing manual triage and helping analysts move from fragmented observations to an actionable threat assessment.

---

## 💡 Solution

ARES is a FastAPI-based threat intelligence command center that normalizes simulated security telemetry, correlates related alerts across multiple sources, calculates explainable risk scores, maps observed activity to MITRE ATT&CK techniques, and generates AI-assisted BLUF (Bottom Line Up Front) reports.

The core workflow is **alert → correlation → investigation → risk → ATT&CK → intelligence report**, allowing analysts to focus on the highest-risk activity instead of manually connecting isolated alerts.

---

## ✨ Key Features

* **Multi-Source Alert Normalization:** Converts simulated SIEM, network sensor, authentication, firewall, and threat-intelligence events into a common alert model.

* **Cross-Source Correlation:** Connects related alerts using indicator matching and entity/time-window correlation to create investigation clusters.

* **Explainable Risk Prioritisation:** Scores investigations using known-bad indicators, source diversity, recency, severity signals, and allowlist penalties, with a visible risk breakdown.

* **MITRE ATT&CK Mapping:** Derives ATT&CK techniques from correlated security activity and presents observed techniques, tactics, confidence, and supporting investigations.

* **AI-Assisted BLUF Generation:** Uses an external LLM to transform correlated evidence into concise commander-ready reports containing the bottom line, threat classification, confidence, evidence, ATT&CK techniques, and recommended action.

* **Security Intelligence Command Center:** Provides a unified interface for alerts, investigations, intelligence sources, MITRE ATT&CK mappings, BLUF reports, and operational summaries.

---

## 🛠️ Tech Stack

| Category             | Technologies                              |
| -------------------- | ----------------------------------------- |
| **Languages**        | Python, JavaScript, HTML, CSS             |
| **Frameworks**       | FastAPI, Jinja2, Uvicorn, Tailwind CSS    |
| **IBM Technologies** | IBM Bob AI-assisted development workflow  |
| **AI / LLM**         | External LLM API for BLUF generation      |
| **Databases**        | In-memory simulated dataset for prototype |
| **Other**            | REST APIs, Git, GitHub Actions, Mermaid   |

---

## 📁 Repository Structure

```text
├── src/                         # Application source code
│   └── app/                     # FastAPI backend and application logic
│
├── docs/                        # Written documentation
│   ├── problem-statement.md
│   ├── solution-overview.md
│   ├── architecture.md
│   └── setup-guide.md
│
├── demo/                        # Demo artifacts
│   ├── screenshots/             # Application screenshots
│   └── demo-video-link.txt      # Demo video link
│
├── presentation/                # Hackathon presentation
│
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment variable template
├── .gitignore                   # Repository exclusions
├── submission.yaml               # Structured submission metadata
└── README.md                    # Project overview
```

---

## ⚡ How to Run

> **The commands below mirror the project's setup workflow. See [`docs/setup-guide.md`](docs/setup-guide.md) for the complete setup instructions.**

```bash
# 1. Clone the repo
git clone https://github.com/Aayesha-25/bob-ai-hackathon-ThreatIQ.git
cd bob-ai-hackathon-ThreatIQ

# 2. Create and activate a virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
copy .env.example .env

# Linux / macOS:
# cp .env.example .env

# Edit .env with the required LLM API configuration

# 5. Run the FastAPI application
uvicorn app.main:app --reload
```

> **Note:** The application uses simulated security telemetry. LLM-generated BLUF functionality requires the appropriate API credentials configured in `.env`.

---

## 🖥️ Demo

| Artifact        | Link                                                     |
| --------------- | -------------------------------------------------------- |
| 📹 Demo Video   | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 🌐 Live Demo    | [See demo/live-demo-url.txt](demo/live-demo-url.txt)     |
| 🖼️ Screenshots | [See demo/screenshots/](demo/screenshots/)               |
| 📊 Presentation | [See presentation/](presentation/)                       |

> **Demo environment:** ARES uses simulated security telemetry and is intended for demonstration and evaluation. It does not connect to live defence, military, SOC, SIEM, firewall, EDR, or classified intelligence infrastructure.

---

## ⚠️ Known Limitations

> ARES is a hackathon prototype. Limitations are intentionally disclosed rather than presenting simulated capabilities as production functionality.

* **Simulated telemetry:** The current implementation uses deterministic simulated data rather than live SIEM, EDR, firewall, authentication, network, or threat-intelligence feeds.

* **Prototype persistence:** Alert and investigation results are derived from an in-memory simulated dataset rather than a production database.

* **Investigation workflow:** Analyst assignment, status updates, and notes are currently demonstrated as prototype interactions rather than a persistent case-management system.

* **ATT&CK integration:** ATT&CK mapping is generated from the prototype's backend logic and metadata; ARES does not query the live MITRE ATT&CK platform.

* **No autonomous response:** Recommended actions are presented as analyst guidance. The prototype does not automatically isolate endpoints, block network traffic, or modify real security infrastructure.

* **LLM dependency:** BLUF generation requires an available external LLM API and appropriate credentials.

* **Production security controls:** Enterprise authentication, role-based access control, persistent audit logging, production secret management, and classified-data handling are outside the scope of this hackathon prototype.

---

## 🏅 What We're Most Proud Of

The strongest part of ARES is that it demonstrates a complete **security intelligence reasoning pipeline**, rather than only presenting a visual dashboard.

Starting with **13 simulated alerts across five intelligence sources**, ARES normalizes the events, correlates related evidence into **three investigation clusters**, calculates explainable risk, identifies ATT&CK techniques, and turns the highest-priority investigation into an AI-assisted BLUF report.

The critical demonstration scenario shows how seemingly separate observations — threat intelligence identifying a Cobalt Strike C2 address, authentication activity, PowerShell execution, unusual outbound traffic, malware detection, firewall telemetry, and network activity — can be connected into a single investigation.

The result is a **100/100 CRITICAL** investigation with evidence-backed ATT&CK mappings and a commander-ready assessment.

The core idea behind ARES is simple:

> **Don't make analysts investigate alerts one by one. Help them understand the incident those alerts collectively describe.**

ARES uses AI as an **analyst multiplier**: correlation and risk scoring establish the investigative context, while the LLM helps transform that evidence into concise decision-support intelligence.

All demonstrated capabilities are clearly labelled as simulated so the prototype remains technically honest while showing how the architecture could evolve into a production SOC/threat-intelligence platform.
