# Problem Statement

## Background

Security operations teams receive large volumes of alerts from different sources such as SIEM systems, network monitoring, authentication systems, firewalls, and threat-intelligence feeds. These alerts often describe related activity but are presented as separate events.

ARES (Threat Intelligence Command Center) is a simulated cybersecurity operations platform designed to correlate these heterogeneous security events into meaningful threat investigations. The system demonstrates how raw security telemetry can be normalized, correlated, prioritized, mapped to MITRE ATT&CK techniques, and summarized for analysts and commanders.

## The Problem

The main problem is the difficulty of turning large numbers of isolated security alerts into a clear and prioritized understanding of an ongoing threat.

Individual alerts may contain useful evidence such as suspicious IP addresses, domains, hosts, authentication activity, malware indicators, PowerShell activity, network behavior, or firewall detections. However, when these events are viewed independently, analysts may have difficulty identifying that they belong to the same potential attack sequence.

ARES addresses this problem by providing a simulated correlation and threat-intelligence workflow that:

- Normalizes security events from multiple simulated sources.
- Correlates alerts using shared entities, indicators, and time relationships.
- Groups related alerts into investigation clusters.
- Calculates explainable risk scores and assigns risk levels.
- Maps correlated activity to MITRE ATT&CK techniques.
- Provides investigation-oriented views for analysts.
- Generates commander-ready BLUF (Bottom Line Up Front) summaries from correlated evidence.

The goal is not to replace a production SOC or perform automated incident response, but to demonstrate an end-to-end threat-intelligence correlation and investigation workflow.

## Who is Affected

The problem primarily affects:

- **SOC Analysts** who must review and investigate large numbers of security alerts.
- **Threat Intelligence Analysts** who need to connect indicators and observed activity into meaningful threat patterns.
- **Incident Responders** who need a prioritized view of related events during an investigation.
- **Security Managers and Commanders** who require concise summaries of risk, affected assets, and relevant attack techniques.
- **Security Students and Researchers** who need a practical environment for understanding alert correlation, threat prioritization, and ATT&CK-based analysis.

## Why It Matters

Effective alert correlation is important because the security value of an individual alert is often limited without context.

A collection of related alerts can provide stronger evidence of suspicious activity than any single event. By connecting events across different simulated sources, ARES helps demonstrate how analysts can move from raw telemetry to an investigation-level view.

Risk prioritization is also important because analysts cannot treat every alert with the same urgency. ARES uses factors such as known-bad indicators, source diversity, recency, severity hints, and allowlist considerations to produce an explainable risk score.

MITRE ATT&CK mapping adds another layer of analytical context by connecting observed activity with recognized adversary tactics and techniques. This makes the resulting investigation easier to understand, communicate, and evaluate.

## Why Existing Solutions Fall Short

Traditional security platforms such as SIEM and security monitoring systems provide valuable alert collection and detection capabilities, but raw alert visibility alone does not guarantee effective investigation-level correlation or clear executive communication.

For this project, ARES focuses specifically on demonstrating the analytical layer between raw alerts and decision-ready intelligence:

- Multiple simulated security sources are brought into a common normalized representation.
- Related events are correlated into investigation clusters rather than treated only as individual alerts.
- Risk scoring provides an explainable basis for prioritization.
- MITRE ATT&CK techniques are associated with correlated activity.
- Investigation views connect alerts, risk, entities, and techniques.
- BLUF reporting converts investigation evidence into concise commander-oriented intelligence.

ARES is intentionally presented as a simulated demonstration environment. It does not claim to provide live production SIEM connectivity, live threat-intelligence feeds, automated containment, or real-world incident response capabilities.
