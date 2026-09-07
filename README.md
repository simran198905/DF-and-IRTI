# Cross-Vector Forensic & Threat Intelligence Correlation Framework (DF-and-IRTI)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Vanilla JS](https://img.shields.io/badge/ES6-JavaScript-F7DF1E?logo=javascript&logoColor=black)](js/app.js)
[![HTML5 & CSS3](https://img.shields.io/badge/Frontend-HTML5%20%7C%20CSS3-E34F26)](index.html)
[![DFIR Framework](https://img.shields.io/badge/Domain-Digital%20Forensics%20%26%20Incident%20Response-0A84FF)](https://github.com/simran198905/DF-and-IRTI)

> An advanced Digital Forensics and Incident Response (DFIR) multi-incident attribution and causality framework designed to ingest heterogeneous forensic artifacts across multiple vectors, correlate evidence across 6 dimensions, and determine campaign linkages with explainable confidence scoring.

---

## 📌 Overview

Modern targeted intrusions rarely occur in isolation. Threat actors execute coordinated operations across varied vectors—such as identity compromise, cloud control plane manipulation, endpoint persistence, memory injection, and network exfiltration.

The **Cross-Vector Forensic & Threat Intelligence Correlation Framework** ingests, normalizes, and inter-correlates multi-source forensic evidence to:
- Dissect complex attack campaigns across disconnected incident scopes.
- Discover shared IOCs, infrastructure reuse, and overlapping TTPs (MITRE ATT&CK).
- Map temporal sequencing and attack campaign chronologies.
- Compute multi-dimensional causality scores with transparent, explainable attribution rationale.

---

## 🌟 Key Features

### 1. 📊 Investigation Dashboard
- **High-level situational metrics**: Shared nexus IOCs, temporal offset, target alignment, and campaign attribution confidence.
- **Incident Overview Cards**: Drill-down cards for each incident vector with threat group hypotheses.

### 2. 📑 Multi-Vector Evidence Hub
- Comprehensive evidence table spanning multiple telemetry types:
  - Host Forensics (MFT, Registry, Prefetch, Event Logs)
  - Memory Forensics (Injected threads, Volatility artifacts)
  - Network Forensics (PCAP, NetFlow, Zeek/Suricata alerts)
  - Cloud Forensics (AWS CloudTrail, Azure Activity Logs)
  - Identity & Access (IdP logs, OAuth consents, Kerberos tickets)
- Search, filter by source vector, severity, and MITRE ATT&CK technique IDs.
- Dynamic modal to add custom forensic artifacts in real-time.

### 3. 🕸️ Interactive Entity Graph (Force-Directed Visualization)
- Canvas-based interactive knowledge graph connecting:
  - Incident Nodes
  - Threat Actor / Campaign Nodes
  - Shared & Local IOC Nodes (IPs, Hashes, Domains, C2 channels)
  - MITRE ATT&CK TTP Nodes
- Dynamic node clustering, zoom/pan controls, and inspector modal on node selection.

### 4. ⏱️ Chronological Swimlane Timeline
- Multi-lane chronological progression showing relative offsets across parallel intrusion stages.
- Visual nexus flags marking key pivot events and lateral transitions.

### 5. ⚖️ 6-Dimensional Correlation Matrix
- Evaluates multi-incident linkages across 6 analytical vectors:
  1. **Nexus IOC Overlap**: Direct indicators of compromise (IP, Domain, File Hash).
  2. **TTP / Behavioral Fingerprint**: MITRE ATT&CK technique similarities and sub-technique alignment.
  3. **Temporal Proximity & Sequence**: Co-occurrence windows and operational shift matching.
  4. **Target & Scope Proximity**: Sector, org entity, infrastructure co-location.
  5. **Malware / Tooling Lineage**: Shared code patterns, compile timestamps, packing traits.
  6. **Threat Intelligence Feed Matching**: Cross-matching against external CTI feeds (AlienVault, MISP, Mandiant, VirusTotal).

### 6. 📄 DFIR Incident Report Generator
- Produces executive summaries and technical forensic write-ups.
- Formats evidence chains of custody, attribution rationale, and remediation playbooks.
- One-click print / export to PDF.

### 7. 🧪 Academic & Benchmark Evaluation Lab
- Precision, Recall, and F1-Score evaluation benchmarks against ground-truth incident datasets.
- Performance profiling for real-time cross-vector correlation.

---

## 📂 Project Structure

```
DF-and-IRTI/
├── index.html                  # Main Web Application UI
├── styles.css                  # Modern Dark-Themed Cyber UI Stylesheet
├── js/
│   ├── app.js                  # Main Application Orchestrator & State Manager
│   ├── data/
│   │   └── sampleScenarios.js  # Preloaded Multi-Vector DFIR Incidents & CTI Feeds
│   ├── engine/
│   │   ├── correlationEngine.js# 6-Dimensional Cross-Correlation Algorithms
│   │   └── confidenceScorer.js # Attribution & Causality Scoring Engine
│   ├── models/
│   │   └── evidenceSchema.js   # Forensic Data Schemas & Normalizers
│   └── ui/
│       ├── graphVisualizer.js  # Force-directed Canvas Network Graph
│       ├── timelineVisualizer.js # Multi-track Chronological Swimlane
│       └── reportGenerator.js  # Formal DFIR Markdown/HTML Report Builder
├── .gitignore
└── README.md
```

---

## 🚀 Getting Started

No build tools or heavy dependencies required. The framework runs natively in any modern web browser.

### Option 1: Quick Launch via Local HTTP Server (Recommended)

Using Python:
```bash
# Clone the repository
git clone https://github.com/simran198905/DF-and-IRTI.git
cd DF-and-IRTI

# Start local server
python3 -m http.server 8000
```
Then navigate to: `http://localhost:8000`

Using Node.js (`npx serve`):
```bash
npx serve .
```

### Option 2: Direct Browser Launch
Open `index.html` directly in any ES6 module-supporting browser (Chrome, Edge, Firefox, Safari).

---

## 🛡️ Telemetry & Evidence Normalization

Evidence records adhere to a standardized forensic schema:
```json
{
  "id": "EV-001",
  "incidentId": "INC-A",
  "timestamp": "2026-03-01T04:12:00Z",
  "sourceType": "ENDPOINT_HOST",
  "title": "PsExec execution with encoded PowerShell cradle",
  "iocType": "PROCESS_EXECUTION",
  "iocValue": "powershell.exe -enc SQBFAFgA...",
  "mitreTactic": "TA0002 Execution",
  "mitreTechnique": "T1059.001 PowerShell",
  "confidenceScore": 0.95
}
```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to open an issue or submit a pull request.
1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/NewFeature`)
3. Commit your Changes (`git commit -m 'Add NewFeature'`)
4. Push to the Branch (`git push origin feature/NewFeature`)
5. Open a Pull Request

---

## 📜 License

Distributed under the MIT License.
