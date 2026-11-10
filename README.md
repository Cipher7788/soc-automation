# SOC Automation System

A comprehensive **Security Operations Center (SOC) automation system** built with Python and AI, integrating Wazuh SIEM, TheHive case management, and Shuffle SOAR for end-to-end security alert ingestion, analysis, enrichment, response, and reporting.

---

## Architecture

```
[Endpoints / Network Devices / Firewalls]
        │
        ▼
  ┌─────────────┐
  │    Wazuh     │  ◄── Log Collection & SIEM / XDR
  │  (SIEM/XDR)  │
  └──────┬──────┘
         │ Wazuh Indexer API
         ▼
  ┌─────────────────────────────────────────────────────┐
  │          Python SOC Automation Engine                │
  │                                                     │
  │  1. Ingestion   → LogCollector, LogNormalizer        │
  │  2. Detection   → IOCDetector, MLAnalyzer,           │
  │                   RulesEngine, IOCDatabase           │
  │  3. Enrichment  → ThreatIntelEnricher (VT/AIPDB/OTX)│
  │  4. Mapping     → MITREMapper (ATT&CK framework)     │
  │  5. Prioritize  → AlertPrioritizer (AI/ML)           │
  │  6. Response    → IncidentResponder, PlaybookManager  │
  │  7. Reporting   → ReportGenerator (HTML/MD/JSON)     │
  │  8. Notify      → Notifier (Slack/Email/Teams/Webhook)│
  └──────┬───────────────────────────────────────────────┘
         │
    ┌────┴──────┐
    ▼           ▼
┌────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
│TheHive │  │ Shuffle  │  │ Grafana │  │ Reports │
│(Cases) │  │(Playbooks│  │Dashboard│  │(HTML/MD)│
└────────┘  └─────────┘  └─────────┘  └─────────┘
```

---

## Quick Start

### 1. Clone & configure

```bash
git clone https://github.com/Cipher7788/soc-automation.git
cd soc-automation
cp .env.example .env
# Edit .env with your API keys and endpoints
```

### 2. Run the engine with Docker Compose

Set `WAZUH_INDEXER_URL` and the indexer credentials in `.env`. Use a URL
reachable from the container. Wazuh is deployed separately, and TheHive and
Shuffle are optional external integrations.

```bash
docker compose up --build -d
docker compose logs -f soc-automation
```

See the [setup guide](docs/setup_guide.md) for private CA certificates and service configuration.

### 3. Run locally (development)

```bash
python -m venv .venv
source .venv/bin/activate  # PowerShell: .venv\Scripts\Activate.ps1
python -m pip install .
python -m src.main
```

### 4. Run tests

```bash
python -m pip install -r requirements.txt
python -m pytest -q
```

---

## Configuration

All configuration is done via environment variables (copy `.env.example` to `.env`):

| Variable | Description |
|----------|-------------|
| `WAZUH_INDEXER_URL` | Required Wazuh Indexer base URL |
| `WAZUH_INDEXER_USERNAME`, `WAZUH_INDEXER_PASSWORD` | Read-only indexer credentials |
| `WAZUH_INDEXER_CA_BUNDLE` | PEM certificate bundle for a private indexer CA |
| `WAZUH_HOST` | Wazuh Manager URL (e.g. `https://wazuh-manager:55000`) |
| `WAZUH_USERNAME` | Wazuh API username |
| `WAZUH_PASSWORD` | Wazuh API password |
| `THEHIVE_URL` | TheHive instance URL |
| `THEHIVE_API_KEY` | TheHive API key |
| `SHUFFLE_URL` | Shuffle backend URL |
| `SHUFFLE_API_KEY` | Shuffle API key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB threat intel API key |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |
| `OTX_API_KEY` | AlienVault OTX API key |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook for notifications |
| `TEAMS_WEBHOOK_URL` | Microsoft Teams incoming webhook |
| `SMTP_HOST` | SMTP server for email notifications |
| `IOC_DATABASE_PATH` | Path to the local IOC JSON database (default: `data/ioc_database.json`) |
| `REPORTS_DIR` | Directory to store generated reports (default: `reports`) |
| `LOG_LEVEL` | Logging level (default: `INFO`) |
| `WAZUH_POLL_INTERVAL` | Seconds between Wazuh polls (default: `60`) |

---

## Module Descriptions

### `src/ingestion/`
- **`wazuh_client.py`** — Wazuh Indexer alert search and separate Wazuh Manager JWT authentication
- **`log_collector.py`** — Async multi-source log collector with in-memory buffering
- **`normalizer.py`** — ECS-compatible log normalizer (IP extraction, timestamp normalization)

### `src/detection/`
- **`ioc_detector.py`** — IOC detection engine (malicious IPs, domains, hashes, URLs, emails)
- **`threat_intel.py`** — AbuseIPDB, VirusTotal, OTX threat intelligence integration with caching
- **`ml_analyzer.py`** — Isolation Forest anomaly detection with model persistence
- **`rules_engine.py`** — YAML-based detection rules engine with hot-reload
- **`mitre_mapper.py`** — MITRE ATT&CK mapping with 30+ built-in techniques across all tactics
- **`ai_prioritizer.py`** — GradientBoosting-based alert prioritization with rule-based fallback

### `src/enrichment/`
- **`threat_intel_enricher.py`** — IOC enrichment via VirusTotal, AbuseIPDB, and AlienVault OTX with TTL caching
- **`ioc_database.py`** — Local JSON-backed IOC repository with CRUD, bulk import, and CSV/JSON export

### `src/alerting/`
- **`thehive_client.py`** — TheHive v5 API client for alert/case management
- **`alert_manager.py`** — Alert deduplication, correlation, and severity scoring
- **`notifier.py`** — Multi-channel notifications (email, Slack, webhook)
- **`teams_notifier.py`** — Microsoft Teams Adaptive Card notifications with severity colour coding
- **`escalation.py`** — SLA tracking and automatic escalation chains

### `src/response/`
- **`shuffle_client.py`** — Shuffle SOAR API client for workflow execution
- **`playbook_manager.py`** — Alert-type-to-playbook mapping with approval gates
- **`actions.py`** — Automated response actions (block IP, isolate host, disable user)
- **`incident_responder.py`** — Automated incident response engine with configurable playbooks per alert type and severity

### `src/reporting/`
- **`report_generator.py`** — Jinja2-based incident report generator supporting HTML, Markdown, and JSON output formats

### `src/simulation/`
- **`attack_simulator.py`** — Attack scenario simulator for SOC pipeline testing; generates realistic log entries from YAML scenario files
- **`scenarios/`** — 5 built-in YAML attack scenarios: brute_force_ssh, powershell_exploitation, credential_dumping, port_scan, data_exfiltration

### `dashboard/grafana/`
- Pre-configured Grafana dashboard provisioning for SOC visibility
- 10 panels: attack timeline, severity distribution, top sources, top hosts, IOC types, MITRE techniques, and more
- See `dashboard/README.md` for setup instructions

### `playbooks/`
Workflow design examples for Shuffle:
- `malware_detected.json` — Enrich → VirusTotal → Create case → Isolate host → Notify
- `brute_force.json` — Check IP reputation → Block if malicious → Create alert → Notify
- `suspicious_network.json` — Analyze traffic → Threat intel → Create case → Respond

### `rules/`
YAML detection rules:
- `ioc_rules.yml` — IOC-based rules (malicious IPs, C2, scanning, malware hashes)
- `correlation_rules.yml` — Event correlation (brute force, lateral movement, exfiltration, privilege escalation)

### `data/`
- `ioc_database.json` — Seed IOC database with sample malicious IPs, domains, and hashes

---

## SOC Pipeline Flow

```
Wazuh Alert
    │
    ├─ Normalize (LogNormalizer)
    ├─ ML Anomaly Detection (MLAnalyzer)
    ├─ IOC Detection (IOCDetector + IOCDatabase)
    ├─ Rules Evaluation (RulesEngine)
    ├─ Threat Intel Enrichment (ThreatIntelEnricher → VT/AbuseIPDB/OTX)
    ├─ MITRE ATT&CK Mapping (MITREMapper)
    ├─ AI Prioritization (AlertPrioritizer → GradientBoosting)
    ├─ TheHive Case Creation
    ├─ Shuffle Playbook Execution
    ├─ Incident Response (TheHive case creation and action status tracking)
    ├─ Incident Report Generation (HTML/Markdown)
    └─ Notifications (Slack + Teams + Email + Webhook)
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Write tests for your changes
4. Ensure all tests pass: `pytest tests/ -v`
5. Open a pull request

---

## License

[MIT](LICENSE)
