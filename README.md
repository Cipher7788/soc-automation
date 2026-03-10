# SOC Automation System

A comprehensive **Security Operations Center (SOC) automation system** built with Python and AI, integrating Wazuh SIEM, TheHive case management, and Shuffle SOAR for end-to-end security alert ingestion, analysis, and response.

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
         │ Wazuh REST API
         ▼
  ┌───────────────────┐
  │   Python Engine    │  ◄── Core SOC Automation
  │  (AI/ML + Logic)   │       - IOC Detection
  │                    │       - Anomaly Detection (ML)
  │                    │       - Rules Engine (YAML)
  │                    │       - Alert Correlation
  └──────┬─────────────┘
         │
    ┌────┴──────┐
    ▼           ▼
┌────────┐  ┌─────────┐
│TheHive │  │ Shuffle  │  ◄── Case Management + SOAR
│(Cases) │  │(Playbooks│
└────────┘  └─────────┘
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

### 2. Start the full stack (Docker)

```bash
docker compose up -d
```

This starts:
- Wazuh Manager + Indexer + Dashboard
- TheHive 5 + Cassandra + MinIO
- Shuffle SOAR backend + frontend
- The Python SOC automation engine

### 3. Run locally (development)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m src.main
```

### 4. Run tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

---

## Configuration

All configuration is done via environment variables (copy `.env.example` to `.env`):

| Variable | Description |
|----------|-------------|
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
| `SMTP_HOST` | SMTP server for email notifications |
| `LOG_LEVEL` | Logging level (default: `INFO`) |
| `WAZUH_POLL_INTERVAL` | Seconds between Wazuh polls (default: `60`) |

---

## Module Descriptions

### `src/ingestion/`
- **`wazuh_client.py`** — Wazuh REST API client with JWT auth + auto-refresh, retry logic, pagination
- **`log_collector.py`** — Async multi-source log collector with in-memory buffering
- **`normalizer.py`** — ECS-compatible log normalizer (IP extraction, timestamp normalization)

### `src/detection/`
- **`ioc_detector.py`** — IOC detection engine (malicious IPs, domains, hashes, URLs, emails)
- **`threat_intel.py`** — AbuseIPDB, VirusTotal, OTX threat intelligence integration with caching
- **`ml_analyzer.py`** — Isolation Forest anomaly detection with model persistence
- **`rules_engine.py`** — YAML-based detection rules engine with hot-reload

### `src/alerting/`
- **`thehive_client.py`** — TheHive v5 API client for alert/case management
- **`alert_manager.py`** — Alert deduplication, correlation, and severity scoring
- **`notifier.py`** — Multi-channel notifications (email, Slack, webhook)
- **`escalation.py`** — SLA tracking and automatic escalation chains

### `src/response/`
- **`shuffle_client.py`** — Shuffle SOAR API client for workflow execution
- **`playbook_manager.py`** — Alert-type-to-playbook mapping with approval gates
- **`actions.py`** — Automated response actions (block IP, isolate host, disable user)

### `playbooks/`
JSON workflow definitions for Shuffle:
- `malware_detected.json` — Enrich → VirusTotal → Create case → Isolate host → Notify
- `brute_force.json` — Check IP reputation → Block if malicious → Create alert → Notify
- `suspicious_network.json` — Analyze traffic → Threat intel → Create case → Respond

### `rules/`
YAML detection rules:
- `ioc_rules.yml` — IOC-based rules (malicious IPs, C2, scanning, malware hashes)
- `correlation_rules.yml` — Event correlation (brute force, lateral movement, exfiltration, privilege escalation)

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Write tests for your changes
4. Ensure all tests pass: `pytest tests/ -v`
5. Open a pull request

---

## License

MIT
