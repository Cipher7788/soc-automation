# Architecture Documentation

## Overview

The SOC Automation System is a Python-based security operations platform that integrates three best-of-breed open-source security tools:

| Component | Role |
|-----------|------|
| **Wazuh** | SIEM / XDR — log collection, file integrity monitoring, vulnerability detection |
| **TheHive** | Case management — structured incident tracking with observables |
| **Shuffle** | SOAR — workflow automation for repeatable response procedures |

---

## Data Flow

```
[Agent Events / Syslogs / Firewall Logs]
         │
         ▼
    [Wazuh Manager]
    - Normalises & enriches logs
    - Applies Wazuh detection rules
    - Stores in Wazuh Indexer (OpenSearch)
         │
         ▼ REST API (JWT)
    [log_collector.py]
    - Polls /alerts every N seconds
    - Buffers in memory
         │
         ▼
    [normalizer.py]
    - ECS-compatible schema
    - IP/timestamp/field extraction
         │
         ▼
    ┌────────────────────────────────┐
    │        Detection Pipeline       │
    │  ┌─────────────┐               │
    │  │ ioc_detector│ ◄─ blocklist  │
    │  └─────────────┘               │
    │  ┌─────────────┐               │
    │  │ threat_intel│ ◄─ APIs       │
    │  └─────────────┘               │
    │  ┌─────────────┐               │
    │  │ ml_analyzer │ ◄─ model.pkl  │
    │  └─────────────┘               │
    │  ┌─────────────┐               │
    │  │rules_engine │ ◄─ YAML rules │
    │  └─────────────┘               │
    └───────────────┬────────────────┘
                    │
                    ▼
            [alert_manager.py]
            - Deduplication
            - Correlation
            - Severity scoring
                    │
          ┌─────────┼────────────┐
          ▼         ▼            ▼
    [thehive]  [shuffle]  [notifier]
    Alert/Case  Playbook   Email/Slack
    Creation    Execution  Webhook
```

---

## Component Details

### Wazuh Integration (`src/ingestion/`)

The `WazuhClient` authenticates via JWT and polls the `/alerts` endpoint with time-range filtering. Retry logic (exponential backoff) handles transient failures. Pagination handles large alert volumes.

The `LogNormalizer` maps Wazuh's JSON alert format to an ECS-inspired `NormalizedLog` schema that downstream components can rely upon regardless of source.

### Detection Pipeline (`src/detection/`)

**IOC Detector** — Uses compiled regex patterns to extract IPs, domains, file hashes (MD5/SHA1/SHA256), URLs and email addresses from log text. Matches against configurable blocklists and returns confidence-scored `IOCMatch` objects. Results are TTL-cached.

**Threat Intelligence** — Queries AbuseIPDB, VirusTotal v3, and OTX AlienVault in parallel (with per-feed rate limiting). Results are cached to minimise API calls.

**ML Analyzer** — Trains a scikit-learn `IsolationForest` on feature vectors extracted from log batches (login frequency, unique IPs, failed auth count, time-of-day, data volume, event count). Detects statistical anomalies with a normalised 0–1 score.

**Rules Engine** — Loads YAML files from `rules/`. Each rule specifies field conditions (equals, contains, regex, gt/lt/gte, in, exists), boolean logic (AND/OR/NOT), and optional threshold/time-window enforcement. Supports hot-reload without restart.

### Alerting (`src/alerting/`)

**Alert Manager** — Fingerprints alerts by title + source + severity. Duplicates within the dedup window (default 5 minutes) are suppressed. Related alerts sharing keywords or IOC values are grouped into correlated incidents.

**TheHive Client** — Creates structured alerts and cases via TheHive v5 REST API. Observables (IPs, hashes, domains) are attached automatically from IOC matches.

**Notifier** — Severity-based channel routing: critical/high → email + Slack + webhook; medium → Slack + webhook; low → webhook only. Uses Jinja2 templates for message formatting.

**Escalation Manager** — Tracks SLA timers per alert. Unacknowledged alerts that breach their SLA trigger escalation through a configurable contact chain (L1 → L2 → L3 → Management).

### Response (`src/response/`)

**Shuffle Client** — Calls Shuffle REST API to trigger workflow executions with alert context as payload.

**Playbook Manager** — Maps alert types to playbook names, resolves Shuffle workflow IDs (from local JSON or API), tracks executions, and enforces manual approval gates for high-impact playbooks.

**Response Actions** — Firewall API integration for IP blocking, Wazuh active response for host isolation, stub for identity provider integration (user disablement). All actions require `confirmed=True` and are logged to an audit trail.

---

## Security Considerations

- All API keys are loaded from environment variables; never hardcoded
- TheHive and Shuffle use Bearer token authentication over HTTPS
- Wazuh uses JWT authentication with auto-refresh before expiry
- Response actions require explicit confirmation to prevent accidental execution
- The Docker container runs as a non-root user (`socuser`)
- TLP and PAP levels are set on all TheHive alerts/cases
