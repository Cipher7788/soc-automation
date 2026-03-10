# API Reference

## `src/ingestion/wazuh_client.WazuhClient`

Wazuh REST API client with JWT authentication and retry logic.

### Constructor

```python
WazuhClient(
    host: str,
    username: str,
    password: str,
    verify_ssl: bool = False,
    timeout: int = 30,
)
```

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `authenticate()` | `str` | Authenticate and return JWT token |
| `get_alerts(time_range: int = 60)` | `list[dict]` | Fetch alerts from the last N minutes |
| `get_agents()` | `list[dict]` | Fetch all registered agents |
| `get_agent_events(agent_id: str)` | `list[dict]` | Fetch events for a specific agent |
| `get_vulnerabilities()` | `list[dict]` | Fetch vulnerability data |

---

## `src/ingestion/log_collector.LogCollector`

Multi-source log collector with async support.

### Constructor

```python
LogCollector(
    wazuh_client: WazuhClient,
    poll_interval: int = 60,
    batch_size: int = 1000,
    time_range: int = 60,
)
```

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `register_callback(cb)` | `None` | Register a callback for log batches |
| `collect_once()` | `list[dict]` | Perform a single collection cycle |
| `flush_buffer()` | `list[dict]` | Return and clear buffer |
| `collect_loop()` | coroutine | Async continuous collection loop |
| `stop()` | `None` | Signal the loop to stop |

---

## `src/ingestion/normalizer.LogNormalizer`

ECS-compatible log normalizer.

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `normalize(raw, source)` | `NormalizedLog` | Normalize a single raw log |
| `normalize_batch(records, source)` | `list[NormalizedLog]` | Normalize a batch of logs |

### `NormalizedLog` fields

`timestamp`, `source_ip`, `destination_ip`, `event_type`, `severity`, `rule_id`, `rule_description`, `agent_id`, `agent_name`, `hostname`, `user`, `process`, `raw_message`, `source`, `extra`

---

## `src/detection/ioc_detector.IOCDetector`

IOC detection engine.

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `detect(text: str)` | `list[IOCMatch]` | Detect IOCs in text |
| `add_malicious_ip(ip)` | `None` | Add IP to blocklist |
| `add_malicious_domain(domain)` | `None` | Add domain to blocklist |
| `add_malicious_hash(hash_val)` | `None` | Add hash to blocklist |

### `IOCMatch` fields

`ioc_type`, `value`, `confidence` (0.0–1.0), `source`, `details`

---

## `src/detection/threat_intel.ThreatIntelManager`

Multi-feed threat intelligence manager.

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `lookup_ip(ip)` | `ThreatIntelResult` | AbuseIPDB + OTX IP lookup |
| `lookup_hash(hash_val)` | `ThreatIntelResult` | VirusTotal hash lookup |
| `lookup_domain(domain)` | `ThreatIntelResult` | OTX + VirusTotal domain lookup |

---

## `src/detection/ml_analyzer.MLAnalyzer`

Isolation Forest anomaly detection.

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `extract_features(log_batch)` | `dict[str, float]` | Extract feature vector from logs |
| `train(training_data)` | `None` | Train on normal baseline data |
| `analyze(features)` | `AnomalyResult` | Analyze a feature vector |
| `analyze_batch(log_batch)` | `AnomalyResult` | Extract features and analyze |

---

## `src/detection/rules_engine.RulesEngine`

YAML-based detection rules engine.

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `load_rules()` | `None` | Load rules from YAML files |
| `reload_rules()` | `None` | Hot-reload rules from disk |
| `evaluate(log)` | `list[RuleMatch]` | Evaluate rules against a log |
| `evaluate_batch(logs)` | `dict[int, list[RuleMatch]]` | Evaluate rules against a batch |

---

## `src/alerting/thehive_client.TheHiveClient`

TheHive v5 REST API client.

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `create_alert(alert: HiveAlert)` | `dict` | Create a TheHive alert |
| `search_alerts(query)` | `list[dict]` | Search alerts |
| `create_case(case: HiveCase)` | `dict` | Create a case |
| `get_case(case_id)` | `dict` | Get case by ID |
| `update_case(case_id, updates)` | `dict` | Update case fields |
| `add_observable(case_id, ...)` | `dict` | Add observable to case |

---

## `src/alerting/alert_manager.AlertManager`

Alert lifecycle management.

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `process(alert: Alert)` | `Optional[Alert]` | Process through dedup/scoring |
| `acknowledge(alert_id)` | `bool` | Acknowledge an alert |
| `get_active_alerts()` | `list[Alert]` | Return unacknowledged alerts |
| `get_incidents()` | `list[list[Alert]]` | Return correlated groups |
| `purge_old(max_age)` | `int` | Remove old alerts |

---

## `src/alerting/notifier.Notifier`

Multi-channel notification dispatcher.

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `notify(title, description, severity, ...)` | `dict[str, bool]` | Send notifications |

---

## `src/alerting/escalation.EscalationManager`

SLA tracking and escalation management.

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `register_alert(alert_id, severity)` | `EscalationRecord` | Register for SLA tracking |
| `acknowledge(alert_id)` | `bool` | Acknowledge and stop escalation |
| `resolve(alert_id)` | `bool` | Mark alert resolved |
| `check_escalations()` | `list[tuple]` | Check and trigger escalations |
| `get_sla_status(alert_id)` | `dict` | Get SLA status |

---

## `src/response/shuffle_client.ShuffleClient`

Shuffle SOAR API client.

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `list_workflows()` | `list[dict]` | List available workflows |
| `trigger_workflow(workflow_id, args)` | `dict` | Trigger a workflow execution |
| `get_workflow_status(workflow_id)` | `dict` | Get workflow details |
| `get_execution_results(wf_id, exec_id)` | `dict` | Get execution results |

---

## `src/response/playbook_manager.PlaybookManager`

Alert-to-playbook mapping and execution tracking.

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `select_playbook(alert_type)` | `Optional[str]` | Get playbook name for alert type |
| `execute(alert_type, alert_id, ...)` | `Optional[PlaybookExecution]` | Execute appropriate playbook |
| `approve_and_execute(execution, ...)` | `PlaybookExecution` | Approve pending execution |
| `get_execution_log()` | `list[PlaybookExecution]` | Return audit trail |

---

## `src/response/actions.ResponseActions`

Automated response actions.

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `block_ip(ip, reason, confirmed)` | `ActionResult` | Block IP via firewall API |
| `isolate_host(agent_id, reason, confirmed)` | `ActionResult` | Isolate host via Wazuh |
| `disable_user(username, reason, confirmed)` | `ActionResult` | Disable user account |
| `collect_forensics(agent_id, case_id)` | `ActionResult` | Trigger forensic collection |
| `get_audit_log()` | `list[ActionResult]` | Return all action results |
