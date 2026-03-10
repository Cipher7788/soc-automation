# SOC Automation — Grafana Dashboard Setup

This directory contains Grafana provisioning configuration and pre-built dashboard panels for the SOC Automation pipeline.

## Quick Start

The Grafana service is defined in `docker-compose.yml` and will start automatically alongside the rest of the SOC stack:

```bash
docker compose up -d grafana
```

Grafana will be available at **http://localhost:3000** (default credentials: `admin` / `admin`).

## Directory Structure

```
dashboard/grafana/
├── provisioning/
│   ├── dashboards/
│   │   └── dashboard.yml          # Grafana dashboard provisioner config
│   └── datasources/
│       └── datasource.yml         # OpenSearch/Wazuh datasource config
└── dashboards/
    └── soc_overview.json          # Pre-built SOC Overview dashboard JSON
```

## Dashboard Panels

The **SOC Overview** dashboard (`soc_overview.json`) includes:

| Panel | Type | Description |
|---|---|---|
| Total Alerts | Stat | Count of all alerts in time range |
| Critical Alerts | Stat | Count of alerts with rule level ≥ 12 |
| High Severity Alerts | Stat | Count of alerts with rule level 8–11 |
| Active Agents | Stat | Unique Wazuh agent count |
| Attack Timeline | Time-series | Alert volume over time |
| Alert Severity Distribution | Pie chart | Breakdown by rule level |
| Top Threat Sources | Bar gauge | Top source IPs by alert count |
| Top Attacked Hosts | Table | Most targeted Wazuh agents |
| IOC Types Distribution | Pie chart | Breakdown by rule group / IOC type |
| MITRE ATT&CK Techniques | Bar gauge | Top triggered MITRE technique IDs |

## Datasource

The dashboard uses a provisioned **OpenSearch** datasource (`Wazuh-OpenSearch`) that points to the Wazuh Indexer at `https://wazuh-indexer:9200`.

If you run Wazuh with a custom password, set `INDEXER_PASSWORD` in your `.env` file.

## Adding Custom Panels

1. Edit the dashboard in the Grafana UI.
2. Click the kebab menu (⋮) → **Dashboard settings** → **JSON Model**.
3. Copy the panel JSON into `dashboards/soc_overview.json`.
4. Restart the Grafana container: `docker compose restart grafana`.

## Required Plugin

The datasource uses the **Grafana OpenSearch plugin** (`grafana-opensearch-datasource`).  
It is automatically installed via the `GF_INSTALL_PLUGINS` environment variable in `docker-compose.yml`.
