# Setup Guide

## Wazuh

Deploy Wazuh using its [installation guide](https://documentation.wazuh.com/current/installation-guide/index.html).
Confirm a connected agent has produced alerts in the `wazuh-alerts-*` indices.
Create an indexer account with read access to those indices and permission to search and scroll.

```bash
git clone https://github.com/Cipher7788/soc-automation.git
cd soc-automation
cp .env.example .env
```

Set `WAZUH_INDEXER_URL` to the indexer base URL, such as
`https://wazuh.example.net:9200`. Set `WAZUH_INDEXER_USERNAME` and
`WAZUH_INDEXER_PASSWORD` to the indexer credentials. With a private CA, set
`WAZUH_INDEXER_CA_BUNDLE` to a readable PEM file. For Compose, put the PEM file
under `certs/` and use its container path, such as `/app/certs/indexer-ca.pem`.
Use a URL hostname that matches the TLS certificate.

## Run the engine

```bash
docker compose up --build -d
docker compose logs -f soc-automation
```

The engine uses external services. If a service runs on the Docker host, use
`host.docker.internal` where that name matches the service certificate.
For local development, use Python 3.11 or later and run `python -m pip install .`
then `python -m src.main` from the repository root.

Reports and models are stored in Compose named volumes. Copy reports out with
`docker compose cp soc-automation:/app/reports ./reports`. If upgrading from
the original bind mounts, keep your existing local reports and copy any model
you want to reuse into the new model volume. Load only trusted pickle models
and retrain if a scikit-learn upgrade makes them incompatible.

Alert collection searches a rolling 60-minute window and deduplicates in
memory. Restarting the process can replay recent alerts, and an outage longer
than the window can leave gaps.

## Optional services

- Set `THEHIVE_URL` and `THEHIVE_API_KEY` to enable TheHive alert and case creation.
- Set `SHUFFLE_URL` to the backend API (typically port 5001) and set
  `SHUFFLE_API_KEY`. Create workflows using the JSON playbook files as design
  examples, then match their names or add the deployed workflow ID as
  `workflow_id` in the corresponding JSON file. High-impact workflows wait
  for in-process approval.
- Set the individual threat intelligence keys and notification endpoints to
  enable those integrations. Each enabled provider receives the indicators
  or alert details needed for its function.
- Grafana provisioning examples live under `dashboard/grafana`. Configure
  the datasource for your own indexer deployment.

The built-in responder can create TheHive cases. Host isolation, account
changes, forensic snapshots, and firewall changes need deployed integrations.
Skipped or failed actions are recorded with their actual status.
