# Setup Guide

## Prerequisites

- **Docker** 24.x+ and **Docker Compose** v2+
- **Python** 3.11+ (for local development)
- API keys for: AbuseIPDB, VirusTotal, AlienVault OTX (optional but recommended)

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/Cipher7788/soc-automation.git
cd soc-automation
```

---

## Step 2 — Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` and fill in:

| Key | Where to obtain |
|-----|----------------|
| `WAZUH_PASSWORD` | Set during Wazuh install or via dashboard |
| `THEHIVE_API_KEY` | TheHive → Settings → API Keys |
| `SHUFFLE_API_KEY` | Shuffle → Profile → API Key |
| `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/account/api |
| `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/user/apikey |
| `OTX_API_KEY` | https://otx.alienvault.com/api |
| `SLACK_WEBHOOK_URL` | Slack App → Incoming Webhooks |
| `SMTP_*` | Your SMTP provider |

---

## Step 3 — Start the Full Stack

```bash
docker compose up -d
```

Wait ~2-3 minutes for all services to initialise. Monitor with:

```bash
docker compose logs -f soc-automation
```

---

## Step 4 — Verify Services

| Service | URL | Default Credentials |
|---------|-----|---------------------|
| Wazuh Dashboard | https://localhost:443 | admin / changeme |
| TheHive | http://localhost:9000 | admin@thehive.local / secret |
| Shuffle | http://localhost:3001 | (register on first visit) |
| Wazuh API | https://localhost:55000 | wazuh-wui / changeme |

---

## Step 5 — Configure Wazuh Agents

On each endpoint to monitor, install the Wazuh agent and register it with your Wazuh Manager:

```bash
# On Linux endpoints
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
# ... (see Wazuh official docs for full installation)
WAZUH_MANAGER=<your-wazuh-ip> agent-auth -m <your-wazuh-ip>
systemctl start wazuh-agent
```

---

## Step 6 — Configure TheHive

1. Log in to TheHive at http://localhost:9000
2. Create an organisation and a user account
3. Generate an API key: **Settings → API Keys → Create**
4. Update `THEHIVE_API_KEY` in `.env`

---

## Step 7 — Configure Shuffle

1. Visit http://localhost:3001 and register
2. Note your API key from your profile settings
3. Update `SHUFFLE_API_KEY` in `.env`
4. Import the playbooks from the `playbooks/` directory

---

## Troubleshooting

### Container fails to start
```bash
docker compose logs <service-name>
```

### Wazuh authentication fails
- Ensure `WAZUH_USERNAME` and `WAZUH_PASSWORD` match the values set in your Wazuh deployment
- Check SSL: set `WAZUH_VERIFY_SSL=false` for self-signed certificates

### TheHive returns 401
- Regenerate the API key in TheHive and update `.env`

### No alerts appearing
- Verify Wazuh agents are connected: Wazuh Dashboard → Agents
- Check poll interval: `WAZUH_POLL_INTERVAL` (default 60 seconds)
- Inspect logs: `docker compose logs soc-automation`
