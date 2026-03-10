# 🚨 SOC Incident Report

| Field | Value |
|---|---|
| **Incident ID** | {{ incident_id }} |
| **Generated At** | {{ generated_at }} |
| **Attack Type** | {{ attack_type }} |
| **Severity** | {{ severity | upper }} |
| **MITRE ATT&CK** | {{ mitre_technique if mitre_technique else "N/A" }} |

---

{% if iocs %}
## Indicators of Compromise (IOCs)

| Type | Value | Confidence |
|---|---|---|
{% for ioc in iocs -%}
| {{ ioc.get('type', ioc.get('ioc_type', '')) }} | {{ ioc.get('value', ioc.get('ioc_value', '')) }} | {{ ioc.get('confidence', '') }} |
{% endfor %}
{% endif %}

{% if timeline %}
## Timeline

| Time | Event |
|---|---|
{% for event in timeline -%}
| {{ event.get('time', event.get('timestamp', '')) }} | {{ event.get('event', event.get('message', '')) }} |
{% endfor %}
{% endif %}

{% if response_actions %}
## Response Actions Taken

| Action | Target | Status | Result |
|---|---|---|---|
{% for action in response_actions -%}
| {{ action.get('action_type', '') }} | {{ action.get('target', '') }} | {{ action.get('status', '') }} | {{ action.get('result', '') }} |
{% endfor %}
{% endif %}

{% if recommendations %}
## Recommendations

{% for rec in recommendations -%}
- {{ rec }}
{% endfor %}
{% endif %}

---
*Generated automatically by SOC Automation | {{ generated_at }}*
