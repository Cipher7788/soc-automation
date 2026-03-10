"""Incident Report Generator — produces HTML, Markdown, and JSON reports using Jinja2."""

import json
import logging
import os
import time
import uuid
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")
_DEFAULT_REPORTS_DIR = "reports"


class ReportGenerator:
    """Generate SOC incident reports in HTML, Markdown, or JSON format.

    Templates are loaded from *templates_dir* (defaults to the ``templates/``
    sub-directory next to this module).  Generated reports are stored under
    *reports_dir*.
    """

    def __init__(
        self,
        templates_dir: str = _TEMPLATES_DIR,
        reports_dir: str = _DEFAULT_REPORTS_DIR,
    ) -> None:
        self._reports_dir = reports_dir
        os.makedirs(reports_dir, exist_ok=True)

        if os.path.isdir(templates_dir):
            # Enable autoescape for HTML to prevent XSS; disable for Markdown/JSON
            self._jinja_html = Environment(
                loader=FileSystemLoader(templates_dir),
                autoescape=True,
            )
            self._jinja_text = Environment(
                loader=FileSystemLoader(templates_dir),
                autoescape=False,
            )
        else:
            logger.warning("Templates directory not found: %s", templates_dir)
            self._jinja_html = None
            self._jinja_text = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_report(
        self,
        incident_data: dict[str, Any],
        fmt: str = "html",
    ) -> str:
        """Generate an incident report from *incident_data*.

        *fmt* must be one of "html", "markdown", or "json".
        The rendered report string is returned AND saved to *reports_dir*.
        """
        incident_data = self._enrich_incident_data(incident_data)

        if fmt == "json":
            content = json.dumps(incident_data, indent=2, default=str)
        elif fmt == "html" and self._jinja_html:
            try:
                tmpl = self._jinja_html.get_template("incident_report.html")
                content = tmpl.render(**incident_data)
            except Exception as exc:
                logger.error("Template rendering failed: %s", exc)
                content = self._fallback_render(incident_data, fmt)
        elif self._jinja_text:
            try:
                tmpl = self._jinja_text.get_template("incident_report.md")
                content = tmpl.render(**incident_data)
            except Exception as exc:
                logger.error("Template rendering failed: %s", exc)
                content = self._fallback_render(incident_data, fmt)
        else:
            content = self._fallback_render(incident_data, fmt)

        self._save_report(incident_data["incident_id"], fmt, content)
        return content

    def generate_summary_report(
        self,
        alerts: list[dict[str, Any]],
        time_range: str = "last 24 hours",
        fmt: str = "markdown",
    ) -> str:
        """Generate a summary report for a collection of alerts."""
        total = len(alerts)
        severity_counts: dict[str, int] = {}
        for alert in alerts:
            sev = alert.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        summary_data = {
            "report_type": "Summary Report",
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "time_range": time_range,
            "total_alerts": total,
            "severity_breakdown": severity_counts,
            "alerts": alerts[:50],  # cap for readability
        }

        if fmt == "json":
            content = json.dumps(summary_data, indent=2, default=str)
        else:
            lines = [
                f"# SOC Summary Report — {time_range}",
                "",
                f"**Generated:** {summary_data['generated_at']}",
                f"**Total Alerts:** {total}",
                "",
                "## Severity Breakdown",
                "",
            ]
            for sev, count in sorted(severity_counts.items()):
                lines.append(f"- **{sev.title()}**: {count}")
            content = "\n".join(lines)

        summary_id = f"summary-{int(time.time())}"
        self._save_report(summary_id, fmt, content)
        return content

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _enrich_incident_data(self, data: dict[str, Any]) -> dict[str, Any]:
        out = dict(data)
        out.setdefault("incident_id", str(uuid.uuid4())[:8].upper())
        out.setdefault("generated_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        out.setdefault("attack_type", "Unknown")
        out.setdefault("severity", "medium")
        out.setdefault("mitre_technique", "")
        out.setdefault("response_actions", [])
        out.setdefault("iocs", [])
        out.setdefault("timeline", [])
        out.setdefault("recommendations", self._default_recommendations(out.get("severity", "medium")))
        return out

    def _default_recommendations(self, severity: str) -> list[str]:
        base = [
            "Review and update firewall rules",
            "Audit user accounts and privileges",
            "Check for additional IOCs across the environment",
        ]
        if severity in ("high", "critical"):
            base.insert(0, "Conduct a full forensic investigation")
            base.append("Consider engaging external incident response team")
        return base

    def _fallback_render(self, data: dict[str, Any], fmt: str) -> str:
        if fmt == "html":
            return (
                f"<html><body>"
                f"<h1>Incident Report: {data.get('incident_id')}</h1>"
                f"<p>Attack Type: {data.get('attack_type')}</p>"
                f"<p>Severity: {data.get('severity')}</p>"
                f"<p>MITRE: {data.get('mitre_technique')}</p>"
                f"</body></html>"
            )
        return (
            f"# Incident Report: {data.get('incident_id')}\n\n"
            f"- **Attack Type:** {data.get('attack_type')}\n"
            f"- **Severity:** {data.get('severity')}\n"
            f"- **MITRE:** {data.get('mitre_technique')}\n"
        )

    def _save_report(self, report_id: str, fmt: str, content: str) -> None:
        ext_map = {"html": "html", "markdown": "md", "json": "json", "md": "md"}
        ext = ext_map.get(fmt, "txt")
        filename = os.path.join(self._reports_dir, f"report_{report_id}.{ext}")
        try:
            with open(filename, "w", encoding="utf-8") as fh:
                fh.write(content)
            logger.info("Report saved: %s", filename)
        except Exception as exc:
            logger.error("Failed to save report: %s", exc)
