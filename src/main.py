"""Main entry point and event-loop orchestrator for SOC Automation."""

import asyncio
import logging
import signal
import sys
import time
import uuid
from typing import Any

from config.logging_config import setup_logging
from config.settings import settings
from src.ingestion.wazuh_client import WazuhClient
from src.ingestion.log_collector import LogCollector
from src.ingestion.normalizer import LogNormalizer
from src.detection.ioc_detector import IOCDetector
from src.detection.threat_intel import ThreatIntelManager
from src.detection.ml_analyzer import MLAnalyzer
from src.detection.rules_engine import RulesEngine
from src.alerting.thehive_client import TheHiveClient, HiveAlert, HiveCase
from src.alerting.alert_manager import AlertManager, Alert
from src.alerting.notifier import Notifier
from src.alerting.escalation import EscalationManager
from src.response.shuffle_client import ShuffleClient
from src.response.playbook_manager import PlaybookManager
from src.utils.helpers import severity_to_int, truncate

setup_logging(settings.log_level)
logger = logging.getLogger(__name__)


class SOCOrchestrator:
    """Central orchestrator that ties all SOC automation modules together.

    Event loop:
    1. Poll Wazuh for new alerts
    2. Normalize and enrich alerts
    3. Run IOC detection (pattern + ML)
    4. Run correlation rules
    5. Create TheHive alerts/cases for detections
    6. Trigger appropriate Shuffle playbooks
    7. Send notifications
    """

    def __init__(self) -> None:
        logger.info("Initialising SOC Orchestrator")

        # --- Ingestion ---
        self.wazuh = WazuhClient(
            host=settings.wazuh.host,
            username=settings.wazuh.username,
            password=settings.wazuh.password,
            verify_ssl=settings.wazuh.verify_ssl,
        )
        self.collector = LogCollector(
            wazuh_client=self.wazuh,
            poll_interval=settings.wazuh.poll_interval,
        )
        self.normalizer = LogNormalizer()

        # --- Detection ---
        self.ioc_detector = IOCDetector()
        self.threat_intel = ThreatIntelManager(
            abuseipdb_key=settings.threat_intel.abuseipdb_api_key,
            virustotal_key=settings.threat_intel.virustotal_api_key,
            otx_key=settings.threat_intel.otx_api_key,
            cache_ttl=settings.threat_intel.cache_ttl,
        )
        self.ml_analyzer = MLAnalyzer(model_path=settings.ml_model_path)
        self.rules_engine = RulesEngine(rules_dir=settings.rules_dir)

        # --- Alerting ---
        self.hive_client = TheHiveClient(
            url=settings.thehive.url,
            api_key=settings.thehive.api_key,
        )
        self.alert_manager = AlertManager(
            dedup_window=settings.alert_dedup_window,
        )
        self.notifier = Notifier(
            smtp_host=settings.notifications.smtp_host,
            smtp_port=settings.notifications.smtp_port,
            smtp_username=settings.notifications.smtp_username,
            smtp_password=settings.notifications.smtp_password,
            smtp_from=settings.notifications.smtp_from,
            smtp_to=settings.notifications.smtp_to,
            slack_webhook_url=settings.notifications.slack_webhook_url,
            webhook_url=settings.notifications.webhook_url,
        )
        self.escalation_mgr = EscalationManager()

        # --- Response ---
        self.shuffle_client = ShuffleClient(
            url=settings.shuffle.url,
            api_key=settings.shuffle.api_key,
        )
        self.playbook_mgr = PlaybookManager(
            shuffle_client=self.shuffle_client,
            playbooks_dir=settings.playbooks_dir,
        )

        self._running = False

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Start the main SOC automation event loop."""
        self._running = True
        logger.info("SOC Automation started (poll_interval=%ds)", settings.wazuh.poll_interval)

        while self._running:
            try:
                await self._cycle()
            except Exception as exc:
                logger.error("Error in main cycle: %s", exc, exc_info=True)
            self.escalation_mgr.check_escalations()
            await asyncio.sleep(settings.wazuh.poll_interval)

    def stop(self) -> None:
        """Gracefully stop the orchestrator."""
        logger.info("Stopping SOC Automation")
        self._running = False
        self.collector.stop()

    # ------------------------------------------------------------------
    # Single cycle
    # ------------------------------------------------------------------

    async def _cycle(self) -> None:
        logger.debug("Starting collection cycle")
        loop = asyncio.get_event_loop()

        # 1. Collect logs
        raw_logs = await loop.run_in_executor(None, self.collector.collect_once)
        if not raw_logs:
            logger.debug("No new logs")
            return

        # 2. Normalize
        normalized = self.normalizer.normalize_batch(raw_logs, source="wazuh")
        log_dicts = [log.model_dump() for log in normalized]

        # 3. ML anomaly analysis
        anomaly = self.ml_analyzer.analyze_batch(log_dicts)
        if anomaly.is_anomaly:
            logger.warning("ML anomaly detected: score=%.2f — %s", anomaly.anomaly_score, anomaly.explanation)

        # 4. IOC detection + rules
        for norm_log in normalized:
            text = f"{norm_log.raw_message or ''} {norm_log.source_ip or ''} {norm_log.destination_ip or ''}"
            ioc_matches = self.ioc_detector.detect(text)
            rule_matches = self.rules_engine.evaluate(norm_log.model_dump())

            if not ioc_matches and not rule_matches and not anomaly.is_anomaly:
                continue

            # 5. Build internal alert
            severity = norm_log.severity or "medium"
            ioc_data = [
                {"type": m.ioc_type, "value": m.value, "confidence": m.confidence}
                for m in ioc_matches
            ]
            alert = Alert(
                alert_id=str(uuid.uuid4()),
                title=self._build_title(norm_log, ioc_matches, rule_matches),
                description=self._build_description(norm_log, ioc_matches, rule_matches, anomaly),
                severity=severity,
                source="wazuh",
                tags=list({m.ioc_type for m in ioc_matches} | {r.rule_name for r in rule_matches}),
                iocs=ioc_data,
                raw_data=norm_log.model_dump(),
            )
            processed = self.alert_manager.process(alert)
            if not processed:
                continue

            # 6. Create TheHive alert
            await loop.run_in_executor(None, self._create_hive_alert, processed)

            # 7. Trigger Shuffle playbook
            alert_type = self._infer_alert_type(rule_matches, ioc_matches)
            await loop.run_in_executor(
                None,
                lambda: self.playbook_mgr.execute(alert_type, processed.alert_id, {"severity": severity}),
            )

            # 8. Notify
            await loop.run_in_executor(
                None,
                lambda: self.notifier.notify(
                    title=processed.title,
                    description=truncate(processed.description, 500),
                    severity=processed.severity,
                    score=processed.composite_score,
                ),
            )

            # Register for SLA tracking
            self.escalation_mgr.register_alert(processed.alert_id, processed.severity)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_title(self, log: Any, ioc_matches: list, rule_matches: list) -> str:
        if rule_matches:
            return rule_matches[0].rule_name
        if ioc_matches:
            return f"IOC Detected: {ioc_matches[0].ioc_type.upper()} — {ioc_matches[0].value}"
        return f"Security Event: {log.event_type or 'Unknown'}"

    def _build_description(self, log: Any, ioc_matches: list, rule_matches: list, anomaly: Any) -> str:
        parts = []
        if log.rule_description:
            parts.append(f"Rule: {log.rule_description}")
        if rule_matches:
            parts.append(f"Matched rules: {', '.join(r.rule_name for r in rule_matches)}")
        if ioc_matches:
            parts.append(f"IOCs: {', '.join(f'{m.ioc_type}:{m.value}' for m in ioc_matches)}")
        if anomaly.is_anomaly:
            parts.append(f"ML anomaly: {anomaly.explanation}")
        if log.source_ip:
            parts.append(f"Source IP: {log.source_ip}")
        if log.agent_name:
            parts.append(f"Agent: {log.agent_name}")
        return " | ".join(parts) or "Security event detected"

    def _infer_alert_type(self, rule_matches: list, ioc_matches: list) -> str:
        for r in rule_matches:
            name = r.rule_name.lower()
            if "brute" in name or "failed login" in name:
                return "brute_force"
            if "malware" in name or "virus" in name:
                return "malware"
            if "lateral" in name:
                return "lateral_movement"
            if "exfil" in name:
                return "data_exfiltration"
        if ioc_matches:
            return "malware"
        return "suspicious_network"

    def _create_hive_alert(self, alert: Alert) -> None:
        try:
            hive_alert = HiveAlert(
                title=alert.title,
                description=alert.description,
                severity=severity_to_int(alert.severity),
                source_ref=alert.alert_id,
                tags=alert.tags,
                observables=[
                    {"dataType": ioc["type"], "data": ioc["value"]}
                    for ioc in alert.iocs
                ],
            )
            self.hive_client.create_alert(hive_alert)
        except Exception as exc:
            logger.error("Failed to create TheHive alert: %s", exc)


def main() -> None:
    """Application entry point."""
    orchestrator = SOCOrchestrator()

    def _handle_signal(sig: int, frame: Any) -> None:
        logger.info("Received signal %s, shutting down", sig)
        orchestrator.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    asyncio.run(orchestrator.run())


if __name__ == "__main__":
    main()
