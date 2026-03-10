"""Central configuration loader for SOC Automation."""

import os
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()


def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _env_int(key: str, default: int = 0) -> int:
    try:
        return int(os.environ.get(key, default))
    except (TypeError, ValueError):
        return default


def _env_bool(key: str, default: bool = False) -> bool:
    val = os.environ.get(key, str(default)).lower()
    return val in ("1", "true", "yes")


@dataclass
class WazuhConfig:
    host: str = field(default_factory=lambda: _env("WAZUH_HOST", "https://wazuh-manager:55000"))
    username: str = field(default_factory=lambda: _env("WAZUH_USERNAME", "wazuh-wui"))
    password: str = field(default_factory=lambda: _env("WAZUH_PASSWORD", ""))
    verify_ssl: bool = field(default_factory=lambda: _env_bool("WAZUH_VERIFY_SSL", False))
    poll_interval: int = field(default_factory=lambda: _env_int("WAZUH_POLL_INTERVAL", 60))


@dataclass
class TheHiveConfig:
    url: str = field(default_factory=lambda: _env("THEHIVE_URL", "http://thehive:9000"))
    api_key: str = field(default_factory=lambda: _env("THEHIVE_API_KEY", ""))


@dataclass
class ShuffleConfig:
    url: str = field(default_factory=lambda: _env("SHUFFLE_URL", "http://shuffle-backend:3001"))
    api_key: str = field(default_factory=lambda: _env("SHUFFLE_API_KEY", ""))


@dataclass
class ThreatIntelConfig:
    abuseipdb_api_key: str = field(default_factory=lambda: _env("ABUSEIPDB_API_KEY", ""))
    virustotal_api_key: str = field(default_factory=lambda: _env("VIRUSTOTAL_API_KEY", ""))
    otx_api_key: str = field(default_factory=lambda: _env("OTX_API_KEY", ""))
    cache_ttl: int = field(default_factory=lambda: _env_int("CACHE_TTL", 3600))


@dataclass
class NotificationConfig:
    smtp_host: str = field(default_factory=lambda: _env("SMTP_HOST", ""))
    smtp_port: int = field(default_factory=lambda: _env_int("SMTP_PORT", 587))
    smtp_username: str = field(default_factory=lambda: _env("SMTP_USERNAME", ""))
    smtp_password: str = field(default_factory=lambda: _env("SMTP_PASSWORD", ""))
    smtp_from: str = field(default_factory=lambda: _env("SMTP_FROM", ""))
    smtp_to: str = field(default_factory=lambda: _env("SMTP_TO", ""))
    slack_webhook_url: str = field(default_factory=lambda: _env("SLACK_WEBHOOK_URL", ""))
    webhook_url: str = field(default_factory=lambda: _env("WEBHOOK_URL", ""))


@dataclass
class AppConfig:
    log_level: str = field(default_factory=lambda: _env("LOG_LEVEL", "INFO"))
    environment: str = field(default_factory=lambda: _env("ENVIRONMENT", "production"))
    alert_dedup_window: int = field(default_factory=lambda: _env_int("ALERT_DEDUP_WINDOW", 300))
    ml_model_path: str = field(default_factory=lambda: _env("ML_MODEL_PATH", "models/isolation_forest.pkl"))
    rules_dir: str = field(default_factory=lambda: _env("RULES_DIR", "rules"))
    playbooks_dir: str = field(default_factory=lambda: _env("PLAYBOOKS_DIR", "playbooks"))
    wazuh: WazuhConfig = field(default_factory=WazuhConfig)
    thehive: TheHiveConfig = field(default_factory=TheHiveConfig)
    shuffle: ShuffleConfig = field(default_factory=ShuffleConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)


# Singleton configuration instance
settings = AppConfig()
