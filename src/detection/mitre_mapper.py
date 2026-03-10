"""MITRE ATT&CK Mapper — maps alerts and rule matches to MITRE ATT&CK techniques."""

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class MITRETechnique:
    """A single MITRE ATT&CK technique."""

    technique_id: str
    name: str
    tactic: list[str]
    description: str
    url: str = ""

    def __post_init__(self) -> None:
        if not self.url:
            tid = self.technique_id.replace(".", "/")
            self.url = f"https://attack.mitre.org/techniques/{tid}/"


# ---------------------------------------------------------------------------
# Built-in technique database (20+ techniques)
# ---------------------------------------------------------------------------

MITRE_TECHNIQUE_DB: dict[str, MITRETechnique] = {
    t.technique_id: t
    for t in [
        # Initial Access
        MITRETechnique("T1190", "Exploit Public-Facing Application", ["Initial Access"],
                       "Adversaries exploit weaknesses in internet-facing systems."),
        MITRETechnique("T1566", "Phishing", ["Initial Access"],
                       "Adversaries send phishing messages to gain access."),
        MITRETechnique("T1078", "Valid Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"],
                       "Adversaries use valid credentials to gain access."),
        # Execution
        MITRETechnique("T1059", "Command and Scripting Interpreter", ["Execution"],
                       "Adversaries abuse command-line interpreters to execute commands."),
        MITRETechnique("T1059.001", "Command and Scripting Interpreter: PowerShell", ["Execution"],
                       "Adversaries abuse PowerShell to execute commands."),
        MITRETechnique("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", ["Execution"],
                       "Adversaries abuse the Windows command shell."),
        MITRETechnique("T1204", "User Execution", ["Execution"],
                       "Adversaries rely on user action to execute malicious code."),
        # Persistence
        MITRETechnique("T1053", "Scheduled Task/Job", ["Persistence", "Privilege Escalation", "Execution"],
                       "Adversaries abuse task scheduling to execute programs at startup."),
        MITRETechnique("T1543", "Create or Modify System Process", ["Persistence", "Privilege Escalation"],
                       "Adversaries create or modify system-level processes."),
        # Privilege Escalation
        MITRETechnique("T1068", "Exploitation for Privilege Escalation", ["Privilege Escalation"],
                       "Adversaries exploit software vulnerabilities to elevate privileges."),
        MITRETechnique("T1134", "Access Token Manipulation", ["Privilege Escalation", "Defense Evasion"],
                       "Adversaries modify access tokens to operate under different privileges."),
        # Defense Evasion
        MITRETechnique("T1562", "Impair Defenses", ["Defense Evasion"],
                       "Adversaries impair tools used to analyze or respond to activity."),
        MITRETechnique("T1027", "Obfuscated Files or Information", ["Defense Evasion"],
                       "Adversaries obfuscate content to make detection more difficult."),
        # Credential Access
        MITRETechnique("T1003", "OS Credential Dumping", ["Credential Access"],
                       "Adversaries dump credentials to obtain account login information."),
        MITRETechnique("T1110", "Brute Force", ["Credential Access"],
                       "Adversaries attempt to gain access to accounts by guessing credentials."),
        MITRETechnique("T1555", "Credentials from Password Stores", ["Credential Access"],
                       "Adversaries search for common password storage locations."),
        # Discovery
        MITRETechnique("T1046", "Network Service Discovery", ["Discovery"],
                       "Adversaries scan networks to gather information about services."),
        MITRETechnique("T1083", "File and Directory Discovery", ["Discovery"],
                       "Adversaries enumerate files and directories."),
        # Lateral Movement
        MITRETechnique("T1021", "Remote Services", ["Lateral Movement"],
                       "Adversaries use valid accounts to log into remote services."),
        MITRETechnique("T1021.001", "Remote Services: Remote Desktop Protocol", ["Lateral Movement"],
                       "Adversaries use Valid Accounts to log into a computer using RDP."),
        # Collection
        MITRETechnique("T1560", "Archive Collected Data", ["Collection"],
                       "Adversaries may compress and/or encrypt data before exfiltration."),
        MITRETechnique("T1005", "Data from Local System", ["Collection"],
                       "Adversaries search local system sources for files of interest."),
        # Command and Control
        MITRETechnique("T1071", "Application Layer Protocol", ["Command and Control"],
                       "Adversaries communicate using OSI application layer protocols."),
        MITRETechnique("T1071.004", "Application Layer Protocol: DNS", ["Command and Control"],
                       "Adversaries communicate using DNS to avoid detection."),
        MITRETechnique("T1095", "Non-Application Layer Protocol", ["Command and Control"],
                       "Adversaries use non-application layer protocols for C2 communications."),
        # Exfiltration
        MITRETechnique("T1041", "Exfiltration Over C2 Channel", ["Exfiltration"],
                       "Adversaries steal data by exfiltrating it over an existing C2 channel."),
        MITRETechnique("T1048", "Exfiltration Over Alternative Protocol", ["Exfiltration"],
                       "Adversaries steal data by exfiltrating it over a different protocol."),
        # Impact
        MITRETechnique("T1486", "Data Encrypted for Impact", ["Impact"],
                       "Adversaries encrypt data to interrupt availability (ransomware)."),
        MITRETechnique("T1490", "Inhibit System Recovery", ["Impact"],
                       "Adversaries delete shadow copies and backups to inhibit recovery."),
        MITRETechnique("T1485", "Data Destruction", ["Impact"],
                       "Adversaries destroy data to interrupt availability."),
    ]
}

# ---------------------------------------------------------------------------
# Keyword → technique mapping
# ---------------------------------------------------------------------------

KEYWORD_TO_TECHNIQUE: dict[str, list[str]] = {
    "powershell": ["T1059.001"],
    "cmd.exe": ["T1059.003"],
    "command shell": ["T1059.003"],
    "credential dump": ["T1003"],
    "mimikatz": ["T1003"],
    "lsass": ["T1003"],
    "brute force": ["T1110"],
    "failed login": ["T1110"],
    "password spray": ["T1110"],
    "lateral movement": ["T1021"],
    "rdp": ["T1021.001"],
    "remote desktop": ["T1021.001"],
    "data exfil": ["T1041"],
    "exfiltration": ["T1041", "T1048"],
    "c2": ["T1071"],
    "command and control": ["T1071"],
    "dns tunnel": ["T1071.004"],
    "dns tunneling": ["T1071.004"],
    "port scan": ["T1046"],
    "nmap": ["T1046"],
    "network scan": ["T1046"],
    "phishing": ["T1566"],
    "ransomware": ["T1486"],
    "encrypt": ["T1486"],
    "shadow copy": ["T1490"],
    "scheduled task": ["T1053"],
    "cron": ["T1053"],
    "privilege escalation": ["T1068"],
    "token manipulation": ["T1134"],
    "defense evasion": ["T1562"],
    "obfuscat": ["T1027"],
    "encoded command": ["T1027", "T1059.001"],
    "base64": ["T1027"],
    "valid account": ["T1078"],
    "malware": ["T1204"],
    "trojan": ["T1204"],
    "exploit": ["T1190", "T1068"],
}


class MITREMapper:
    """Map SOC alerts and rule matches to MITRE ATT&CK techniques."""

    def __init__(self) -> None:
        self._db = MITRE_TECHNIQUE_DB
        self._keyword_map = KEYWORD_TO_TECHNIQUE

    def map_alert(
        self,
        alert_title: str = "",
        rule_names: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
    ) -> list[MITRETechnique]:
        """Return MITRE techniques relevant to the given alert context."""
        technique_ids: set[str] = set()
        text_sources = [alert_title] + (rule_names or []) + (tags or [])
        combined = " ".join(text_sources).lower()

        for keyword, tids in self._keyword_map.items():
            if keyword in combined:
                technique_ids.update(tids)

        return [self._db[tid] for tid in sorted(technique_ids) if tid in self._db]

    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Look up a technique by its ID (e.g. 'T1059.001')."""
        return self._db.get(technique_id)

    def list_techniques(self, tactic: Optional[str] = None) -> list[MITRETechnique]:
        """Return all known techniques, optionally filtered by tactic name."""
        techniques = list(self._db.values())
        if tactic:
            techniques = [t for t in techniques if tactic in t.tactic]
        return techniques
