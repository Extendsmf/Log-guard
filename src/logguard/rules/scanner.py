from typing import Optional
from datetime import datetime, timezone
from ..models import Alert, LogEvent
from .base import BaseRule
import re

user_agent_pattern = re.compile(r"nikto|sqlmap|nmap|masscan|dirbuster|gobuster|nuclei|wpscan", re.IGNORECASE)
path_pattern = re.compile(r"/\.env|/\.git|/wp-login\.php|/phpmyadmin", re.IGNORECASE)


class VulnerabilityScannerDetector(BaseRule):

    rule_name = "WEB_SCANNER_DETECTED"
    severity = "LOW"
    mitre_technique_id = "T1595.002" #Active Scanning: Vulnerability Scanning
    mitre_tactic = "Reconnaissance"

    def check(self, event: LogEvent) -> Optional[Alert]:
        text = event.normalised_path
        path_result = path_pattern.search(text)
        user_agent_result = user_agent_pattern.search(event.user_agent)

        if user_agent_result:
            alert = Alert(datetime.now(timezone.utc), self.rule_name, self.severity, self.mitre_technique_id, self.mitre_tactic, event.ip,  user_agent_result.group(0), event)
            return alert

        if path_result:
            alert = Alert(datetime.now(timezone.utc), self.rule_name, self.severity, self.mitre_technique_id, self.mitre_tactic, event.ip,  path_result.group(0), event)
            return alert

        return None

