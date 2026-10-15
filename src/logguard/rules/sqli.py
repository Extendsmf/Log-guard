from typing import Optional
from datetime import datetime, timezone
from ..models import Alert, LogEvent
from .base import BaseRule
import re

pattern = re.compile(r"UNION\s+(?:ALL\s+)?SELECT|'\s+OR\s+1=1|'\s+OR\s+'1'='1'|--\s+|/\*.*?\*/|SLEEP\s*\(\d+\)|WAITFOR DELAY", re.IGNORECASE)

class SqlInjectionRule (BaseRule):

    rule_name = "WEB_SQL_INJECTION"
    severity = "CRITICAL"
    mitre_technique_id = "T1190" #Exploit Public-Facing Application
    mitre_tactic = "Initial Access"

    def check(self, event: LogEvent) -> Optional[Alert]:
        text = event.normalised_path
        result = pattern.search(text)

        if result:
            alert = Alert(datetime.now(timezone.utc), self.rule_name, self.severity, self.mitre_technique_id, self.mitre_tactic, event.ip,  result.group(0), event)
            return alert
        else:
            return None


