from typing import Optional
from datetime import datetime, timezone
from ..models import Alert, LogEvent
from .base import BaseRule
import re

class PathTraversalRule(BaseRule):

    rule_name = "WEB_PATH_TRAVERSAL"
    severity = "HIGH"
    mitre_technique_id = "T1083" #File and Directory Discovery
    mitre_tactic = "Discovery"

    def check(self, event: LogEvent) -> Optional[Alert]:
        text = event.normalised_path
        pattern = r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|/proc/self/|windows/win\.ini|boot\.ini"
        result = re.search(pattern, text, re.IGNORECASE)

        if result:
            alert = Alert(datetime.now(timezone.utc), self.rule_name, self.severity, self.mitre_technique_id, self.mitre_tactic, event.ip,  result.group(0), event)
            return alert
        else:
            return None



