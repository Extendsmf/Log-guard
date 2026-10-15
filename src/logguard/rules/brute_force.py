from typing import Optional
from datetime import datetime, timezone
from ..models import Alert, LogEvent
from .base import BaseRule
from collections import deque, defaultdict


class DirectoryBruteforceRule(BaseRule):

    rule_name = "WEB_DIRECTORY_BRUTEFORCE"
    severity = "MEDIUM"
    mitre_technique_id = "T1083" #File and Directory Discovery
    mitre_tactic = "Discovery"

    def __init__(self, threshold: int = 5, window_seconds: int = 10):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.state = defaultdict(deque)

    def check(self, event: LogEvent) -> Optional[Alert]:
        if event.status_code != 404:
            return None

        self.state[event.ip].append(event.timestamp)

        while self.state[event.ip] and (event.timestamp - self.state[event.ip][0]).total_seconds() > self.window_seconds:
            self.state[event.ip].popleft()

        if len(self.state[event.ip]) >= self.threshold:
            alert = Alert(datetime.now(timezone.utc), self.rule_name, self.severity, self.mitre_technique_id, self.mitre_tactic, event.ip,  f"{len(self.state[event.ip])} 404 responses in {self.window_seconds}s", event)
            self.state[event.ip].clear()
            return alert

        return None
        
