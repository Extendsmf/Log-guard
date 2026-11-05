from .models import Alert, LogEvent
from .rules.base import BaseRule
from .rules.brute_force import DirectoryBruteforceRule
from .rules.path_traversal import PathTraversalRule
from .rules.scanner import VulnerabilityScannerDetector
from .rules.sqli import SqlInjectionRule


class DetectionEngine:

    def __init__(self):
        self.rules: list[BaseRule] = [
            SqlInjectionRule(),
            VulnerabilityScannerDetector(),
            PathTraversalRule(),
            DirectoryBruteforceRule()
        ]

    
    def detect(self, event: LogEvent) -> list[Alert]:
        alerts = []
        for rule in self.rules:
            alert = rule.check(event)
            if alert:
                alerts.append(alert)

        return alerts
    

    
