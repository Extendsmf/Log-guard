from abc import ABC, abstractmethod

from ..models import Alert, LogEvent


class BaseRule(ABC):
    rule_name: str
    severity: str
    mitre_technique_id: str
    mitre_tactic: str

    @abstractmethod
    def check(self, event: LogEvent) -> Alert | None:
        
        pass

