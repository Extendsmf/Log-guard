from ..models import Alert, LogEvent
from typing import Optional
from abc import ABC, abstractmethod

class BaseRule(ABC):
    rule_name: str
    severity: str
    mitre_technique_id: str
    mitre_tactic: str

    @abstractmethod
    def check(self, event: LogEvent) -> Optional[Alert]:
        
        pass

