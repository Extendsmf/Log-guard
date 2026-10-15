from dataclasses import dataclass
from datetime import datetime

@dataclass
class LogEvent:
    ip: str
    timestamp: datetime
    method: str
    raw_path: str
    normalised_path:str
    protocol: str
    status_code: int
    response_size: int
    referer: str
    user_agent: str
    raw_log: str

@dataclass
class Alert:
    timestamp: datetime
    rule_name: str
    severity: str
    mitre_technique_id: str
    mitre_tactic: str
    source_ip: str
    matched_indicator: str
    event: LogEvent
    
