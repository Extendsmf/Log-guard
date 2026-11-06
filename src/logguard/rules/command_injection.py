from datetime import UTC, datetime
import re

from ..models import Alert, LogEvent
from .base import BaseRule


class CommandInjectionRule(BaseRule):

    rule_name = "COMMAND_INJECTION"
    severity = "CRITICAL"
    mitre_technique_id = "T1059" # Command and Scripting Interpreter
    mitre_tactic = "Execution"

    def __init__(self):
        # Паттерны опасных команд и инъекций
        patterns = [
            r";\s*id\b",                       # ;id или ; id
            r"\bwhoami\b",                     # whoami как отдельное слово
            r"\$\(cat\s+/etc/passwd\)",        # $(cat /etc/passwd)
            r"[;&|`]\s*(?:curl|wget)\b",       # вызов curl/wget через разделители команды
            r"\bpowershell(?:\.exe)?\b",       # powershell или powershell.exe
            r"\bcmd(?:\.exe)?\b",              # cmd или cmd.exe
            r"/bin/(?:sh|bash)"                # прямой вызов шелла /bin/sh
        ]
        # Собираем в единое регулярное выражение без лишних пробелов
        self.pattern = re.compile("|".join(patterns), re.IGNORECASE)    

    def check(self, event: LogEvent) -> Alert | None:

        text = event.normalised_path

        result = self.pattern.search(text)
        
        if result:
            alert = Alert(datetime.now(UTC), self.rule_name, self.severity, self.mitre_technique_id, self.mitre_tactic, event.ip,  result.group(0), event)
            return alert
        else:
            return None


        
