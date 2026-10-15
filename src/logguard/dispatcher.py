import json
from .models import Alert

class AlertDispatcher:

    def __init__(self, output_file: str = "alerts.json"):
        self.output_file = output_file
        self.blocked_ips: set[str] = set()

    def dispatch(self, alert: Alert):
        alert_dict = {
            "timestamp" : alert.timestamp.isoformat(), 
            "rule_name" : alert.rule_name, 
            "severity" : alert.severity, 
            "mitre": {"technique_id": alert.mitre_technique_id, "tactic": alert.mitre_tactic}, 
            "source_ip": alert.source_ip, 
            "indicator": alert.matched_indicator, 
            "raw_log" : alert.event.raw_log
        }

        json_line = json.dumps(alert_dict, ensure_ascii=False)
        with open(self.output_file, "a", encoding="utf-8") as f:
            f.write(json_line + "\n")

        if alert.severity in ("HIGH", "CRITICAL"):
            self._active_response(alert.source_ip, alert.rule_name)

    
    def _active_response(self, ip: str, reason: str):
        if ip in self.blocked_ips:
            return

        self.blocked_ips.add(ip)
        print(f"[ACTIVE RESPONSE] IP {ip} BLOCKED! Simulated command: iptables -A INPUT -s {ip} -j DROP (Reason: {reason})")
        with open("blocked_ips.txt", "a", encoding="utf-8") as f:
                    f.write(ip + "\n")

        


