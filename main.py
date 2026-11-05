import argparse
import sys
from prometheus_client import start_http_server, Counter

from src.logguard.parser import parser
from src.logguard.engine import DetectionEngine
from src.logguard.dispatcher import AlertDispatcher
from src.logguard.reader import read_gen

# Метрики для Prometheus
LOGS_TOTAL = Counter('logguard_logs_processed_total', 'Всего обработано строк логов')
ALERTS_TOTAL = Counter(
    'logguard_alerts_total', 
    'Количество обнаруженных угроз безопасности', 
    ['rule_name', 'severity']
)

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("--file", type=str, required=True, help="Путь к файлу с логами")
arg_parser.add_argument("--follow", action="store_true", help="Следовать за новыми строками в реальном времени (tail -f)")
arg_parser.add_argument("--metrics-port", type=int, default=8000, help="Порт для эндпоинта Prometheus /metrics")
args = arg_parser.parse_args()

filepath = args.file
follow = args.follow

# Запуск экспортера метрик на порту 8000 (эндпоинт /metrics)
try:
    start_http_server(args.metrics_port)
    print(f"[*] Prometheus metrics server started on port {args.metrics_port}")
except Exception as e:
    print(f"[!] Warning: Could not start metrics server: {e}")

engine = DetectionEngine() 
dispatcher = AlertDispatcher()

try:
    for line in read_gen(filepath, follow):
        LOGS_TOTAL.inc()  # Увеличиваем счетчик обработанных логов
        event = parser(line)
        if event:
            alerts = engine.detect(event)
            for alert in alerts:
                # Фиксируем инцидент с лейблами правила и критичности
                rule_name = getattr(alert, 'rule_name', 'UNKNOWN')
                severity = getattr(alert, 'severity', 'INFO')
                ALERTS_TOTAL.labels(rule_name=rule_name, severity=severity).inc()
                
                dispatcher.dispatch(alert)
except KeyboardInterrupt:
    print('Interrupted')
    sys.exit(0)