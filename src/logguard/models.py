from dataclasses import dataclass
from datetime import datetime


@dataclass
class LogEvent:
    ip: str # ip адрес
    timestamp: datetime # Время самого события
    method: str # Метод запроса
    raw_path: str # Сырой запрошенный путь
    normalised_path:str # Декодированный путь
    protocol: str # Протокол соединения
    status_code: int # Статус код (200 / 404 / 502)
    response_size: int # Размер ответа
    referer: str # Адрес источника запроса (страница-источник)
    user_agent: str # Cигнатура клиента
    raw_log: str # Сырой лог без обработки

@dataclass
class Alert:
    timestamp: datetime # Время самого события
    rule_name: str # Правило, на которое сработал алерт
    severity: str # Уровень опасности 
    mitre_technique_id: str # Техника MITRE ATT&CK
    mitre_tactic: str # Тактика MITRE ATT&CK
    source_ip: str # ip адрес
    matched_indicator: str # Что именно в логе вызвало алерт
    event: LogEvent # Объект LogEvent, который вызвал алерт
    
