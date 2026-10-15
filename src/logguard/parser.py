import re
from urllib.parse import unquote
from .models import LogEvent
from datetime import datetime


LOG_PATTERN = re.compile(
        r"""
        ^(?P<ip>\S+)                     # IP клиента (любые непробельные символы)
        \s+\S+\s+\S+\s+                 # Пропускаем ident и authuser ("- -")
        \[(?P<date>[^\]]+)\]            # Дата внутри квадратных скобок [ ... ]
        \s+
        "(?P<method>[A-Z]+)             # HTTP метод внутри кавычки: "GET
        \s+
        (?P<path>\S+)                   # Запрошенный путь (URI): /index.html
        \s+
        (?P<protocol>[^"]+)"            # Протокол и закрывающая кавычка: HTTP/1.1"
        \s+
        (?P<status>\d{3})
        \s+
        (?P<size>\d+)
        \s+
        "(?P<referer>[^"]*)"
        \s+
        "(?P<user_agent>[^"]*)"
        (?:\s+"(?P<x_forwarded_for>[^"]*)")?   # Опциональный X-Forwarded-For в кавычках
        \s*$
        """,
        re.VERBOSE,
    )

def parser(log_line: str):
    #"""203.0.113.42 - - [10/May/2026:14:32:20 +0000] "POST /login.php HTTP/1.1" 500 240 "https://example.com" "sqlmap/1.6""""
    log = log_line.strip()
    pattern = LOG_PATTERN
    match = pattern.match(log)

    if not match: 
        return None
    
    data = match.groupdict()
    status_code = int(data["status"])
    response_size = int(data["size"])

    dt_obj = datetime.strptime(data["date"], "%d/%b/%Y:%H:%M:%S %z")

    raw_path = data["path"]
    decoded = unquote(raw_path)

    if "%" in decoded:
        decoded = unquote(decoded)


    return LogEvent(data["ip"],dt_obj,data["method"],raw_path, decoded,  data["protocol"],status_code,response_size, data["referer"],data["user_agent"], log_line)

