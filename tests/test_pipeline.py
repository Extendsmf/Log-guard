from src.logguard.parser import parser
from src.logguard.rules.brute_force import DirectoryBruteforceRule


def test_parser_valid_log():
    # Проверяем, что парсер корректно разбирает строку Nginx
    raw_log = '172.19.0.1 - - [05/Nov/2026:22:42:14 +0000] "GET /test HTTP/1.1" 404 153 "-" "curl/8.22.0" "-"'
    event = parser(raw_log)
    
    assert event is not None
    assert getattr(event, 'ip', getattr(event, 'source_ip', None)) == '172.19.0.1'
    assert int(event.status_code) == 404

def test_parser_invalid_log():
    # Проверяем, что мусорная строка не роняет парсер
    assert parser("invalid log line") is None
    assert parser("") is None

def test_bruteforce_rule_initialization():
    # Проверяем инициализацию правила брутфорса
    rule = DirectoryBruteforceRule(threshold=5, window_seconds=10)
    assert rule.threshold == 5
    assert rule.window_seconds == 10
    assert rule.rule_name == "WEB_DIRECTORY_BRUTEFORCE"