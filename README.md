# LogGuard — Log Intrusion Detector (Mini-SIEM)

Легковесный сервис на Python для анализа логов Nginx в реальном времени. Читает поток логов (`tail -f`), находит веб-атаки и сканеры, выявляет перебор директорий через скользящее окно времени и сохраняет структурированные алерты в JSON с имитацией блокировки IP.

Написан на чистой стандартной библиотеке Python (без сторонних зависимостей).

---

## Что умеет детектировать

* **SQL Injection (T1190):** поиск `UNION SELECT`, обхода условий (`' OR 1=1`), комментариев (`--`) и `SLEEP()`.
* **Path Traversal (T1083):** попытки выхода из директории (`../`, `..\`) и чтение системных файлов (`/etc/passwd`, `win.ini`) с защитой от двойного URL-кодирования (`%252e`).
* **Directory Brute-force (T1083):** поведенческий анализ — отслеживает превышение порога в $\ge 5$ ответов `404` за 10 секунд с одного IP.
* **Сканеры уязвимостей (T1595.002):** выявление автоматизированных утилит по User-Agent (`sqlmap`, `nikto`, `gobuster`, `dirbuster`, `nuclei`).

---

## Быстрый старт (Docker Compose)

Проект поставляется с готовым стендом: контейнер с **Nginx** (пишет логи) и контейнер с **LogGuard** (слушает их в режиме `:ro`).

### 1. Запуск
```bash
docker compose up --build
```

### 2. Проверка работы (из соседнего терминала)

* **Тест SQLi (критичный алерт + бан IP):**
  ```bash
  curl "http://localhost:8080/products.php?id=1%27%20UNION%20SELECT%20null--%20"
  ```

* **Тест брутфорса директорий:**
  ```bash
  for dir in admin backup secret config .git; do curl -s "http://localhost:8080/$dir" -A "gobuster/3.1"; sleep 0.5; done
  ```

### 3. Результаты работы
* `alerts.json` — структурированные события в формате NDJSON.
* `blocked_ips.txt` — список IP-адресов, заблокированных модулем Active Response (для атак уровня HIGH и CRITICAL).

---

## Формат алерта (`alerts.json`)

Каждое срабатывание записывается в одну строку JSON с метаданными MITRE ATT&CK и сырым логом для расследования:

```json
{
  "timestamp": "2026-10-15T13:34:54.120531+00:00",
  "rule_name": "WEB_SQL_INJECTION",
  "severity": "CRITICAL",
  "mitre": {
    "technique_id": "T1190",
    "tactic": "Initial Access"
  },
  "source_ip": "172.18.0.1",
  "indicator": "UNION SELECT",
  "raw_log": "172.18.0.1 - - [15/Oct/2026:13:34:54 +0000] \"GET /products.php?id=1%27%20UNION%20SELECT%20null--%20 HTTP/1.1\" 404 153 \"-\" \"curl/8.22.0\" \"-\""
}
```

---

## Запуск без Docker (CLI)

```bash
# Разовый анализ готового файла
python main.py --file access.log

# Мониторинг в реальном времени
python main.py --file /var/log/nginx/access.log --follow
```


