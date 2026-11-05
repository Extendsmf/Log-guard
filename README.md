# LogGuard — Log Intrusion Detector & Observability Stack (Mini-SIEM)

Легковесный сервис на Python для потокового анализа веб-логов Nginx в реальном времени (`tail -f`). Обнаруживает веб-атаки, выявляет перебор директорий через скользящее окно времени, экспортирует метрики безопасности в **Prometheus** и визуализирует инциденты в **Grafana**.

В проект встроен автоматический **CI/CD пайплайн (GitHub Actions)** с тестированием, линтингом и DevSecOps-сканированием уязвимостей через **Trivy**.

---

## Что умеет детектировать

* **SQL Injection (T1190):** поиск `UNION SELECT`, обхода условий (`' OR 1=1`), комментариев (`--`) и `SLEEP()`.
* **Path Traversal (T1083):** попытки выхода из директории (`../`, `..\`) и чтение системных файлов с защитой от double URL-encoding (`%252e`).
* **Directory Brute-force (T1083):** поведенческий анализ — отслеживание $\ge 5$ ответов `404` за 10 секунд с одного IP (скользящее окно `deque`).
* **Сканеры уязвимостей (T1595.002):** детект утилит по User-Agent (`sqlmap`, `nikto`, `gobuster`, `dirbuster`, `nuclei`).

---

## Архитектура стенда (Docker Compose)

Проект разворачивает изолированную сеть из 4 сервисов:
* **`web`** (Nginx, `:8080`) — веб-сервер, генерирующий поток `access.log`.
* **`logguard`** (`:8000`) — ядро детекта, отдающее метрики на эндпоинт `/metrics`.
* **`prometheus`** (`:9090`) — TSDB, опрашивающая LogGuard раз в 5 секунд.
* **`grafana`** (`:3000`, `admin:admin`) — дашборд мониторинга и графики атак.

---

## Быстрый старт

### 1. Запуск стека
```bash
docker compose up --build -d
```

### 2. Тестирование атак
* **SQL Injection (критичный алерт + изоляция IP):**
  ```bash
  curl "http://localhost:8080/products.php?id=1%27%20UNION%20SELECT%20null--%20"
  ```
* **Брутфорс директорий (всплеск 404):**
  ```bash
  for i in {1..7}; do curl -s "http://localhost:8080/admin_$i" > /dev/null; done
  ```

### 3. Где смотреть результаты
* **Метрики в Prometheus:** `http://localhost:9090` (метрики `logguard_alerts_total` и `logguard_logs_processed_total`).
* **Дашборды Grafana:** `http://localhost:3000` (логин/пароль: `admin` / `admin`).
* **Артефакты инцидентов:** `alerts.json` (события в NDJSON с маппингом MITRE) и `blocked_ips.txt` (Active Response).

---

## CI/CD & DevSecOps

При каждом пуше в ветку `main` запускается GitHub Actions workflow:
1. **Linter:** статический анализ кода через **Ruff**.
2. **Unit Tests:** автоматические тесты парсера и логики правил через **Pytest**.
3. **Container Security:** аудит собранного Docker-образа на CVE-уязвимости с помощью **Trivy**.

---

## Запуск без Docker (CLI)

```bash
pip install -r requirements.txt

# Разовый анализ готового файла
python main.py --file access.log

# Мониторинг в реальном времени
python main.py --file /var/log/nginx/access.log --follow
```
