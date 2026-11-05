FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# ВОТ ЭТИ ДВЕ СТРОЧКИ КРИТИЧНО ВАЖНЫ:
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/sh -m appuser

COPY src/ ./src/
COPY main.py .

RUN touch alerts.json blocked_ips.txt && \
    chown -R appuser:appgroup /app

USER appuser
EXPOSE 8000

ENTRYPOINT ["python", "main.py"]
