FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY src/ ./src/
COPY main.py .
ENTRYPOINT ["python", "main.py"]