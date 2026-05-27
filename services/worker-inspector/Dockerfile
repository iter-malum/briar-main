FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

# ── Inspector tuning defaults (override via docker-compose environment:) ───────
ENV INSPECTOR_MAX_ENDPOINTS=300 \
    INSPECTOR_MAX_PARAMS=15 \
    INSPECTOR_TIMEOUT=10 \
    INSPECTOR_TIMING_DELTA=2.5 \
    INSPECTOR_CONCURRENCY=20 \
    INSPECTOR_WORKER_TIMEOUT=3600

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/worker-inspector/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-inspector/main.py ./main.py

CMD ["python3", "main.py"]
