FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl \
    && git clone --depth 1 https://github.com/commixproject/commix /opt/commix \
    && (pip install --no-cache-dir -r /opt/commix/requirements.txt 2>/dev/null \
        || pip install --no-cache-dir requests) \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/worker-commix/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-commix/main.py ./

ENV COMMIX_BIN=/opt/commix/commix.py

RUN mkdir -p /tmp/commix && chmod 777 /tmp/commix

CMD ["python3", "main.py"]
