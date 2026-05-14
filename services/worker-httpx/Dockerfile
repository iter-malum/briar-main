# FILE: services/worker-httpx/Dockerfile (FIXED - NO NAME CONFLICT)
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    HTTPX_VERSION=1.3.3

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

# ✅ Скачиваем и ПЕРЕИМЕНОВЫВАЕМ бинарник
RUN curl -sL -o /tmp/httpx.zip \
    "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" && \
    unzip -q /tmp/httpx.zip -d /tmp/httpx-bin/ && \
    mv /tmp/httpx-bin/httpx /usr/local/bin/httpx-pd && \
    chmod +x /usr/local/bin/httpx-pd && \
    rm -rf /tmp/httpx.zip /tmp/httpx-bin/ && \
    /usr/local/bin/httpx-pd -version

WORKDIR /app

COPY services/worker-httpx/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-httpx/main.py ./

RUN mkdir -p /tmp/httpx && chmod 777 /tmp/httpx

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD python3 -c "import sys; sys.exit(0)" || exit 1

CMD ["python3", "main.py"]