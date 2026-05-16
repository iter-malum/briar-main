FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    DALFOX_VERSION=2.13.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && curl -sL -o /tmp/dalfox.tar.gz \
        "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-linux-amd64.tar.gz" \
    && tar -xzf /tmp/dalfox.tar.gz -C /usr/local/bin dalfox \
    && chmod +x /usr/local/bin/dalfox \
    && rm /tmp/dalfox.tar.gz \
    && rm -rf /var/lib/apt/lists/* \
    && dalfox version

WORKDIR /app

COPY services/worker-dalfox/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-dalfox/main.py ./main.py

RUN mkdir -p /tmp/dalfox && chmod 777 /tmp/dalfox

CMD ["python3", "main.py"]
