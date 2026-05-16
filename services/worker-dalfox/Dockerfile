FROM python:3.11-slim

# Install system dependencies and dalfox Go binary
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && DALFOX_VERSION=2.9.2 \
    && curl -sL -o /tmp/dalfox.tar.gz \
        "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox_linux_amd64.tar.gz" \
    && tar -xzf /tmp/dalfox.tar.gz -C /usr/local/bin dalfox \
    && chmod +x /usr/local/bin/dalfox \
    && rm /tmp/dalfox.tar.gz \
    && dalfox version \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/worker-dalfox/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-dalfox/main.py ./main.py

RUN mkdir -p /tmp/dalfox && chmod 777 /tmp/dalfox

CMD ["python3", "main.py"]
