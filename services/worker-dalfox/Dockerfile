FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    DALFOX_VERSION=2.13.0

# Switch apt to HTTPS (port 80 may be blocked in some environments)
RUN sed -i 's|URIs: http://|URIs: https://|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null; \
    sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list 2>/dev/null; \
    apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && curl -sL -o /tmp/dalfox.tar.gz \
        "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-linux-amd64.tar.gz" \
    && mkdir -p /tmp/dalfox-extract \
    && tar -xzf /tmp/dalfox.tar.gz -C /tmp/dalfox-extract \
    && find /tmp/dalfox-extract -type f -executable | head -1 | xargs -I{} mv {} /usr/local/bin/dalfox \
    && chmod +x /usr/local/bin/dalfox \
    && rm -rf /tmp/dalfox.tar.gz /tmp/dalfox-extract \
    && rm -rf /var/lib/apt/lists/* \
    && dalfox version

WORKDIR /app

COPY services/worker-dalfox/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-dalfox/main.py ./main.py

RUN mkdir -p /tmp/dalfox && chmod 777 /tmp/dalfox

CMD ["python3", "main.py"]
