# WhatWeb Technology Detection Worker
#
# WhatWeb is available in the Debian Bookworm apt repository (v0.5.5) —
# the same version as the current GitHub HEAD.  Installing from apt is
# far more reliable than cloning GitHub during docker build (network may
# be restricted / TLS-blocked in some environments).

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

RUN sed -i 's|URIs: http://|URIs: https://|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null; \
    sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list 2>/dev/null; \
    apt-get update && apt-get install -y --no-install-recommends \
        whatweb \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/worker-whatweb/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-whatweb/main.py ./main.py

RUN mkdir -p /tmp/whatweb && chmod 777 /tmp/whatweb

CMD ["python3", "main.py"]
