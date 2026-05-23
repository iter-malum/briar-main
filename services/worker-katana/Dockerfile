# FILE: services/worker-katana/Dockerfile
#
# M8: Multi-stage build — compile katana from source (golang:latest) to avoid
# GitHub release download timeouts.  gau is also compiled from source.
# Chromium is installed from Debian repos for headless SPA crawling.

# ── Stage 1: compile Go tools ─────────────────────────────────────────────────
FROM golang:latest AS builder

# katana (ProjectDiscovery crawler with JS + XHR support)
RUN go install github.com/projectdiscovery/katana/cmd/katana@v1.1.0

# gau (passive URL discovery from Wayback Machine / CommonCrawl)
RUN go install github.com/lc/gau/v2/cmd/gau@v2.2.4

# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# Install Chromium for headless SPA crawling
RUN sed -i 's|URIs: http://|URIs: https://|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null; \
    sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list 2>/dev/null; \
    apt-get update && apt-get install -y --no-install-recommends \
        chromium \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV CHROME_BIN=/usr/bin/chromium

# Copy compiled binaries from builder
COPY --from=builder /go/bin/katana /usr/local/bin/katana
COPY --from=builder /go/bin/gau    /usr/local/bin/gau

WORKDIR /app

COPY services/worker-katana/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-katana/main.py ./

RUN mkdir -p /tmp/katana && chmod 777 /tmp/katana

ENV KATANA_HEADLESS=true \
    KATANA_DEPTH=3 \
    KATANA_HEADLESS_DEPTH=5 \
    KATANA_CONCURRENCY=10 \
    KATANA_TIMEOUT=600 \
    KATANA_JS_EXTRACT=true

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD python3 -c "import sys; sys.exit(0)" || exit 1

CMD ["python3", "main.py"]
