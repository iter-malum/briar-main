FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    DISPLAY=:1

# Switch apt to HTTPS, then install system deps.
# Use only top-level packages — apt resolves renamed t64 deps (libcups2t64, etc.) automatically.
RUN sed -i 's|URIs: http://|URIs: https://|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null; \
    sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list 2>/dev/null; \
    apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        wget \
        # Virtual display + VNC
        xvfb \
        x11vnc \
        # Fonts for browser rendering
        fonts-liberation \
        # Process management
        procps \
    && rm -rf /var/lib/apt/lists/*

# noVNC web client + websockify
RUN pip install --no-cache-dir websockify==0.11.0 && \
    wget -qO /tmp/novnc.tar.gz \
      https://github.com/novnc/noVNC/archive/refs/tags/v1.4.0.tar.gz && \
    tar -xzf /tmp/novnc.tar.gz -C /opt && \
    mv /opt/noVNC-1.4.0 /opt/novnc && \
    rm /tmp/novnc.tar.gz

WORKDIR /app

COPY services/auth-service/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Playwright installs its own Chromium with all bundled dependencies
RUN python -m playwright install chromium --with-deps

COPY shared/ ./shared/
COPY services/auth-service/main.py ./
COPY services/auth-service/start.sh ./

RUN chmod +x start.sh

EXPOSE 8000 6080

CMD ["./start.sh"]
