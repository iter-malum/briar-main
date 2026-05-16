FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    DISPLAY=:1

# Base image is Ubuntu Jammy — apt works on standard HTTP mirrors.
# Add only what Playwright image doesn't already have: Xvfb + VNC stack.
RUN DEBIAN_FRONTEND=noninteractive TZ=UTC apt-get update && \
    DEBIAN_FRONTEND=noninteractive TZ=UTC apt-get install -y --no-install-recommends \
        xvfb \
        x11vnc \
        fonts-liberation \
        procps \
    && rm -rf /var/lib/apt/lists/*

# noVNC web client + websockify (Python-based, no apt needed)
RUN pip install --no-cache-dir websockify==0.11.0 && \
    curl -sL -o /tmp/novnc.tar.gz \
      https://github.com/novnc/noVNC/archive/refs/tags/v1.4.0.tar.gz && \
    tar -xzf /tmp/novnc.tar.gz -C /opt && \
    mv /opt/noVNC-1.4.0 /opt/novnc && \
    rm /tmp/novnc.tar.gz

WORKDIR /app

COPY services/auth-service/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Chromium is already installed in the base image — just verify it
RUN python -m playwright install chromium

COPY shared/ ./shared/
COPY services/auth-service/main.py ./
COPY services/auth-service/start.sh ./

RUN chmod +x start.sh

EXPOSE 8000 6080

CMD ["./start.sh"]
