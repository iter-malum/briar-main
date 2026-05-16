FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    DISPLAY=:1

# System dependencies: Playwright/Chromium + Xvfb + VNC stack
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates wget \
    # Chromium dependencies
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libgbm1 libasound2 libpango-1.0-0 libcairo2 \
    libdbus-1-3 libxshmfence1 libxcb1 libx11-6 libxext6 \
    # Virtual display + VNC
    xvfb x11vnc \
    # Fonts
    fonts-liberation fonts-unifont \
    # Utils
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install noVNC (web VNC client) + websockify
RUN pip install --no-cache-dir websockify==0.11.0 && \
    wget -qO /tmp/novnc.tar.gz \
      https://github.com/novnc/noVNC/archive/refs/tags/v1.4.0.tar.gz && \
    tar -xzf /tmp/novnc.tar.gz -C /opt && \
    mv /opt/noVNC-1.4.0 /opt/novnc && \
    rm /tmp/novnc.tar.gz

WORKDIR /app

COPY services/auth-service/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

RUN python -m playwright install chromium

COPY shared/ ./shared/
COPY services/auth-service/main.py ./
COPY services/auth-service/start.sh ./

RUN chmod +x start.sh

EXPOSE 8000 6080

CMD ["./start.sh"]
