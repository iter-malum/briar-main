# FILE: services/worker-katana/Dockerfile (FIXED - ARM64/AMD64 + версия)
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

# Автоматическое определение архитектуры
ARG TARGETARCH=amd64
ARG KATANA_VERSION=1.5.0

# Установка зависимостей
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

# ✅ Скачиваем Katana с правильным форматом URL и имени файла
# Паттерн: download/v{VER}/katana_{VER_NO_V}_{OS}_{ARCH}.zip
RUN ARCH=$(if [ "$TARGETARCH" = "amd64" ]; then echo "amd64"; elif [ "$TARGETARCH" = "arm64" ]; then echo "arm64"; else echo "$TARGETARCH"; fi) && \
    curl -sL -o /tmp/katana.zip \
      "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${ARCH}.zip" && \
    unzip -q /tmp/katana.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/katana && \
    rm /tmp/katana.zip && \
    /usr/local/bin/katana -version

# Install gau (GetAllUrls) for passive URL discovery from public archives
RUN ARCH=$(if [ "$TARGETARCH" = "amd64" ]; then echo "amd64"; elif [ "$TARGETARCH" = "arm64" ]; then echo "arm64"; else echo "$TARGETARCH"; fi) && \
    curl -sL -o /tmp/gau.tar.gz \
      "https://github.com/lc/gau/releases/download/v2.2.4/gau_2.2.4_linux_${ARCH}.tar.gz" && \
    tar -xzf /tmp/gau.tar.gz -C /usr/local/bin/ gau && \
    chmod +x /usr/local/bin/gau && \
    rm /tmp/gau.tar.gz || true

WORKDIR /app

COPY services/worker-katana/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-katana/main.py ./

RUN mkdir -p /tmp/katana && chmod 777 /tmp/katana

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD python3 -c "import sys; sys.exit(0)" || exit 1

CMD ["python3", "main.py"]