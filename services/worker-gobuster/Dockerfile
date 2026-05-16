FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# ── System dependencies ────────────────────────────────────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        unzip \
        tar \
    && rm -rf /var/lib/apt/lists/*

# ── Install gobuster binary ────────────────────────────────────────────────────
ENV GOBUSTER_VERSION=3.8.2
RUN curl -sL -o /tmp/gobuster.tar.gz \
      "https://github.com/OJ/gobuster/releases/download/v${GOBUSTER_VERSION}/gobuster_Linux_x86_64.tar.gz" && \
    tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin gobuster && \
    chmod +x /usr/local/bin/gobuster && \
    rm -f /tmp/gobuster.tar.gz

# ── Install wordlist (common.txt from SecLists) ────────────────────────────────
# We download only the single wordlist we need to keep the image lean.
RUN mkdir -p /usr/share/seclists/Discovery/Web-Content && \
    curl -sL -o /usr/share/seclists/Discovery/Web-Content/common.txt \
      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"

# ── Application ────────────────────────────────────────────────────────────────
WORKDIR /app

COPY services/worker-gobuster/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-gobuster/main.py ./

# Output directory used by gobuster --output
RUN mkdir -p /tmp/gobuster && chmod 777 /tmp/gobuster

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import sys; sys.exit(0)" || exit 1

CMD ["python3", "main.py"]
