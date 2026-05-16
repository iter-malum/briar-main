FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# Switch apt to HTTPS, install curl + tar
RUN sed -i 's|URIs: http://|URIs: https://|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null; \
    sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list 2>/dev/null; \
    apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        tar \
    && rm -rf /var/lib/apt/lists/*

# Install gobuster binary — extract all, find the executable, move it
ENV GOBUSTER_VERSION=3.8.2
RUN curl -sL -o /tmp/gobuster.tar.gz \
      "https://github.com/OJ/gobuster/releases/download/v${GOBUSTER_VERSION}/gobuster_Linux_x86_64.tar.gz" \
    && mkdir -p /tmp/gobuster-extract \
    && tar -xzf /tmp/gobuster.tar.gz -C /tmp/gobuster-extract \
    && find /tmp/gobuster-extract -type f -executable | head -1 | xargs -I{} mv {} /usr/local/bin/gobuster \
    && chmod +x /usr/local/bin/gobuster \
    && rm -rf /tmp/gobuster.tar.gz /tmp/gobuster-extract \
    && gobuster version

# Download common.txt wordlist from SecLists
RUN mkdir -p /usr/share/seclists/Discovery/Web-Content && \
    curl -sL -o /usr/share/seclists/Discovery/Web-Content/common.txt \
      "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"

WORKDIR /app

COPY services/worker-gobuster/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-gobuster/main.py ./

RUN mkdir -p /tmp/gobuster && chmod 777 /tmp/gobuster

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import sys; sys.exit(0)" || exit 1

CMD ["python3", "main.py"]
