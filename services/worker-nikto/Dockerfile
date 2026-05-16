FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

# Switch apt to HTTPS, then install Perl + nikto from GitHub
RUN sed -i 's|URIs: http://|URIs: https://|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null; \
    sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list 2>/dev/null; \
    apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        perl \
        libnet-ssleay-perl \
        libio-socket-ssl-perl \
        libwww-perl \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && nikto -Version

WORKDIR /app

COPY services/worker-nikto/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-nikto/main.py ./

RUN mkdir -p /tmp/nikto && chmod 777 /tmp/nikto

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import sys; sys.exit(0)" || exit 1

CMD ["python3", "main.py"]
