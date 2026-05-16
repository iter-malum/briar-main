FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

# Nikto is a Perl script — install Perl + SSL libs, then clone from GitHub.
# The official nikto package was removed from Debian trixie.
RUN apt-get update \
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
