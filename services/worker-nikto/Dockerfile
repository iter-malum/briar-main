FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

# Install Nikto and CA certificates from Debian repositories
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nikto \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY services/worker-nikto/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared library and worker entry point
COPY shared/ ./shared/
COPY services/worker-nikto/main.py ./

# Prepare writable output directory for Nikto JSON reports
RUN mkdir -p /tmp/nikto && chmod 777 /tmp/nikto

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import sys; sys.exit(0)" || exit 1

CMD ["python3", "main.py"]
