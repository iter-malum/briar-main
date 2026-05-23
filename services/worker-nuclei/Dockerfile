FROM projectdiscovery/nuclei:latest AS nuclei

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

# Copy nuclei binary
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei

WORKDIR /app

COPY services/worker-nuclei/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# M9: Pull the full community template library and update at build time.
# nuclei-templates are stored in /root/nuclei-templates by default.
# The "-update-templates" flag downloads everything including community/contrib.
RUN nuclei -update-templates -update-template-dir /root/nuclei-templates || true

# Also pull headless extension templates if available
RUN nuclei -update-templates -ut || true

COPY shared/ ./shared/
COPY services/worker-nuclei/main.py ./

RUN mkdir -p /tmp/nuclei && chmod 777 /tmp/nuclei

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import sys; sys.exit(0)" || exit 1

CMD ["python", "main.py"]
