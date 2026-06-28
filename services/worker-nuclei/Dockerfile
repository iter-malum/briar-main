FROM projectdiscovery/nuclei:latest AS nuclei

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

# Copy nuclei binary AND bundled templates from the official image.
# Without copying templates, nuclei runs with 0 templates → 0 results.
# The official nuclei image stores templates at /root/nuclei-templates.
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=nuclei /root/nuclei-templates /root/nuclei-templates

WORKDIR /app

COPY services/worker-nuclei/requirements.txt ./
RUN pip install --no-cache-dir --timeout 120 --retries 5 -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-nuclei/main.py ./

RUN mkdir -p /tmp/nuclei && chmod 777 /tmp/nuclei

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import sys; sys.exit(0)" || exit 1

CMD ["python", "main.py"]
