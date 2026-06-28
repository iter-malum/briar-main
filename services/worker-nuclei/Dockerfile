FROM projectdiscovery/nuclei:latest AS nuclei

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

# Copy the nuclei binary from the official image.
# Templates are no longer bundled in recent nuclei images — they are downloaded
# at first run via `nuclei -update-templates`.  We download them here during
# the build so the container starts immediately without an internet call.
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei

WORKDIR /app

COPY services/worker-nuclei/requirements.txt ./
RUN pip install --no-cache-dir --timeout 120 --retries 5 -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-nuclei/main.py ./

# Download/update nuclei templates at build time.
# HOME must be set so nuclei writes to a predictable path.
ENV HOME=/root
RUN nuclei -update-templates -silent || true

RUN mkdir -p /tmp/nuclei && chmod 777 /tmp/nuclei

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import sys; sys.exit(0)" || exit 1

CMD ["python", "main.py"]
