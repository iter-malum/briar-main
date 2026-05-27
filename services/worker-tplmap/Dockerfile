FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl \
    && git clone --depth 1 https://github.com/epinna/tplmap /opt/tplmap \
    && pip install --no-cache-dir -r /opt/tplmap/requirements.txt \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/worker-tplmap/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-tplmap/main.py ./

ENV TPLMAP_BIN=/opt/tplmap/tplmap.py

RUN mkdir -p /tmp/tplmap && chmod 777 /tmp/tplmap

CMD ["python3", "main.py"]
