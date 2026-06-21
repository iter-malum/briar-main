FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

# Install Node.js LTS + retire.js CLI
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm install -g retire \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/worker-retirejs/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-retirejs/main.py ./

RUN mkdir -p /tmp/retirejs && chmod 777 /tmp/retirejs

CMD ["python3", "main.py"]
