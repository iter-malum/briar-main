FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

# System deps needed by Playwright's bundled Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/worker-playwright/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
 && playwright install chromium --with-deps

COPY shared/ ./shared/
COPY services/worker-playwright/main.py ./

RUN mkdir -p /tmp/playwright && chmod 777 /tmp/playwright

CMD ["python3", "main.py"]
