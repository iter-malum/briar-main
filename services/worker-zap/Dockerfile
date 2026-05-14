FROM ghcr.io/zaproxy/zaproxy:stable

USER root

RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 python3-pip python3-venv && \
    rm -rf /var/lib/apt/lists/*

# Создаем виртуальное окружение
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app

WORKDIR /app

COPY services/worker-zap/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-zap/main.py .

RUN mkdir -p /tmp/zap && \
    chown -R zap:zap /tmp/zap /opt/venv && \
    chmod 777 /tmp/zap

USER zap

CMD ["python", "main.py"]