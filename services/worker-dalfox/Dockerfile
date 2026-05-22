FROM hahwul/dalfox:2.13.0 AS dalfox-bin

FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

COPY --from=dalfox-bin /usr/local/bin/dalfox /usr/local/bin/dalfox

WORKDIR /app

COPY services/worker-dalfox/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-dalfox/main.py ./main.py

RUN mkdir -p /tmp/dalfox && chmod 777 /tmp/dalfox

CMD ["python3", "main.py"]
