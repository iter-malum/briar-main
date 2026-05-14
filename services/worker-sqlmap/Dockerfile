FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl \
    && git clone --depth 1 https://github.com/sqlmapproject/sqlmap /opt/sqlmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/worker-sqlmap/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-sqlmap/main.py ./main.py

ENV SQLMAP_BIN=/opt/sqlmap/sqlmap.py

CMD ["python3", "main.py"]
