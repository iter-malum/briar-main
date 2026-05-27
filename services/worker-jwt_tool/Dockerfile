FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl \
    && git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool \
    && pip install --no-cache-dir -r /opt/jwt_tool/requirements.txt \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/worker-jwt_tool/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-jwt_tool/main.py ./

ENV JWT_TOOL_BIN=/opt/jwt_tool/jwt_tool.py \
    JWT_TOOL_WORDLIST=/opt/jwt_tool/jwt-common.txt

RUN mkdir -p /tmp/jwt_tool && chmod 777 /tmp/jwt_tool

CMD ["python3", "main.py"]
