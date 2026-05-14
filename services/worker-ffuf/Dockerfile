# FILE: services/worker-ffuf/Dockerfile (MINIMAL FIX)
FROM secsi/ffuf:latest

# ✅ ЭТА СТРОКА переопределяет ENTRYPOINT базового образа ["ffuf"]
# Теперь контейнер будет запускать то, что указано в CMD, а не ffuf
ENTRYPOINT []

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app
WORKDIR /app

# Установите Python и pip (в Alpine Linux используется apk)
RUN apk add --no-cache python3 py3-pip wget unzip

COPY services/worker-ffuf/requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

RUN mkdir -p /usr/share/seclists && \
    wget -q -O /tmp/seclists.zip https://github.com/danielmiessler/SecLists/archive/master.zip && \
    unzip -q /tmp/seclists.zip -d /usr/share/ && \
    mv /usr/share/SecLists-master /usr/share/seclists && \
    rm -f /tmp/seclists.zip

COPY shared/ ./shared/
COPY services/worker-ffuf/main.py ./

RUN mkdir -p /tmp/ffuf && chmod 777 /tmp/ffuf

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import sys; sys.exit(0)" || exit 1

# ✅ CMD теперь будет выполнен напрямую, а не как аргумент для ffuf
CMD ["python3", "main.py"]