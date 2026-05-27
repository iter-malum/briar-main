# FILE: services/worker-ffuf/Dockerfile (MINIMAL FIX)
FROM secsi/ffuf:latest

# ✅ ЭТА СТРОКА переопределяет ENTRYPOINT базового образа ["ffuf"]
# Теперь контейнер будет запускать то, что указано в CMD, а не ffuf
ENTRYPOINT []

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

# ── Tuning (override via docker-compose environment:) ─────────────────────────
ENV FFUF_RATE=300 \
    FFUF_THREADS=40 \
    FFUF_STRATEGY_TIMEOUT=600 \
    FFUF_WORDLIST_ROOT=/usr/share/seclists/Discovery/Web-Content/common.txt \
    FFUF_WORDLIST_API=/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt

WORKDIR /app

# Python + wget (Alpine base from secsi/ffuf)
RUN apk add --no-cache python3 py3-pip wget

COPY services/worker-ffuf/requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

# Download wordlists used by ROOT and API PREFIX strategies
# Avoids pulling ~500 MB of full SecLists
RUN mkdir -p /usr/share/seclists/Discovery/Web-Content/api && \
    wget -q -O /usr/share/seclists/Discovery/Web-Content/common.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt && \
    wget -q -O /usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt \
      https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints-res.txt && \
    # Verify downloads succeeded
    test -s /usr/share/seclists/Discovery/Web-Content/common.txt && \
    test -s /usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt && \
    echo "Wordlists OK: $(wc -l < /usr/share/seclists/Discovery/Web-Content/common.txt) root entries, \
$(wc -l < /usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt) API entries"

COPY shared/ ./shared/
COPY services/worker-ffuf/main.py ./

RUN mkdir -p /tmp/ffuf && chmod 777 /tmp/ffuf

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import sys; sys.exit(0)" || exit 1

# ✅ CMD теперь будет выполнен напрямую, а не как аргумент для ffuf
CMD ["python3", "main.py"]