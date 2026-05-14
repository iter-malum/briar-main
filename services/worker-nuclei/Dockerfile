FROM projectdiscovery/nuclei:latest AS nuclei

FROM python:3.11-slim

# Копируем бинарник nuclei
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

WORKDIR /app

# Установка зависимостей
COPY services/worker-nuclei/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Обновление шаблонов nuclei при запуске
RUN nuclei -update-templates || true

# Копируем код
COPY shared/ ./shared/
COPY services/worker-nuclei/main.py ./

# Создаем директорию для временных файлов
RUN mkdir -p /tmp/nuclei && chmod 777 /tmp/nuclei

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import sys; sys.exit(0)" || exit 1

CMD ["python", "main.py"]