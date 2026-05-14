# FILE: services/auth-service/Dockerfile (BULLETPROOF VERSION)
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true

# ✅ Установка системных зависимостей для Playwright/Chromium на Debian
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Базовые утилиты
    curl ca-certificates gnupg wget \
    # Зависимости для Chromium/Playwright
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 \
    libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libgbm1 libasound2 libpango-1.0-0 libcairo2 \
    libdbus-1-3 libxshmfence1 libxcb1 libx11-6 libxext6 \
    # Шрифты (критично для рендеринга)
    fonts-liberation fonts-ipafont-gothic fonts-unifont \
    # Для работы subprocess
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

# ✅ Копируем и устанавливаем Python-зависимости (включая playwright)
COPY services/auth-service/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# ✅ Установка браузеров через python -m (гарантирует правильный интерпретатор)
# Устанавливаем ТОЛЬКО chromium для экономии места (~200МБ вместо ~1ГБ)
RUN python -m playwright install chromium

# ✅ Копируем код
COPY shared/ ./shared/
COPY services/auth-service/main.py ./

EXPOSE 8000

# ✅ Запуск с увеличенным лимитом памяти для Playwright
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]