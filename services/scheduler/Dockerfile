FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app
WORKDIR /app
COPY shared/ ./shared/
COPY services/scheduler/requirements.txt ./
RUN pip install --no-cache-dir --timeout 120 --retries 5 -r requirements.txt
COPY services/scheduler/main.py ./
EXPOSE 8005
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8005", "--log-level", "info"]
