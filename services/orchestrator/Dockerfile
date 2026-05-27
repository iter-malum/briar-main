FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app
WORKDIR /app
COPY shared/ ./shared/
COPY services/orchestrator/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY services/orchestrator/main.py ./
COPY services/orchestrator/finding_router.py ./
COPY services/orchestrator/result_processor.py ./
COPY services/orchestrator/report_generator.py ./
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]