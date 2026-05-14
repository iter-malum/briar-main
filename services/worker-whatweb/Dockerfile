FROM ruby:3.2-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        git curl build-essential \
    && gem install whatweb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/worker-whatweb/requirements.txt ./requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-whatweb/main.py ./main.py

CMD ["python3", "main.py"]
