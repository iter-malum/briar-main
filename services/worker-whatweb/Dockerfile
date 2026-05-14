# ── Stage 1: build WhatWeb gems ───────────────────────────────────────────────
FROM ruby:3.2-slim AS ruby-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl build-essential ruby-dev \
    && git clone --depth 1 https://github.com/urbanadventurer/WhatWeb /opt/whatweb \
    && cd /opt/whatweb \
    && gem install bundler --no-document \
    && bundle config set --local without 'development test' \
    && bundle config set --local path '/opt/whatweb/vendor/bundle' \
    && bundle install --no-cache \
    && rm -rf /var/lib/apt/lists/* /tmp/*

# ── Stage 2: Python worker with WhatWeb pre-built ─────────────────────────────
FROM python:3.11-slim

# Ruby runtime (no compiler needed — gems already built in stage 1)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ruby curl \
    && rm -rf /var/lib/apt/lists/*

# Copy WhatWeb + pre-built gems from builder
COPY --from=ruby-builder /opt/whatweb /opt/whatweb
COPY --from=ruby-builder /usr/local/lib/ruby /usr/local/lib/ruby
COPY --from=ruby-builder /usr/local/bundle /usr/local/bundle

RUN ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb

WORKDIR /app

COPY services/worker-whatweb/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-whatweb/main.py ./main.py

CMD ["python3", "main.py"]
