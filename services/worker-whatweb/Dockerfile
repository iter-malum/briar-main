FROM ruby:3.2-slim

# build-essential required for native gem extensions (json, racc, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        git curl \
        build-essential ruby-dev \
    && git clone --depth 1 https://github.com/urbanadventurer/WhatWeb /opt/whatweb \
    && cd /opt/whatweb \
    && gem install bundler --no-document \
    && bundle config set --local without 'development test' \
    && bundle install --no-cache \
    && ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb \
    # Strip build tools to reduce image size
    && apt-get purge -y --auto-remove build-essential ruby-dev \
    && rm -rf /var/lib/apt/lists/* /tmp/* /root/.bundle/cache

WORKDIR /app

COPY services/worker-whatweb/requirements.txt ./requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-whatweb/main.py ./main.py

CMD ["python3", "main.py"]
