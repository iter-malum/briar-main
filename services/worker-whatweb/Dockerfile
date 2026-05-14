FROM ruby:3.2-slim

# WhatWeb is not on RubyGems — clone from GitHub
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        git curl \
    && git clone --depth 1 https://github.com/urbanadventurer/WhatWeb /opt/whatweb \
    && cd /opt/whatweb && gem install bundler && bundle install \
    && ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY services/worker-whatweb/requirements.txt ./requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY shared/ ./shared/
COPY services/worker-whatweb/main.py ./main.py

CMD ["python3", "main.py"]
