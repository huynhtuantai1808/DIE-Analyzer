FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG DIE_VERSION=4.1.0

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates wget python3 python3-pip python3-venv 7zip 7zip-rar unrar-free \
    && wget -q "https://github.com/horsicq/DIE-engine/releases/download/Beta/die_${DIE_VERSION}_noble_amd64.deb" \
         -O /tmp/die.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends /tmp/die.deb \
    && rm -f /tmp/die.deb \
    && rm -rf /var/lib/apt/lists/*

# The signature database is distributed in the Detect-It-Easy repository.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && git clone --depth 1 https://github.com/horsicq/Detect-It-Easy.git /tmp/die-repo \
    && mkdir -p /usr/lib/die/db \
    && if [ -d /tmp/die-repo/db ]; then cp -a /tmp/die-repo/db/. /usr/lib/die/db/; fi \
    && rm -rf /tmp/die-repo /var/lib/apt/lists/* \
    && diec --help >/dev/null

WORKDIR /app
COPY backend/requirements.txt .
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN useradd --system --uid 10001 --create-home appuser \
    && mkdir -p /data/uploads \
    && chown -R appuser:appuser /app /data /home/appuser

USER appuser
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-config", "/app/app/log_config.json", "--proxy-headers"]
