FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# WeasyPrint runtime deps (PDF export)
# Fonts for PDF rendering
# ca-certificates for HTTPS requests
RUN apt-get update && apt-get install -y \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz-subset0 \
    fonts-liberation \
    fonts-dejavu-core \
    fonts-dejavu-extra \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir .

RUN useradd --create-home --shell /bin/bash naminter && \
    chown -R naminter:naminter /app
USER naminter

ENTRYPOINT ["naminter"]
