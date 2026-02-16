FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# WeasyPrint runtime deps (PDF export)
# Fonts for PDF text rendering
RUN apt-get update && apt-get install -y \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz-subset0 \
    fonts-dejavu-core \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir .

RUN useradd --create-home --shell /bin/bash naminter && \
    chown -R naminter:naminter /app
USER naminter

ENTRYPOINT ["naminter"]
