FROM eclipse-temurin:21.0.13_9-jdk-jammy@sha256:432e54724c3e57d1846aeb886f4d339f3b0522931c4e64119c2797013b7cfc3c AS java

FROM python:3.12.8-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PYTHONPATH=/app
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="/opt/java/openjdk/bin:${PATH}"
ENV GHIDRA_HOME=/opt/ghidra_12.1.3_PUBLIC
ENV GHIDRA_VERSION=12.1.3
ENV JAVA_VERSION=21.0.13+9
WORKDIR /app
COPY --from=java /opt/java/openjdk /opt/java/openjdk
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip libasound2 libfontconfig1 libfreetype6 libx11-6 libxext6 libxi6 libxrender1 libxtst6 \
    && curl -fsSL "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.3_build/ghidra_12.1.3_PUBLIC_20260817.zip" -o /tmp/ghidra.zip \
    && echo "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && chmod -R a+rX /opt/ghidra_12.1.3_PUBLIC \
    && rm -f /tmp/ghidra.zip \
    && apt-get purge -y --auto-remove curl unzip \
    && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY worker/requirements.txt ./worker-requirements.txt
RUN pip install --no-cache-dir --timeout 180 --retries 5 -r worker-requirements.txt
COPY backend/app ./app
COPY worker ./worker
COPY ghidra_scripts ./ghidra_scripts
COPY tests/worker ./tests/worker
COPY tests/unit ./tests/unit
COPY shared ./shared
COPY fixtures ./fixtures
COPY rules/import_categories.json ./rules/import_categories.json
COPY rules/rules_v1.0 ./rules/rules_v1.0
COPY rules/detectors ./rules/detectors
COPY rules/scoring_weights_v1.0.json ./rules/scoring_weights_v1.0.json
RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home app \
    && mkdir -p /data/uploads /data/artifacts \
    && chown -R app:app /data
USER 10001:10001
CMD ["celery", "-A", "app.celery_app:celery_app", "worker", "--pool=prefork", "--concurrency=1", "--queues=analyses", "--loglevel=INFO"]
