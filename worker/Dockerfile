FROM python:3.12.8-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY worker/requirements.txt ./worker-requirements.txt
RUN pip install --no-cache-dir --timeout 180 --retries 5 -r worker-requirements.txt
COPY backend/app ./app
COPY worker ./worker
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
