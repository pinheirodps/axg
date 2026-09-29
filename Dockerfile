# Pinned by digest for reproducible, tamper-evident builds; Dependabot bumps it
FROM python:3.14-slim@sha256:51dafde81dbdb6ebde285137a295cf18a47ca95234fe388a343719cb97305b3d

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8090

COPY pyproject.toml README.md ./
COPY axg ./axg
COPY plugins ./plugins

RUN pip install --no-cache-dir . \
    && useradd --system --uid 10001 --no-create-home axg \
    && chown -R axg /app

USER axg

EXPOSE 8090

CMD ["sh", "-c", "uvicorn axg.api:app --host 0.0.0.0 --port ${PORT}"]

