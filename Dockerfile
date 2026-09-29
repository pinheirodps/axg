# Pinned by digest for reproducible, tamper-evident builds; Dependabot bumps it
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8090

COPY pyproject.toml README.md ./
COPY axg ./axg
COPY plugins ./plugins

# [otel]: OTLP export, enabled only when OTEL_EXPORTER_OTLP_ENDPOINT is set.
# /var/lib/axg holds the audit log (AXG_AUDIT_FILE); a volume mounted there inherits the axg owner.
RUN pip install --no-cache-dir ".[otel]" \
    && useradd --system --uid 10001 --no-create-home axg \
    && chown -R axg /app \
    && mkdir -p /var/lib/axg && chown axg /var/lib/axg

USER axg

EXPOSE 8090

CMD ["sh", "-c", "uvicorn axg.api:app --host 0.0.0.0 --port ${PORT}"]

