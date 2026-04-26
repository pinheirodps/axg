FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=8090

COPY pyproject.toml README.md ./
COPY axg ./axg
COPY plugins ./plugins

RUN pip install --no-cache-dir .

EXPOSE 8090

CMD ["sh", "-c", "uvicorn axg.api:app --host 0.0.0.0 --port ${PORT}"]

