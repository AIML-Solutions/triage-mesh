# Shared image for all seven services; the command is set per-service in compose.
FROM python:3.13-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY README.md ./
RUN uv sync --frozen --no-dev

FROM python:3.13-slim
RUN useradd --create-home app \
    && mkdir -p /data/staging /data/published \
    && chown -R app:app /data
USER app
WORKDIR /app
COPY --from=builder --chown=app:app /app /app
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1
