FROM python:3.12-slim AS builder
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /app/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl
RUN addgroup --system --gid 1001 reporeaver && adduser --system --uid 1001 reporeaver
USER reporeaver
HEALTHCHECK CMD reporeaver --help || exit 1
LABEL org.opencontainers.image.title="Reporeaver" \
      org.opencontainers.image.description="Open-source security gate for repositories" \
      org.opencontainers.image.licenses="MIT"
ENTRYPOINT ["reporeaver"]
CMD ["--help"]
