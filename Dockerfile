# Python 3.12.15, pinned by digest; update deliberately (docker buildx imagetools inspect python:3.12-slim)
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml README.md requirements.lock ./
# Every dependency and the build backend from the lock file, each checked against its sha256; then the app itself, without
# letting pip fetch anything else.
RUN pip install --require-hashes --no-deps -r requirements.lock
COPY src ./src
RUN pip install --no-deps --no-build-isolation .
RUN useradd --system --uid 10001 app && mkdir /data && chown app /data
USER app
ENV DATA_DIR=/data MCP_HOST=0.0.0.0 BRIDGE_HOST=0.0.0.0 MCP_PORT=8000
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1
CMD ["python", "-m", "icloud_mcp"]
