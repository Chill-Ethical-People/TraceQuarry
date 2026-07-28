# syntax=docker/dockerfile:1

ARG PYTHON_IMAGE=python:3.12-alpine3.22@sha256:a190708a2dec1bd18b1decb539f8e8f5407abaa9bf39cacda583f7f8c11db322

FROM ${PYTHON_IMAGE} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /build

COPY pyproject.toml README.md LICENSE NOTICE OWNERSHIP.md requirements.txt ./
COPY uac_parser ./uac_parser
COPY rules ./rules
COPY assets ./assets
COPY web ./web

RUN python -m pip wheel --wheel-dir /wheels --requirement requirements.txt \
    && python -m pip wheel --wheel-dir /wheels --no-deps .

FROM ${PYTHON_IMAGE} AS runtime

ARG TRACEQUARRY_UID=10001
ARG TRACEQUARRY_GID=10001

LABEL org.opencontainers.image.title="TraceQuarry" \
      org.opencontainers.image.description="Local-first Linux DFIR timeline workbench" \
      org.opencontainers.image.source="https://github.com/Chill-Ethical-People/TraceQuarry" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV HOME=/home/tracequarry \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TRACEQUARRY_CONTAINER=1

RUN apk upgrade --no-cache \
    && addgroup --system --gid "${TRACEQUARRY_GID}" tracequarry \
    && adduser --system --disabled-password --uid "${TRACEQUARRY_UID}" \
        --ingroup tracequarry --home /home/tracequarry --shell /sbin/nologin tracequarry \
    && mkdir -p /data/web_runs /evidence /licenses \
    && chown -R tracequarry:tracequarry /data /home/tracequarry

COPY --from=builder /wheels /wheels
COPY LICENSE NOTICE OWNERSHIP.md /licenses/
RUN python -m pip install --no-index --find-links=/wheels tracequarry \
    && rm -rf /wheels

USER tracequarry:tracequarry
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import json, urllib.request; response = urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=3); assert response.status == 200 and json.load(response)['status'] == 'ok'"]

ENTRYPOINT ["tracequarry-web"]
CMD ["--host", "0.0.0.0", "--container-bind", "--port", "8765", "--work-dir", "/data/web_runs", "--input-root", "/evidence"]
