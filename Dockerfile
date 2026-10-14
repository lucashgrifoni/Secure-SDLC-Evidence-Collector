# syntax=docker/dockerfile:1.7
# Minimal runtime image for the Secure SDLC Evidence Collector CLI.
# Multi-stage to keep the final image slim and free of build toolchain.

ARG PYTHON_VERSION=3.12

# Base image pinned by multi-arch manifest digest (OpenSSF Scorecard
# Pinned-Dependencies). Dependabot (docker ecosystem) refreshes the digest.
FROM python:${PYTHON_VERSION}-slim-bookworm@sha256:93ab4b7fa528b25124c97bcc755415e60eb671a86b4dbe0328df2fe2d1c1193d AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

COPY pyproject.toml README.md LICENSE THIRD_PARTY_LICENSES.md ./
COPY src/ ./src/
COPY .github/requirements/pip.txt .github/requirements/runtime.txt /requirements/

# Third-party wheels come only from the hash-locked runtime.txt (the lock the
# CI runtime jobs install); the project wheel is built with --no-deps.
RUN python -m pip install --require-hashes -r /requirements/pip.txt && \
    python -m pip wheel --wheel-dir /wheels --require-hashes -r /requirements/runtime.txt && \
    python -m pip wheel --wheel-dir /wheels --no-deps .


FROM python:${PYTHON_VERSION}-slim-bookworm@sha256:93ab4b7fa528b25124c97bcc755415e60eb671a86b4dbe0328df2fe2d1c1193d AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Create an unprivileged user with a predictable UID for volume mounts.
RUN groupadd --system --gid 10001 sdlc && \
    useradd --system --uid 10001 --gid sdlc --home /home/sdlc --create-home sdlc

WORKDIR /app

COPY --from=builder /wheels /wheels
COPY --from=builder /requirements /requirements
# Offline install from the builder's wheels: the dependencies are checked
# against the lock's hashes again, then the project wheel goes on top.
RUN python -m pip install --no-index --find-links=/wheels \
        --require-hashes -r /requirements/runtime.txt && \
    python -m pip install --no-index --no-deps /wheels/secure_sdlc_evidence_collector-*.whl && \
    python -m pip check && \
    rm -rf /wheels /requirements

# Default mount point for pipeline inputs/outputs
USER sdlc
WORKDIR /workspace

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD sdlc-evidence --version >/dev/null || exit 1

ENTRYPOINT ["sdlc-evidence"]
CMD ["--help"]

LABEL org.opencontainers.image.title="secure-sdlc-evidence-collector" \
      org.opencontainers.image.description="Collect, normalize, evaluate and bundle Secure SDLC evidence per release." \
      org.opencontainers.image.authors="Lucas Henrique Grifoni <lucas.henriquegrifoni@gmail.com>" \
      org.opencontainers.image.licenses="Apache-2.0 AND BSD-2-Clause" \
      org.opencontainers.image.source="https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector"
