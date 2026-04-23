# syntax=docker/dockerfile:1.7
# Minimal runtime image for the Secure SDLC Evidence Collector CLI.
# Multi-stage to keep the final image slim and free of build toolchain.

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN python -m pip install --upgrade pip && \
    python -m pip wheel --wheel-dir /wheels .


FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Create an unprivileged user with a predictable UID for volume mounts.
RUN groupadd --system --gid 10001 sdlc && \
    useradd --system --uid 10001 --gid sdlc --home /home/sdlc --create-home sdlc

WORKDIR /app

COPY --from=builder /wheels /wheels
RUN python -m pip install --no-index --find-links=/wheels \
        secure-sdlc-evidence-collector && \
    rm -rf /wheels

# Default mount point for pipeline inputs/outputs
USER sdlc
WORKDIR /workspace

ENTRYPOINT ["sdlc-evidence"]
CMD ["--help"]

LABEL org.opencontainers.image.title="secure-sdlc-evidence-collector" \
      org.opencontainers.image.description="Collect, normalize, evaluate and bundle Secure SDLC evidence per release." \
      org.opencontainers.image.authors="Lucas Henrique Grifoni <lucas.henriquegrifoni@gmail.com>" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/LucasGrifoni/secure-sdlc-evidence-collector"
