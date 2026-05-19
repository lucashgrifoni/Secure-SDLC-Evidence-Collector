#!/usr/bin/env bash
# Verify a published release end-to-end.
#
# Runs after `publish-pypi.yml` succeeds and the GitHub Release / PyPI /
# GHCR assets are all populated. Each step is independently
# verifiable; the script exits 0 only when every check passes.
#
# Usage:
#     bash scripts/verify-release.sh v1.1.0
#
# Requires on PATH:
#   - cosign         (https://github.com/sigstore/cosign)
#   - slsa-verifier  (https://github.com/slsa-framework/slsa-verifier)
#   - python (>= 3.12) for the fresh-venv smoke
#   - gh (optional, used to dump the run log on failure)
set -euo pipefail

TAG="${1:-}"
if [ -z "$TAG" ]; then
  echo "Usage: bash scripts/verify-release.sh <tag>" >&2
  exit 64
fi

OWNER="lucashgrifoni"
REPO="Secure-SDLC-Evidence-Collector"
PYPI_NAME="secure-sdlc-evidence-collector"
PKG_VERSION="${TAG#v}"
WHEEL="${PYPI_NAME//-/_}-${PKG_VERSION}-py3-none-any.whl"
SDIST="${PYPI_NAME//-/_}-${PKG_VERSION}.tar.gz"
BASE="https://github.com/${OWNER}/${REPO}/releases/download/${TAG}"
GHCR_IMAGE="ghcr.io/${OWNER,,}/${PYPI_NAME}:${TAG}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
cd "$WORKDIR"

step() { printf '\n=== %s ===\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

step "Download release assets"
curl -fsSL "$BASE/$WHEEL" -o "$WHEEL"
curl -fsSL "$BASE/$WHEEL.sig" -o "$WHEEL.sig"
curl -fsSL "$BASE/$WHEEL.pem" -o "$WHEEL.pem"
curl -fsSL "$BASE/$SDIST" -o "$SDIST"
curl -fsSL "$BASE/$SDIST.sig" -o "$SDIST.sig"
curl -fsSL "$BASE/$SDIST.pem" -o "$SDIST.pem"
curl -fsSL "$BASE/bundle.json" -o bundle.json
curl -fsSL "$BASE/bundle.json.sig" -o bundle.json.sig
curl -fsSL "$BASE/bundle.json.pem" -o bundle.json.pem
curl -fsSL "$BASE/checksums.txt" -o checksums.txt
ls -la

step "SHA-256 checksums match the published checksums.txt"
sha256sum --check checksums.txt || fail "checksum mismatch"

step "cosign verify-blob (wheel + sdist + bundle)"
COSIGN_IDENTITY_REGEX="https://github.com/${OWNER}/${REPO}"
COSIGN_OIDC_ISSUER="https://token.actions.githubusercontent.com"
for blob in "$WHEEL" "$SDIST" bundle.json; do
  cosign verify-blob \
    --certificate "$blob.pem" \
    --signature "$blob.sig" \
    --certificate-identity-regexp "$COSIGN_IDENTITY_REGEX" \
    --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
    "$blob" \
    || fail "cosign verify-blob failed for $blob"
done

step "SLSA verifier (provenance against wheel + sdist)"
# The SLSA generator produces one .intoto.jsonl with all subjects.
PROVENANCE="$(ls *.intoto.jsonl 2>/dev/null | head -n1 || true)"
if [ -z "$PROVENANCE" ]; then
  curl -fsSL "$BASE/multiple.intoto.jsonl" -o multiple.intoto.jsonl 2>/dev/null \
    || curl -fsSL "$BASE/${PYPI_NAME}-${PKG_VERSION}.intoto.jsonl" -o multiple.intoto.jsonl
  PROVENANCE=multiple.intoto.jsonl
fi
for artifact in "$WHEEL" "$SDIST"; do
  slsa-verifier verify-artifact "$artifact" \
    --provenance-path "$PROVENANCE" \
    --source-uri "github.com/${OWNER}/${REPO}" \
    --source-tag "$TAG" \
    || fail "slsa-verifier failed for $artifact"
done

step "cosign verify on GHCR image"
cosign verify "$GHCR_IMAGE" \
  --certificate-identity-regexp "$COSIGN_IDENTITY_REGEX" \
  --certificate-oidc-issuer "$COSIGN_OIDC_ISSUER" \
  > /dev/null \
  || fail "cosign verify failed for $GHCR_IMAGE"

step "cosign download attestation on GHCR image (SBOM)"
cosign download attestation "$GHCR_IMAGE" > attestations.jsonl \
  || fail "cosign download attestation failed for $GHCR_IMAGE"
test -s attestations.jsonl || fail "empty attestation payload"

step "Fresh venv install from PyPI"
python -m venv venv
# shellcheck disable=SC1091
. venv/bin/activate
python -m pip install --quiet --upgrade pip
python -m pip install --quiet "${PYPI_NAME}==${PKG_VERSION}"
INSTALLED_VERSION="$(python -m evidence_collector.cli.main --version)"
test "$INSTALLED_VERSION" = "$PKG_VERSION" \
  || fail "expected version $PKG_VERSION, got $INSTALLED_VERSION"
deactivate

printf '\nAll checks passed for %s.\n' "$TAG"
