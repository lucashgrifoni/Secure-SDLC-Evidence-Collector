#!/usr/bin/env bash
# Post-create setup for the Secure SDLC Evidence Collector devcontainer.
#
# Installs the project in editable mode plus the canonical OSS supply
# chain CLIs the project's examples and validation flows reach for:
#
# * cosign — Sigstore keyless signing / verification
# * syft   — SBOM generation (CycloneDX / SPDX)
# * trivy  — SCA / IaC / secrets / image scanning
# * conftest — Rego policy testing (used by policies/rego/)
#
# Pinned versions are upgraded with the same review as any other
# dependency: PRs that bump them must explain why.
set -euo pipefail

echo "[postCreate] Installing the project (editable + dev extras)…"
# Same hash-locked files as the CI quality jobs: dev.txt carries the dev, api
# and logs extras; the project goes on top with --no-deps.
python -m pip install --require-hashes -r .github/requirements/pip.txt
python -m pip install --require-hashes -r .github/requirements/dev.txt
python -m pip install --no-deps -e .
python -m pip check

echo "[postCreate] Installing cosign…"
COSIGN_VERSION="2.4.1"
curl -fsSL -o /tmp/cosign \
  "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64"
sudo install -m 0755 /tmp/cosign /usr/local/bin/cosign

# syft and trivy: a pinned release tarball checked against the SHA-256 listed
# in that release's checksums.txt (its Sigstore bundle was verified when the
# pin was taken), instead of piping an install script from a moving branch
# into sh.
echo "[postCreate] Installing syft…"
SYFT_VERSION="1.54.0"
SYFT_SHA256="54a87372498168b2d033e876fd41fa4e8035b872699e525a57046e1f2f09c860"
curl -fsSL -o /tmp/syft.tar.gz \
  "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz"
echo "${SYFT_SHA256}  /tmp/syft.tar.gz" | sha256sum --check --strict
sudo tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft
rm -f /tmp/syft.tar.gz

echo "[postCreate] Installing trivy…"
TRIVY_VERSION="0.75.0"
TRIVY_SHA256="c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f"
curl -fsSL -o /tmp/trivy.tar.gz \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
echo "${TRIVY_SHA256}  /tmp/trivy.tar.gz" | sha256sum --check --strict
sudo tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy
rm -f /tmp/trivy.tar.gz

echo "[postCreate] Installing conftest…"
CONFTEST_VERSION="0.55.0"
curl -fsSL -o /tmp/conftest.tar.gz \
  "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz"
sudo tar -xzf /tmp/conftest.tar.gz -C /usr/local/bin conftest
rm -f /tmp/conftest.tar.gz

echo "[postCreate] Verifying CLIs:"
sdlc-evidence --version
cosign version
syft version | head -n 1
trivy --version | head -n 1
conftest --version | head -n 1

echo "[postCreate] Ready. Sample run:"
echo "  sdlc-evidence run \\"
echo "    --application demo --repository demo/demo \\"
echo "    --release-id 1.0.0 --commit-sha \$(git rev-parse HEAD) \\"
echo "    --artifacts-dir examples/sample_release/artifacts \\"
echo "    --output-dir /tmp/demo-bundle"
