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
python -m pip install --upgrade pip
python -m pip install -e ".[dev,api,logs]"

echo "[postCreate] Installing cosign…"
COSIGN_VERSION="2.4.1"
curl -fsSL -o /tmp/cosign \
  "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64"
sudo install -m 0755 /tmp/cosign /usr/local/bin/cosign

echo "[postCreate] Installing syft…"
curl -fsSL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
  | sudo sh -s -- -b /usr/local/bin

echo "[postCreate] Installing trivy…"
curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sudo sh -s -- -b /usr/local/bin

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
