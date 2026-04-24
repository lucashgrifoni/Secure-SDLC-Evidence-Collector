#!/usr/bin/env bash
# Run Semgrep + Trivy fs + Gitleaks + Syft against a single lab directory
# and place canonical artifacts under examples/labs/<lab>/artifacts/.
#
# Usage: scripts/scan_lab.sh <lab-name> <lab-absolute-path>
set -euo pipefail

LAB_NAME="${1:?lab name required}"
LAB_PATH="${2:?lab path required}"
COLLECTOR_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${COLLECTOR_ROOT}/examples/labs/${LAB_NAME}/artifacts"
ATT_DIR="${COLLECTOR_ROOT}/examples/labs/${LAB_NAME}/attestations"
LOG_DIR="${COLLECTOR_ROOT}/examples/labs/${LAB_NAME}/logs"

mkdir -p "$OUT_DIR" "$ATT_DIR" "$LOG_DIR"

# Override any of these via env if your tooling lives elsewhere.
TRIVY_BIN="${TRIVY_BIN:-trivy}"
GITLEAKS_BIN="${GITLEAKS_BIN:-gitleaks}"
SYFT_BIN="${SYFT_BIN:-syft}"
SEMGREP_BIN="${SEMGREP_BIN:-pysemgrep}"

SKIP_DIRS='node_modules,.git,out,out2,out-aws,out-azure,dist,build'

echo "[lab=$LAB_NAME] Semgrep scan"
PYTHONIOENCODING=utf-8 PYTHONUTF8=1 "$SEMGREP_BIN" scan \
  --config p/security-audit \
  --sarif --output "$OUT_DIR/semgrep.sarif" \
  --metrics=off \
  --timeout 300 \
  --exclude 'node_modules' --exclude 'out' --exclude 'out2' --exclude 'out-aws' --exclude 'out-azure' --exclude 'dist' \
  "$LAB_PATH" \
  >"$LOG_DIR/semgrep.log" 2>&1 || echo "[lab=$LAB_NAME] semgrep exited non-zero (findings expected)"

echo "[lab=$LAB_NAME] Trivy fs scan"
"$TRIVY_BIN" fs \
  --scanners vuln,secret,misconfig \
  --format sarif \
  --output "$OUT_DIR/trivy.sarif" \
  --skip-dirs "$SKIP_DIRS" \
  --timeout 10m \
  "$LAB_PATH" \
  >"$LOG_DIR/trivy.log" 2>&1 || echo "[lab=$LAB_NAME] trivy exited non-zero (findings expected)"

echo "[lab=$LAB_NAME] Gitleaks secrets scan"
"$GITLEAKS_BIN" detect \
  --source "$LAB_PATH" \
  --report-path "$OUT_DIR/gitleaks.sarif" \
  --report-format sarif \
  --no-git \
  --redact \
  --log-opts "" \
  >"$LOG_DIR/gitleaks.log" 2>&1 || echo "[lab=$LAB_NAME] gitleaks exited non-zero (findings expected)"

echo "[lab=$LAB_NAME] Syft SBOM"
"$SYFT_BIN" scan "$LAB_PATH" \
  --exclude './**/node_modules' \
  --exclude './**/out' \
  --exclude './**/out2' \
  -o cyclonedx-json="$OUT_DIR/sbom.cdx.json" \
  >"$LOG_DIR/syft.log" 2>&1 || echo "[lab=$LAB_NAME] syft exited non-zero"

echo "[lab=$LAB_NAME] done"
