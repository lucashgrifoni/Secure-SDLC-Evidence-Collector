#!/usr/bin/env bash
# Re-run the collector on every existing examples/labs/<lab>/artifacts directory
# without re-scanning. Useful after a code change to refresh recorded bundles.
set -euo pipefail

COLLECTOR_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LABS=(
  "01-core-saas-lab"
  "02-identity-admin-lab"
  "03-cloud-native-lab"
  "04-data-batch-lab"
  "05-ai-llm-lab"
  "06-industry-regulated-lab"
  "07-oss-policy-fixtures-lab"
)

cd "$COLLECTOR_ROOT"
for LAB in "${LABS[@]}"; do
  ART_DIR="examples/labs/${LAB}/artifacts"
  OUT_DIR="examples/labs/${LAB}/output"
  if [ ! -d "$ART_DIR" ]; then
    echo "[skip] $LAB has no artifacts"
    continue
  fi
  mkdir -p "$OUT_DIR"
  python -m evidence_collector.cli.main run \
    --application "$LAB" \
    --repository "lucasgrifoni/app-vuln-teste" \
    --release-id "lab-baseline-2026.04.24" \
    --commit-sha "0000000000000000000000000000000000000001" \
    --branch main \
    --artifacts-dir "$ART_DIR" \
    --artifact-root "$COLLECTOR_ROOT" \
    --output-dir "$OUT_DIR" || echo "[lab=$LAB] collector exited non-zero (expected: not_ready)"
done
echo "[regen] done"
