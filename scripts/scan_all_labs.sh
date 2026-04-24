#!/usr/bin/env bash
# Drive scan_lab.sh + collector over every lab in `App vuln - teste` and
# produce one evidence bundle per lab under examples/labs/<lab>/output/.
set -euo pipefail

COLLECTOR_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Override with: LAB_ROOT=/path/to/your/App-vuln-teste bash scripts/scan_all_labs.sh
LAB_ROOT="${LAB_ROOT:-${COLLECTOR_ROOT}/../App vuln - teste}"
LABS=(
  "01-core-saas-lab"
  "02-identity-admin-lab"
  "03-cloud-native-lab"
  "04-data-batch-lab"
  "05-ai-llm-lab"
  "06-industry-regulated-lab"
  "07-oss-policy-fixtures-lab"
)

for LAB in "${LABS[@]}"; do
  LAB_PATH="${LAB_ROOT}/${LAB}"
  if [ ! -d "$LAB_PATH" ]; then
    echo "[skip] $LAB missing"
    continue
  fi

  bash "${COLLECTOR_ROOT}/scripts/scan_lab.sh" "$LAB" "$LAB_PATH"

  ART_DIR="${COLLECTOR_ROOT}/examples/labs/${LAB}/artifacts"
  OUT_DIR="${COLLECTOR_ROOT}/examples/labs/${LAB}/output"
  mkdir -p "$OUT_DIR"

  cd "$COLLECTOR_ROOT"
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
echo "[all labs] done"
