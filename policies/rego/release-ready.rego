# OPA Rego policy: Secure SDLC Evidence Collector — release readiness gate.
#
# This policy decides whether a `bundle.json` produced by
# `sdlc-evidence run` is acceptable for release. It runs against the
# bundle JSON directly, with no transformation:
#
#   conftest test --policy policies/rego/release-ready.rego \
#     --namespace release_ready bundle.json
#
# The package is `release_ready`, and conftest evaluates only `main` unless
# told otherwise: without `--namespace release_ready` it runs 0 tests and
# exits 0 even on a not_ready bundle.
#
# Two evaluation modes, both pure functions over input.summary:
#
#   * `deny[msg]` blocks the release on hard failures (release_status,
#     missing critical controls, coverage floor).
#   * `warn[msg]` raises a warning that does not block by itself.
#
# Tune the floors via `data.release_ready.thresholds` if you want stricter
# gates: put them in a JSON or YAML file and pass its path to conftest with
# `--data` (see policies/README.md). `--data` takes a file, not inline JSON.

package release_ready

import rego.v1

# ---------------------------------------------------------------------------
# Defaults — override via data.release_ready.thresholds.{coverage,confidence}
# ---------------------------------------------------------------------------
default_thresholds := {
    "coverage": 100,
    "confidence": 50,
}

coverage_floor := value if {
    value := data.release_ready.thresholds.coverage
} else := default_thresholds.coverage

confidence_floor := value if {
    value := data.release_ready.thresholds.confidence
} else := default_thresholds.confidence

# ---------------------------------------------------------------------------
# Hard denies — block the release.
# ---------------------------------------------------------------------------

deny contains msg if {
    input.summary.release_status != "ready"
    msg := sprintf(
        "release_status is %q; expected \"ready\" for production release",
        [input.summary.release_status],
    )
}

deny contains msg if {
    count(input.summary.missing_critical_evidence) > 0
    msg := sprintf(
        "missing critical evidence: %v",
        [input.summary.missing_critical_evidence],
    )
}

deny contains msg if {
    input.summary.evidence_coverage_score < coverage_floor
    msg := sprintf(
        "evidence_coverage_score=%d below floor=%d",
        [input.summary.evidence_coverage_score, coverage_floor],
    )
}

deny contains msg if {
    input.summary.controls_missing > 0
    msg := sprintf(
        "%d control(s) report status=missing",
        [input.summary.controls_missing],
    )
}

# ---------------------------------------------------------------------------
# Soft warnings — do not block, but surface in CI logs.
# ---------------------------------------------------------------------------

warn contains msg if {
    input.summary.controls_partial > 0
    msg := sprintf(
        "%d control(s) report status=partial; review before tagging",
        [input.summary.controls_partial],
    )
}

warn contains msg if {
    input.summary.confidence_score < confidence_floor
    msg := sprintf(
        "confidence_score=%d below recommended floor=%d",
        [input.summary.confidence_score, confidence_floor],
    )
}

warn contains msg if {
    input.summary.controls_waived > 0
    msg := sprintf(
        "%d control(s) are satisfied via waiver; ensure exception expiry is reviewed",
        [input.summary.controls_waived],
    )
}
