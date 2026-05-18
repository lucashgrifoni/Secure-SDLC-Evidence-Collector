# OPA Rego policy: Secure SDLC Evidence Collector — release readiness gate.
#
# This policy decides whether a `bundle.json` produced by
# `sdlc-evidence run` is acceptable for release. It runs against the
# bundle JSON directly, with no transformation: pipe the bundle straight
# to `conftest test --policy policies/rego/release-ready.rego bundle.json`.
#
# Two evaluation modes, both pure functions over input.summary:
#
#   * `deny[msg]` blocks the release on hard failures (release_status,
#     missing critical controls, coverage floor).
#   * `warn[msg]` raises a warning that does not block by itself.
#
# Tune the floors via `data.release_ready.thresholds` if you want stricter
# gates: pass `--data` to conftest or wire it through `--update`.

package release_ready

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Defaults — override via data.release_ready.thresholds.{coverage,confidence}
# ---------------------------------------------------------------------------
default thresholds := {
    "coverage": 100,
    "confidence": 50,
}

coverage_floor := value if {
    value := data.release_ready.thresholds.coverage
} else := thresholds.coverage

confidence_floor := value if {
    value := data.release_ready.thresholds.confidence
} else := thresholds.confidence

# ---------------------------------------------------------------------------
# Hard denies — block the release.
# ---------------------------------------------------------------------------

deny[msg] if {
    input.summary.release_status != "ready"
    msg := sprintf(
        "release_status is %q; expected \"ready\" for production release",
        [input.summary.release_status],
    )
}

deny[msg] if {
    count(input.summary.missing_critical_evidence) > 0
    msg := sprintf(
        "missing critical evidence: %v",
        [input.summary.missing_critical_evidence],
    )
}

deny[msg] if {
    input.summary.evidence_coverage_score < coverage_floor
    msg := sprintf(
        "evidence_coverage_score=%d below floor=%d",
        [input.summary.evidence_coverage_score, coverage_floor],
    )
}

deny[msg] if {
    input.summary.controls_missing > 0
    msg := sprintf(
        "%d control(s) report status=missing",
        [input.summary.controls_missing],
    )
}

# ---------------------------------------------------------------------------
# Soft warnings — do not block, but surface in CI logs.
# ---------------------------------------------------------------------------

warn[msg] if {
    input.summary.controls_partial > 0
    msg := sprintf(
        "%d control(s) report status=partial; review before tagging",
        [input.summary.controls_partial],
    )
}

warn[msg] if {
    input.summary.confidence_score < confidence_floor
    msg := sprintf(
        "confidence_score=%d below recommended floor=%d",
        [input.summary.confidence_score, confidence_floor],
    )
}

warn[msg] if {
    input.summary.controls_waived > 0
    msg := sprintf(
        "%d control(s) are satisfied via waiver; ensure exception expiry is reviewed",
        [input.summary.controls_waived],
    )
}
