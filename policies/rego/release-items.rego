# OPA Rego policy: Secure SDLC Evidence Collector — per-item release checks.
#
# `release-ready.rego` gates on the bundle's summary. The rules here look at
# individual records the summary does not surface:
#
#   * a waiver in `exceptions`, scoped to this application and release,
#     whose `expires_at` has passed when the gate runs, which can be weeks
#     after the bundle was generated;
#   * a CVE the `sdlc-evidence enrich` step found in CISA KEV for an
#     artifact, unless every inline CycloneDX analysis of that CVE for the
#     same artifact (`subject_ref`) says `not_affected` or `false_positive`.
#
# The package is separate from `release_ready` on purpose: adding this file
# to a policy directory does not change what an existing gate accepts until
# the caller asks for this namespace:
#
#   conftest test --policy policies/rego/ --namespace release_items bundle.json
#
# Limits: KEV matches come from `vulnerability_intelligence.top_risk_cves`,
# which lists the highest-EPSS CVEs only; a `warn` flags evidence whose KEV
# count is higher than the CVEs listed. The bundle keeps an analysis per CVE
# and artifact, not per component inside the artifact, so the match is at
# artifact level and any conflicting analysis keeps the CVE denied. VEX
# documents passed to `sdlc-evidence vex --consume` are not stored in the
# bundle, so they cannot clear a KEV CVE here.

package release_items

import rego.v1

# CycloneDX analysis states that mean "this release is not affected".
not_affected_states := {"not_affected", "false_positive"}

# ---------------------------------------------------------------------------
# Hard denies — block the release.
# ---------------------------------------------------------------------------

# Same scope rule as EvidenceException.is_valid_for: an empty or missing
# scope value matches any application or release. The collector keeps every
# supplied waiver in the bundle, including ones meant for other releases.
in_scope(waiver) if {
    object.get(waiver, ["scope", "application"], null) in {null, "", input.application.name}
    object.get(waiver, ["scope", "release_id"], null) in {null, "", input.release.release_id}
}

deny contains msg if {
    some waiver in input.exceptions
    in_scope(waiver)
    time.parse_rfc3339_ns(waiver.expires_at) <= time.now_ns()
    msg := sprintf(
        "waiver %s for control %s expired at %s",
        [waiver.exception_id, waiver.control_id, waiver.expires_at],
    )
}

kev_hits contains [evidence.subject_ref, upper(cve.cve_id)] if {
    some evidence in input.evidence
    some cve in evidence.vulnerability_intelligence.top_risk_cves
    cve.in_kev == true
}

analysis_states(subject, cve) := {analysis.state |
    some evidence in input.evidence
    evidence.subject_ref == subject
    some analysis in evidence.metadata.sbom_vex_analyses
    upper(analysis.cve_id) == cve
}

cleared(subject, cve) if {
    states := analysis_states(subject, cve)
    count(states) > 0
    every state in states {
        state in not_affected_states
    }
}

deny contains msg if {
    some [subject, cve] in kev_hits
    not cleared(subject, cve)
    msg := sprintf(
        "%s in %s is in CISA KEV and no VEX analysis for that artifact marks it not_affected",
        [cve, subject],
    )
}

# ---------------------------------------------------------------------------
# Soft warnings — do not block, but surface in CI logs.
# ---------------------------------------------------------------------------

warn contains msg if {
    some evidence in input.evidence
    intel := evidence.vulnerability_intelligence
    listed := count([cve | some cve in intel.top_risk_cves; cve.in_kev == true])
    intel.cves_in_kev_count > listed
    msg := sprintf(
        "evidence %s has %d KEV CVE(s) but lists %d; the rest cannot be checked for VEX",
        [evidence.evidence_id, intel.cves_in_kev_count, listed],
    )
}
