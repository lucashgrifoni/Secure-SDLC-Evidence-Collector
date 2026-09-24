# OPA Rego policy: Secure SDLC Evidence Collector — per-item release checks.
#
# `release-ready.rego` gates on the bundle's summary. The rules here look at
# individual records the summary does not surface:
#
#   * a waiver in `exceptions` whose `expires_at` has passed when the gate
#     runs, which can be weeks after the bundle was generated;
#   * a CVE the `sdlc-evidence enrich` step found in CISA KEV that no inline
#     CycloneDX analysis in the bundle marks `not_affected` or
#     `false_positive`.
#
# The package is separate from `release_ready` on purpose: adding this file
# to a policy directory does not change what an existing gate accepts until
# the caller asks for this namespace:
#
#   conftest test --policy policies/rego/ --namespace release_items bundle.json
#
# Limits: KEV matches come from `vulnerability_intelligence.top_risk_cves`,
# which lists the highest-EPSS CVEs only; a `warn` flags evidence whose KEV
# count is higher than the CVEs listed. VEX documents passed to
# `sdlc-evidence vex --consume` are not stored in the bundle, so they cannot
# clear a KEV CVE here.

package release_items

import rego.v1

# CycloneDX analysis states that mean "this release is not affected".
not_affected_states := {"not_affected", "false_positive"}

# ---------------------------------------------------------------------------
# Hard denies — block the release.
# ---------------------------------------------------------------------------

deny contains msg if {
    some waiver in input.exceptions
    time.parse_rfc3339_ns(waiver.expires_at) <= time.now_ns()
    msg := sprintf(
        "waiver %s for control %s expired at %s",
        [waiver.exception_id, waiver.control_id, waiver.expires_at],
    )
}

kev_cves contains upper(cve.cve_id) if {
    some evidence in input.evidence
    some cve in evidence.vulnerability_intelligence.top_risk_cves
    cve.in_kev == true
}

cleared_cves contains upper(analysis.cve_id) if {
    some evidence in input.evidence
    some analysis in evidence.metadata.sbom_vex_analyses
    analysis.state in not_affected_states
}

deny contains msg if {
    some cve in kev_cves
    not cve in cleared_cves
    msg := sprintf(
        "%s is in CISA KEV and no VEX analysis in the bundle marks it not_affected",
        [cve],
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
