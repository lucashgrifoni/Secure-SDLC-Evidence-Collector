# Conftest tests for policies/rego/release-items.rego.
#
# Run with: conftest verify --policy policies/rego/
package release_items

import rego.v1

# 2026-06-01T00:00:00Z, the "now" every waiver test is evaluated at.
now := 1780272000000000000

release := {
    "application": {"name": "payments-api"},
    "release": {"release_id": "2026.04.10"},
}

waiver(expires_at, scope) := {
    "exception_id": "EXC-1",
    "control_id": "ORG-CODE-REVIEW",
    "expires_at": expires_at,
    "scope": scope,
}

bundle_with_waiver(w) := object.union(release, {"exceptions": [w]})

sca(subject, cve_id) := {
    "evidence_id": "ev-sca",
    "subject_ref": subject,
    "vulnerability_intelligence": {
        "cves_in_kev_count": 1,
        "top_risk_cves": [{"cve_id": cve_id, "in_kev": true}],
    },
}

sbom(subject, analyses) := {
    "evidence_id": "ev-sbom",
    "subject_ref": subject,
    "metadata": {"sbom_vex_analyses": analyses},
}

analysis(cve_id, state) := {"cve_id": cve_id, "state": state}

# --- waivers ----------------------------------------------------------------

test_an_expired_waiver_is_denied if {
    some msg in deny with input as bundle_with_waiver(waiver("2026-05-31T23:59:59Z", {}))
        with time.now_ns as now
    contains(msg, "EXC-1")
    contains(msg, "expired")
}

test_a_waiver_still_in_force_passes if {
    count(deny) == 0 with input as bundle_with_waiver(waiver("2026-06-30T00:00:00+02:00", {}))
        with time.now_ns as now
}

test_a_waiver_with_fractional_seconds_is_parsed if {
    count(deny) == 1 with input as bundle_with_waiver(waiver("2026-05-01T08:30:00.123456Z", {}))
        with time.now_ns as now
}

test_an_expired_waiver_scoped_to_this_release_is_denied if {
    count(deny) == 1 with input as bundle_with_waiver(waiver(
        "2026-05-01T00:00:00Z",
        {"application": "payments-api", "release_id": "2026.04.10"},
    ))
        with time.now_ns as now
}

test_an_expired_waiver_for_another_application_is_ignored if {
    count(deny) == 0 with input as bundle_with_waiver(waiver("2026-05-01T00:00:00Z", {"application": "billing"}))
        with time.now_ns as now
}

test_an_expired_waiver_for_another_release_is_ignored if {
    count(deny) == 0 with input as bundle_with_waiver(waiver("2026-05-01T00:00:00Z", {"release_id": "2026.03.01"}))
        with time.now_ns as now
}

test_an_empty_scope_value_means_unscoped if {
    count(deny) == 1 with input as bundle_with_waiver(waiver("2026-05-01T00:00:00Z", {"application": ""}))
        with time.now_ns as now
}

# --- KEV and VEX -------------------------------------------------------------

test_a_kev_cve_without_vex_is_denied if {
    some msg in deny with input as {"evidence": [sca("pkg:pypi/app@1.0", "CVE-2024-3094")]}
    contains(msg, "CVE-2024-3094")
    contains(msg, "pkg:pypi/app@1.0")
}

test_a_kev_cve_marked_not_affected_for_the_same_artifact_passes if {
    count(deny) == 0 with input as {"evidence": [
        sca("pkg:pypi/app@1.0", "cve-2024-3094"),
        sbom("pkg:pypi/app@1.0", [analysis("CVE-2024-3094", "not_affected")]),
    ]}
}

test_a_kev_cve_marked_false_positive_passes if {
    count(deny) == 0 with input as {"evidence": [
        sca("pkg:pypi/app@1.0", "CVE-2024-3094"),
        sbom("pkg:pypi/app@1.0", [analysis("CVE-2024-3094", "false_positive")]),
    ]}
}

test_vex_for_another_artifact_does_not_clear_the_cve if {
    count(deny) == 1 with input as {"evidence": [
        sca("pkg:pypi/app@1.0", "CVE-2024-3094"),
        sbom("pkg:pypi/worker@2.0", [analysis("CVE-2024-3094", "not_affected")]),
    ]}
}

test_conflicting_analyses_for_one_artifact_do_not_clear_the_cve if {
    count(deny) == 1 with input as {"evidence": [
        sca("pkg:pypi/app@1.0", "CVE-2024-3094"),
        sbom("pkg:pypi/app@1.0", [
            analysis("CVE-2024-3094", "not_affected"),
            analysis("CVE-2024-3094", "exploitable"),
        ]),
    ]}
}

test_an_analysis_without_a_state_does_not_clear_the_cve if {
    count(deny) == 1 with input as {"evidence": [
        sca("pkg:pypi/app@1.0", "CVE-2024-3094"),
        sbom("pkg:pypi/app@1.0", [analysis("CVE-2024-3094", null)]),
    ]}
}

test_a_kev_cve_still_exploitable_is_denied if {
    count(deny) == 1 with input as {"evidence": [
        sca("pkg:pypi/app@1.0", "CVE-2024-3094"),
        sbom("pkg:pypi/app@1.0", [analysis("CVE-2024-3094", "exploitable")]),
    ]}
}

test_a_cve_outside_kev_is_ignored if {
    count(deny) == 0 with input as {"evidence": [{
        "evidence_id": "ev-sca",
        "subject_ref": "pkg:pypi/app@1.0",
        "vulnerability_intelligence": {
            "cves_in_kev_count": 0,
            "top_risk_cves": [{"cve_id": "CVE-2023-0001", "in_kev": false}],
        },
    }]}
}

test_unlisted_kev_cves_raise_a_warning if {
    some msg in warn with input as {"evidence": [{
        "evidence_id": "ev-sca",
        "subject_ref": "pkg:pypi/app@1.0",
        "vulnerability_intelligence": {
            "cves_in_kev_count": 3,
            "top_risk_cves": [{"cve_id": "CVE-2024-3094", "in_kev": true}],
        },
    }]}
    contains(msg, "3 KEV CVE(s) but lists 1")
}

test_a_bundle_without_enrichment_or_waivers_passes if {
    plain := {"evidence": [{"evidence_id": "ev-sast", "subject_ref": "repo", "vulnerability_intelligence": null}]}
    count(deny) == 0 with input as plain
    count(warn) == 0 with input as plain
}
