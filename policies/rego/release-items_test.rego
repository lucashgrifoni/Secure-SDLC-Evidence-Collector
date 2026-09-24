# Conftest tests for policies/rego/release-items.rego.
#
# Run with: conftest verify --policy policies/rego/
package release_items

import rego.v1

# 2026-06-01T00:00:00Z, the "now" every waiver test is evaluated at.
now := 1780272000000000000

waiver(expires_at) := {
    "exception_id": "EXC-1",
    "control_id": "ORG-CODE-REVIEW",
    "expires_at": expires_at,
}

kev_evidence(cve_id, analyses) := {
    "evidence_id": "ev-sca",
    "vulnerability_intelligence": {
        "cves_in_kev_count": 1,
        "top_risk_cves": [{"cve_id": cve_id, "in_kev": true}],
    },
    "metadata": {"sbom_vex_analyses": analyses},
}

test_an_expired_waiver_is_denied if {
    some msg in deny with input as {"exceptions": [waiver("2026-05-31T23:59:59Z")]}
        with time.now_ns as now
    contains(msg, "EXC-1")
    contains(msg, "expired")
}

test_a_waiver_still_in_force_passes if {
    count(deny) == 0 with input as {"exceptions": [waiver("2026-06-30T00:00:00+02:00")]}
        with time.now_ns as now
}

test_a_waiver_with_fractional_seconds_is_parsed if {
    count(deny) == 1 with input as {"exceptions": [waiver("2026-05-01T08:30:00.123456Z")]}
        with time.now_ns as now
}

test_a_kev_cve_without_vex_is_denied if {
    some msg in deny with input as {"evidence": [kev_evidence("CVE-2024-3094", [])]}
    contains(msg, "CVE-2024-3094")
}

test_a_kev_cve_marked_not_affected_passes if {
    count(deny) == 0 with input as {"evidence": [kev_evidence(
        "cve-2024-3094",
        [{"cve_id": "CVE-2024-3094", "state": "not_affected"}],
    )]}
}

test_a_kev_cve_marked_false_positive_passes if {
    count(deny) == 0 with input as {"evidence": [kev_evidence(
        "CVE-2024-3094",
        [{"cve_id": "CVE-2024-3094", "state": "false_positive"}],
    )]}
}

test_a_kev_cve_still_exploitable_is_denied if {
    count(deny) == 1 with input as {"evidence": [kev_evidence(
        "CVE-2024-3094",
        [{"cve_id": "CVE-2024-3094", "state": "exploitable"}],
    )]}
}

test_a_cve_outside_kev_is_ignored if {
    count(deny) == 0 with input as {"evidence": [{
        "evidence_id": "ev-sca",
        "vulnerability_intelligence": {
            "cves_in_kev_count": 0,
            "top_risk_cves": [{"cve_id": "CVE-2023-0001", "in_kev": false}],
        },
    }]}
}

test_unlisted_kev_cves_raise_a_warning if {
    some msg in warn with input as {"evidence": [{
        "evidence_id": "ev-sca",
        "vulnerability_intelligence": {
            "cves_in_kev_count": 3,
            "top_risk_cves": [{"cve_id": "CVE-2024-3094", "in_kev": true}],
        },
    }]}
    contains(msg, "3 KEV CVE(s) but lists 1")
}

test_a_bundle_without_enrichment_or_waivers_passes if {
    count(deny) == 0 with input as {"evidence": [{"evidence_id": "ev-sast", "vulnerability_intelligence": null}]}
    count(warn) == 0 with input as {"evidence": [{"evidence_id": "ev-sast", "vulnerability_intelligence": null}]}
}
