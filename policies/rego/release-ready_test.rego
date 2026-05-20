# Conftest tests for policies/rego/release-ready.rego.
#
# Run with: conftest verify --policy policies/rego/
package release_ready

# Rego imports are per-file: this test file needs the same modern-Rego
# import that release-ready.rego declares, or conftest's OPA rejects it
# with a parse/type error on the `if` / `some ... in` / `contains` syntax.
import rego.v1

test_allows_ready_bundle if {
    count(deny) == 0 with input as {
        "summary": {
            "release_status": "ready",
            "missing_critical_evidence": [],
            "evidence_coverage_score": 100,
            "controls_missing": 0,
            "controls_partial": 0,
            "controls_waived": 0,
            "confidence_score": 75,
        }
    }
}

test_denies_not_ready_status if {
    some msg in deny with input as {
        "summary": {
            "release_status": "not_ready",
            "missing_critical_evidence": [],
            "evidence_coverage_score": 100,
            "controls_missing": 0,
            "controls_partial": 0,
            "controls_waived": 0,
            "confidence_score": 75,
        }
    }
    contains(msg, "release_status")
}

test_denies_missing_critical_evidence if {
    some msg in deny with input as {
        "summary": {
            "release_status": "ready",
            "missing_critical_evidence": ["SSDF-PS.2:artifact_signature"],
            "evidence_coverage_score": 100,
            "controls_missing": 0,
            "controls_partial": 0,
            "controls_waived": 0,
            "confidence_score": 75,
        }
    }
    contains(msg, "missing critical evidence")
}

test_denies_coverage_below_floor if {
    some msg in deny with input as {
        "summary": {
            "release_status": "ready",
            "missing_critical_evidence": [],
            "evidence_coverage_score": 80,
            "controls_missing": 0,
            "controls_partial": 0,
            "controls_waived": 0,
            "confidence_score": 75,
        }
    }
    contains(msg, "evidence_coverage_score")
}

test_warns_on_partial if {
    some msg in warn with input as {
        "summary": {
            "release_status": "ready",
            "missing_critical_evidence": [],
            "evidence_coverage_score": 100,
            "controls_missing": 0,
            "controls_partial": 2,
            "controls_waived": 0,
            "confidence_score": 75,
        }
    }
    contains(msg, "partial")
}

test_warns_on_low_confidence if {
    some msg in warn with input as {
        "summary": {
            "release_status": "ready",
            "missing_critical_evidence": [],
            "evidence_coverage_score": 100,
            "controls_missing": 0,
            "controls_partial": 0,
            "controls_waived": 0,
            "confidence_score": 30,
        }
    }
    contains(msg, "confidence_score")
}
