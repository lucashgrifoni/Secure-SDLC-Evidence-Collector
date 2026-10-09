"""CRA clocks need operator evidence; enrichment is not legal applicability."""

from typing import Any

import pytest
from pydantic import ValidationError

from evidence_collector.application import profiles
from tests.unit.test_profiles_and_guac import _bundle, _evidence


def test_operator_deadlines_are_integrity_protected(tmp_path) -> None:
    import json

    from evidence_collector.application.integrity import structural_sha256

    context = profiles.CraReportingContext(
        release_id="2026.05.19",
        commit_sha="abcdef1234567890",
        notification_type="vulnerability",
        awareness_at="2026-10-01T10:00:00Z",
    )
    bundle = profiles.apply_profile(
        _bundle([_evidence()]), profiles.ReleaseProfile.CRA_2026, cra_context=context
    )
    path = tmp_path / "bundle.json"
    payload = bundle.model_dump(mode="json")
    path.write_text(json.dumps(payload), encoding="utf-8")
    expected = structural_sha256(path)
    payload["evidence"][0]["metadata"]["cra"]["reporting_deadlines"]["early_warning"] = (
        "2099-01-01T00:00:00Z"
    )
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert structural_sha256(path) != expected


def test_incident_occurrence_is_optional_in_the_final_stage() -> None:
    context = profiles.CraReportingContext(
        release_id="2026.05.19",
        commit_sha="abcdef1234567890",
        notification_type="incident",
    )
    result = (
        profiles.apply_profile(
            _bundle([_evidence()]), profiles.ReleaseProfile.CRA_2026, cra_context=context
        )
        .evidence[0]
        .metadata["cra"]
    )
    assert "i38" in result["srp_completeness"]["72h_notification"]["missing_field_ids"]
    assert "i38" not in result["srp_completeness"]["final_report"]["missing_field_ids"]


def test_timestamp_overflow_is_an_input_error() -> None:
    with pytest.raises(ValidationError, match="deadline arithmetic"):
        profiles.CraReportingContext(
            release_id="1",
            commit_sha="a",
            notification_type="incident",
            notification_72h_submitted_at="9999-12-31T23:00:00Z",
        )


def test_no_awareness_does_not_create_absolute_deadlines() -> None:
    cra = (
        profiles.apply_profile(_bundle([_evidence(in_kev=True)]), profiles.ReleaseProfile.CRA_2026)
        .evidence[0]
        .metadata["cra"]
    )
    assert cra["awareness_at"] is None
    assert cra["exploitation_status"] == "not_assessed"
    assert cra["reporting_deadlines"]["early_warning"] == {
        "relative_to": "awareness_at",
        "window_hours": 24,
    }
    assert cra["global_exploitation_signal"] == "kev_listed"


def test_awareness_and_remediation_anchor_vulnerability_clocks() -> None:
    context = profiles.CraReportingContext(
        release_id="2026.05.19",
        commit_sha="abcdef1234567890",
        notification_type="vulnerability",
        awareness_at="2026-10-01T10:00:00-03:00",
        corrective_measure_available_at="2026-10-04T12:00:00Z",
        euvd_ids=["EUVD-2026-4893", "EUVD-2026-45012"],
        srp_fields={"1": "Vulnerability", "2": "A title"},
    )
    cra = (
        profiles.apply_profile(
            _bundle([_evidence()]), profiles.ReleaseProfile.CRA_2026, cra_context=context
        )
        .evidence[0]
        .metadata["cra"]
    )
    assert cra["awareness_at"] == "2026-10-01T13:00:00+00:00"
    assert cra["reporting_deadlines"]["early_warning"] == "2026-10-02T13:00:00+00:00"
    assert cra["reporting_deadlines"]["full_notification"] == "2026-10-04T13:00:00+00:00"
    assert cra["reporting_deadlines"]["final_report"]["due_at"] == "2026-10-18T12:00:00+00:00"
    assert cra["srp_glossary_version"] == "1.4"
    assert cra["srp_completeness"]["early_warning"]["missing_field_ids"] == [
        "3",
        "4",
        "5",
        "6",
        "7",
    ]
    assert "v26a" in cra["srp_completeness"]["72h_notification"]["missing_field_ids"]


@pytest.mark.parametrize(
    ("submitted", "expected"),
    [
        ("2027-01-31T12:00:00Z", "2027-02-28T12:00:00+00:00"),
        ("2028-01-31T12:00:00Z", "2028-02-29T12:00:00+00:00"),
        ("2026-12-10T12:00:00Z", "2027-01-10T12:00:00+00:00"),
    ],
)
def test_incident_final_report_is_one_calendar_month(submitted: str, expected: str) -> None:
    context = profiles.CraReportingContext(
        release_id="2026.05.19",
        commit_sha="abcdef1234567890",
        notification_type="incident",
        awareness_at=submitted,
        notification_72h_submitted_at=submitted,
    )
    cra = (
        profiles.apply_profile(
            _bundle([_evidence()]), profiles.ReleaseProfile.CRA_2026, cra_context=context
        )
        .evidence[0]
        .metadata["cra"]
    )
    assert cra["reporting_deadlines"]["final_report"]["due_at"] == expected


@pytest.mark.parametrize(
    "values",
    [
        {"awareness_at": "2026-10-01T10:00:00"},
        {"euvd_ids": ["EUVD-2026-x"]},
        {"notification_type": "incident", "euvd_ids": ["EUVD-2026-4893"]},
        {"srp_fields": {"v999": "not a field"}},
    ],
)
def test_context_rejects_ambiguous_inputs(values: dict[str, Any]) -> None:
    base = {
        "release_id": "2026.05.19",
        "commit_sha": "abcdef1234567890",
        "notification_type": "vulnerability",
    }
    with pytest.raises(ValidationError):
        profiles.CraReportingContext(**(base | values))


def test_context_is_bound_to_the_release() -> None:
    context = profiles.CraReportingContext(
        release_id="another", commit_sha="abcdef1234567890", notification_type="vulnerability"
    )
    with pytest.raises(ValueError, match="release"):
        profiles.apply_profile(
            _bundle([_evidence()]), profiles.ReleaseProfile.CRA_2026, cra_context=context
        )


def test_fedramp_does_not_invent_a_retention_policy() -> None:
    fedramp = (
        profiles.apply_profile(_bundle([_evidence()]), profiles.ReleaseProfile.FEDRAMP_20X)
        .evidence[0]
        .metadata["fedramp"]
    )
    assert "retention_years" not in fedramp
    assert fedramp["ruleset_version"] == "2026.10.05.01"
    assert fedramp["class"] is None


def test_context_is_rejected_for_another_profile() -> None:
    context = profiles.CraReportingContext(
        release_id="2026.05.19", commit_sha="abcdef1234567890", notification_type="vulnerability"
    )
    with pytest.raises(ValueError, match="cra-2026"):
        profiles.apply_profile(
            _bundle([_evidence()]), profiles.ReleaseProfile.NONE, cra_context=context
        )


def _cra(**values: Any) -> dict[str, Any]:
    base = {"release_id": "2026.05.19", "commit_sha": "abcdef1234567890"}
    context = profiles.CraReportingContext(**(base | values))
    metadata: dict[str, Any] = (
        profiles.apply_profile(
            _bundle([_evidence()]), profiles.ReleaseProfile.CRA_2026, cra_context=context
        )
        .evidence[0]
        .metadata["cra"]
    )
    return metadata


@pytest.mark.parametrize(
    "values",
    [
        {
            "notification_type": "vulnerability",
            "awareness_at": "2025-01-01T00:00:00Z",
            "corrective_measure_available_at": "2025-01-03T00:00:00Z",
        },
        {
            "notification_type": "incident",
            "awareness_at": "2026-09-10T23:59:59Z",
            "notification_72h_submitted_at": "2026-09-12T00:00:00Z",
        },
    ],
)
def test_awareness_before_article_14_applies_yields_no_deadlines(values: dict[str, Any]) -> None:
    deadlines = _cra(**values)["reporting_deadlines"]
    expected = {"status": "not_applicable", "reason": "awareness_precedes_obligation_start"}
    assert deadlines["early_warning"] == expected
    assert deadlines["full_notification"] == expected
    assert deadlines["final_report"]["status"] == "not_applicable"
    assert "due_at" not in deadlines["final_report"]


def test_awareness_on_the_application_date_keeps_deadlines() -> None:
    deadlines = _cra(notification_type="vulnerability", awareness_at="2026-09-11T00:00:00Z")[
        "reporting_deadlines"
    ]
    assert deadlines["early_warning"] == "2026-09-12T00:00:00+00:00"


def test_incident_notification_cannot_precede_awareness() -> None:
    with pytest.raises(ValidationError, match=r"notification_72h_submitted_at.*awareness_at"):
        profiles.CraReportingContext(
            release_id="1",
            commit_sha="a",
            notification_type="incident",
            awareness_at="2026-10-05T00:00:00Z",
            notification_72h_submitted_at="2026-10-01T00:00:00Z",
        )


def test_reporter_note_field_40_is_optional_but_csirt_note_is_rejected() -> None:
    cra = _cra(notification_type="incident", srp_fields={"40": "Supplementary note"})
    assert "40" in cra["srp_declared_field_ids"]
    with pytest.raises(ValidationError, match="SRP field"):
        profiles.CraReportingContext(
            release_id="1",
            commit_sha="a",
            notification_type="incident",
            srp_fields={"41": "CSIRT-authored"},
        )


@pytest.mark.parametrize(("kind", "article"), [("vulnerability", "14(2)"), ("incident", "14(4)")])
def test_article_follows_the_notification_type(kind: str, article: str) -> None:
    assert _cra(notification_type=kind)["article"] == article


def test_article_lists_both_paragraphs_without_context() -> None:
    cra = (
        profiles.apply_profile(_bundle([_evidence()]), profiles.ReleaseProfile.CRA_2026)
        .evidence[0]
        .metadata["cra"]
    )
    assert cra["article"] == "14(2),14(4)"


def test_notification_type_is_case_insensitive() -> None:
    assert _cra(notification_type="Incident")["notification_type"] == "incident"


def test_context_commit_sha_matches_case_insensitively() -> None:
    bundle = _bundle([_evidence()])
    context = profiles.CraReportingContext(
        release_id=bundle.release.release_id,
        commit_sha=bundle.release.commit_sha.upper(),
        notification_type="vulnerability",
    )
    annotated = profiles.apply_profile(
        bundle, profiles.ReleaseProfile.CRA_2026, cra_context=context
    )
    assert annotated.evidence[0].metadata["cra"]["notification_type"] == "vulnerability"
