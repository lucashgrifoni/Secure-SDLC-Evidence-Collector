"""Unit tests for the exception/waiver workflow."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from evidence_collector.controls import default_catalog, evaluate_controls
from evidence_collector.domain.enums import ControlEvaluationStatus, ReleaseStatus
from evidence_collector.domain.models import (
    Application,
    EvidenceException,
    ExceptionScope,
    ReleaseContext,
)
from evidence_collector.parsers import parse_exception
from evidence_collector.parsers._common import ParseError
from evidence_collector.scoring import build_summary


def _exception(
    control_id: str = "SSDF-PW.1",
    *,
    expires_in_days: int = 30,
    application: str | None = None,
    release_id: str | None = None,
) -> EvidenceException:
    approved = datetime(2026, 4, 10, tzinfo=UTC)
    return EvidenceException(
        exception_id=f"EXC-{control_id}",
        control_id=control_id,
        approver="appsec-lead@example.com",
        approved_at=approved,
        expires_at=approved + timedelta(days=expires_in_days),
        justification="No new trust boundary; follow-up scheduled for next quarter.",
        reference="JIRA-1234",
        scope=ExceptionScope(application=application, release_id=release_id),
    )


def test_exception_rejects_expires_before_approved() -> None:
    approved = datetime(2026, 4, 10, tzinfo=UTC)
    with pytest.raises(ValueError, match="expires_at"):
        EvidenceException(
            exception_id="EXC-1",
            control_id="SSDF-PW.1",
            approver="x@example.com",
            approved_at=approved,
            expires_at=approved - timedelta(hours=1),
            justification="reason long enough to pass validation",
        )


def test_exception_is_valid_for_scope() -> None:
    exc = _exception(application="payments-api", release_id="2026.04.10")
    now = datetime(2026, 4, 15, tzinfo=UTC)
    assert exc.is_valid_for("payments-api", "2026.04.10", now) is True
    assert exc.is_valid_for("other-app", "2026.04.10", now) is False
    assert exc.is_valid_for("payments-api", "2026.05.01", now) is False
    expired = datetime(2026, 8, 1, tzinfo=UTC)
    assert exc.is_valid_for("payments-api", "2026.04.10", expired) is False


def test_waiver_turns_missing_control_into_waived() -> None:
    catalog = default_catalog()
    app_ = Application(name="payments-api", repository="acme/payments-api")
    release = ReleaseContext(release_id="2026.04.10", commit_sha="abcdef1234567890")
    exc = _exception(
        control_id="ORG-REL-ROLLBACK",
        application="payments-api",
        release_id="2026.04.10",
    )
    now = datetime(2026, 4, 15, tzinfo=UTC)

    evaluations, gaps = evaluate_controls(
        catalog,
        [],  # no evidence at all
        exceptions=[exc],
        application=app_,
        release=release,
        now=now,
    )

    rollback = next(e for e in evaluations if e.control_id == "ORG-REL-ROLLBACK")
    assert rollback.evaluation_status == ControlEvaluationStatus.WAIVED
    assert rollback.exception_refs == ["EXC-ORG-REL-ROLLBACK"]

    # With every other critical control still missing, release remains
    # not_ready — the waiver only neutralizes ORG-REL-ROLLBACK.
    summary = build_summary(catalog, evaluations, gaps)
    assert summary.release_status == ReleaseStatus.NOT_READY
    assert summary.controls_waived == 1


def test_expired_waiver_does_not_apply() -> None:
    catalog = default_catalog()
    exc = _exception(control_id="ORG-REL-ROLLBACK")
    now = datetime(2027, 4, 15, tzinfo=UTC)  # well past the 30-day expiry
    evaluations, _ = evaluate_controls(
        catalog, [], exceptions=[exc], application="payments-api", release="2026.04.10", now=now
    )
    rollback = next(e for e in evaluations if e.control_id == "ORG-REL-ROLLBACK")
    assert rollback.evaluation_status == ControlEvaluationStatus.MISSING


def test_parse_exception_yaml(tmp_path: Path) -> None:
    path = tmp_path / "EXC-1.yaml"
    path.write_text(
        """
exception_id: EXC-2026-001
control_id: SSDF-PW.1
approver: appsec-lead@example.com
approved_at: 2026-04-10T10:00:00Z
expires_at: 2026-07-10T10:00:00Z
justification: "No new trust boundaries. TM update scheduled next quarter."
reference: JIRA-1234
scope:
  application: payments-api
  release_id: 2026.04.10
""",
        encoding="utf-8",
    )
    exc = parse_exception(path)
    assert exc.exception_id == "EXC-2026-001"
    assert exc.scope.application == "payments-api"
    assert exc.scope.release_id == "2026.04.10"


def test_parse_exception_rejects_short_justification(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        """
exception_id: EXC-2026-002
control_id: SSDF-PW.1
approver: a@example.com
approved_at: 2026-04-10T10:00:00Z
expires_at: 2026-05-10T10:00:00Z
justification: "short"
""",
        encoding="utf-8",
    )
    with pytest.raises(ParseError):
        parse_exception(path)


def test_parse_exception_rejects_missing_required_fields(tmp_path: Path) -> None:
    path = tmp_path / "missing.yaml"
    path.write_text(
        """
exception_id: EXC-2026-099
control_id: SSDF-PW.1
""",
        encoding="utf-8",
    )
    with pytest.raises(ParseError, match="missing required fields"):
        parse_exception(path)


def test_parse_exception_rejects_invalid_iso_datetime(tmp_path: Path) -> None:
    path = tmp_path / "bad_dt.yaml"
    path.write_text(
        """
exception_id: EXC-2026-100
control_id: SSDF-PW.1
approver: appsec-lead@example.com
approved_at: "not-a-real-datetime"
expires_at: 2026-07-10T10:00:00Z
justification: "No new trust boundary; follow-up scheduled for next quarter."
""",
        encoding="utf-8",
    )
    with pytest.raises(ParseError, match="Invalid ISO 8601 datetime"):
        parse_exception(path)


def test_parse_exception_rejects_unsupported_datetime_type(tmp_path: Path) -> None:
    # Pure JSON cannot represent native datetimes, so an integer is treated
    # as an unsupported type by the parser's _parse_datetime helper.
    path = tmp_path / "bad_type.json"
    path.write_text(
        """
{
  "exception_id": "EXC-2026-101",
  "control_id": "SSDF-PW.1",
  "approver": "appsec-lead@example.com",
  "approved_at": 12345,
  "expires_at": "2026-07-10T10:00:00Z",
  "justification": "No new trust boundary; follow-up scheduled for next quarter."
}
""",
        encoding="utf-8",
    )
    with pytest.raises(ParseError, match="Unsupported approved_at type"):
        parse_exception(path)


def test_parse_exception_rejects_non_mapping_scope(tmp_path: Path) -> None:
    path = tmp_path / "bad_scope.yaml"
    path.write_text(
        """
exception_id: EXC-2026-102
control_id: SSDF-PW.1
approver: appsec-lead@example.com
approved_at: 2026-04-10T10:00:00Z
expires_at: 2026-07-10T10:00:00Z
justification: "No new trust boundary; follow-up scheduled for next quarter."
scope: "payments-api"
""",
        encoding="utf-8",
    )
    with pytest.raises(ParseError, match=r"scope.*must be a mapping"):
        parse_exception(path)


# ---------------------------------------------------------------------------
# The demo waiver fixture must not rot silently (FIX-01)
#
# `examples/sample_release/exceptions/EXC-2026-DEMO-001.yaml` is the only way
# to demonstrate the WAIVED state. Its `expires_at` lapsed on 2026-08-05 and
# the documented command in that folder's README silently stopped reproducing:
# `waived=1` became `waived=0`, `missing=5` became `missing=6`, and nothing
# failed. A date-bearing fixture needs a test that trips before the date does.
# ---------------------------------------------------------------------------

_DEMO_WAIVER = Path("examples/sample_release/exceptions/EXC-2026-DEMO-001.yaml")
_RENEW_MARGIN = timedelta(days=180)


def test_demo_waiver_fixture_is_not_close_to_expiring() -> None:
    exc = parse_exception(_DEMO_WAIVER)
    remaining = exc.expires_at - datetime.now(tz=UTC)
    assert remaining > _RENEW_MARGIN, (
        f"{_DEMO_WAIVER} expires in {remaining.days} days. Renew expires_at "
        "before it lapses, or the documented waiver walkthrough in "
        "examples/sample_release/exceptions/README.md stops reproducing."
    )


def test_demo_waiver_still_produces_a_waived_control(sample_release_root: Path) -> None:
    """The state the fixture exists to demonstrate must actually be reachable."""
    exc = parse_exception(_DEMO_WAIVER)
    evaluations, _ = evaluate_controls(
        default_catalog(),
        [],
        exceptions=[exc],
        application=exc.scope.application,
        release=exc.scope.release_id,
    )
    waived = [e for e in evaluations if e.evaluation_status == ControlEvaluationStatus.WAIVED]
    assert [e.control_id for e in waived] == [exc.control_id]
    assert exc.exception_id in waived[0].exception_refs


# ---------------------------------------------------------------------------
# A waiver that did not apply must leave a trace (FIX-01)
#
# An expired or out-of-scope waiver was dropped in silence: it still appeared
# in `bundle.exceptions`, but the control came out MISSING with an empty
# `exception_refs` and a rationale that never mentioned it. An auditor could
# not tell "no exception was ever requested" from "an exception was requested
# and refused" — in a tool whose entire product is the audit trail.
# ---------------------------------------------------------------------------


def test_expired_waiver_is_named_in_the_rationale() -> None:
    expired = _exception(application="app", release_id="1.0.0", expires_in_days=1)
    evaluations, _ = evaluate_controls(
        default_catalog(),
        [],
        exceptions=[expired],
        application="app",
        release="1.0.0",
        now=expired.expires_at + timedelta(days=1),
    )
    target = next(e for e in evaluations if e.control_id == expired.control_id)
    assert target.evaluation_status == ControlEvaluationStatus.MISSING
    assert expired.exception_id in target.rationale
    assert "expired" in target.rationale


def test_out_of_scope_waiver_is_named_in_the_rationale() -> None:
    scoped = _exception(application="some-other-app", expires_in_days=3650)
    evaluations, _ = evaluate_controls(
        default_catalog(),
        [],
        exceptions=[scoped],
        application="the-app-being-released",
        release="1.0.0",
        now=scoped.approved_at + timedelta(days=1),
    )
    target = next(e for e in evaluations if e.control_id == scoped.control_id)
    assert target.evaluation_status == ControlEvaluationStatus.MISSING
    assert scoped.exception_id in target.rationale
    assert "out of scope" in target.rationale


def test_control_without_any_exception_keeps_a_clean_rationale() -> None:
    """The trace must only appear when an exception really was supplied."""
    evaluations, _ = evaluate_controls(default_catalog(), [], exceptions=[])
    for evaluation in evaluations:
        assert "exception was supplied" not in evaluation.rationale


def test_waiver_does_not_apply_before_its_approval_date() -> None:
    """A waiver approved for a future window must not waive anything today.

    `is_valid_for` only checked the upper bound (`now < expires_at`), so an
    exception with `approved_at` in the future was already in force: paste a
    2027 waiver into the exceptions directory today and the control flips to
    WAIVED immediately. The approval window has two ends, and a release gate
    that honours a not-yet-granted approval is exactly the failure mode the
    waiver file exists to prevent.
    """
    future = _exception()
    now = future.approved_at - timedelta(days=1)

    assert not future.is_valid_for(application="", release_id="", now=now)

    evaluations, _ = evaluate_controls(default_catalog(), [], exceptions=[future], now=now)
    target = next(e for e in evaluations if e.control_id == future.control_id)
    assert target.evaluation_status == ControlEvaluationStatus.MISSING
    assert target.exception_refs == []
    assert "not yet in effect" in target.rationale
    assert future.exception_id in target.rationale


def test_waiver_applies_exactly_on_its_approval_instant() -> None:
    """The lower bound is inclusive: the waiver is live the moment it starts."""
    exception = _exception()
    assert exception.is_valid_for(application="", release_id="", now=exception.approved_at)


@pytest.mark.parametrize("field", ["approved_at", "expires_at"])
def test_naive_waiver_timestamps_are_rejected_with_an_actionable_message(field: str) -> None:
    """A timestamp with no timezone has no defined instant, so it cannot be compared.

    Waiver windows are evaluated against an aware UTC `now`. A naive value
    used to reach that comparison and raise `TypeError: can't compare offset-naive
    and offset-aware datetimes` from deep inside the engine — the run died with a
    stack trace that never named the file or the field. YAML makes this easy to
    hit: `expires_at: 2026-12-31` parses to a naive datetime.
    """
    approved = datetime(2026, 4, 10, tzinfo=UTC)
    expires = approved + timedelta(days=30)
    timestamps = {"approved_at": approved, "expires_at": expires}
    timestamps[field] = timestamps[field].replace(tzinfo=None)

    with pytest.raises(ValueError) as excinfo:
        EvidenceException(
            exception_id="EXC-1",
            control_id="SSDF-PW.1",
            approver="appsec-lead@example.com",
            approved_at=timestamps["approved_at"],
            expires_at=timestamps["expires_at"],
            justification="No new trust boundary; follow-up scheduled for next quarter.",
        )

    message = str(excinfo.value)
    assert field in message
    assert "must carry a timezone" in message
    assert "2026-12-31T00:00:00Z" in message
