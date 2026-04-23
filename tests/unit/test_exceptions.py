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
