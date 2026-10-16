"""Edge and error-path tests for the SARIF parser.

The happy path lives in ``test_parsers.py``; these tests pin the
defensive branches: missing severity, malformed runs/results, and the
CVE-mining helpers that scrape identifiers out of ``ruleId``,
``properties``, and ``message.text``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from evidence_collector.parsers import parse_sarif
from evidence_collector.parsers._common import ParseError


def _write(tmp_path: Path, payload: dict[str, Any]) -> Path:
    target = tmp_path / "report.sarif"
    target.write_text(json.dumps(payload), encoding="utf-8")
    return target


def test_parse_sarif_defaults_missing_level_to_medium(tmp_path: Path) -> None:
    # A result with no ``level`` must bucket as medium rather than crash.
    path = _write(
        tmp_path,
        {"runs": [{"tool": {"driver": {"name": "trivy"}}, "results": [{"ruleId": "X"}]}]},
    )
    parsed = parse_sarif(path)
    assert parsed.total_findings == 1
    assert parsed.findings_count["medium"] == 1


def test_parse_sarif_rejects_non_dict_first_run(tmp_path: Path) -> None:
    path = _write(tmp_path, {"runs": [42]})
    with pytest.raises(ParseError, match="malformed first run"):
        parse_sarif(path)


def test_parse_sarif_skips_malformed_runs_and_results(tmp_path: Path) -> None:
    # First run is valid; later entries and stray result types are skipped
    # rather than counted, so the total reflects only well-formed findings.
    path = _write(
        tmp_path,
        {
            "runs": [
                {"tool": {"driver": {"name": "semgrep"}}, "results": [{"level": "error"}, "nope"]},
                "not-a-run",
                {"results": "not-a-list"},
            ]
        },
    )
    parsed = parse_sarif(path)
    assert parsed.tool_name == "semgrep"
    assert parsed.total_findings == 1
    assert parsed.findings_count["high"] == 1


def test_parse_sarif_defaults_tool_metadata_when_absent(tmp_path: Path) -> None:
    # No driver name -> placeholder; semanticVersion is used when version
    # is absent.
    path = _write(
        tmp_path,
        {"runs": [{"tool": {"driver": {"semanticVersion": "1.2.3"}}, "results": []}]},
    )
    parsed = parse_sarif(path)
    assert parsed.tool_name == "unknown-sarif-tool"
    assert parsed.tool_version == "1.2.3"
    assert parsed.total_findings == 0


def test_parse_sarif_mines_cves_from_every_site(tmp_path: Path) -> None:
    # CVEs hide in ruleId, properties.tags, properties.cve/cveId/cveID, and
    # message.text; all sites are scraped and de-duplicated/upper-cased.
    path = _write(
        tmp_path,
        {
            "runs": [
                {
                    "tool": {"driver": {"name": "scanner"}},
                    "results": [
                        {
                            "ruleId": "CVE-2023-1111",
                            "properties": {
                                "tags": ["CVE-2023-2222", 99],
                                "cve": "cve-2023-3333",
                                "cveId": ["CVE-2023-4444"],
                                "cveID": "CVE-2023-5555",
                            },
                            "message": {"text": "see CVE-2023-6666 for details"},
                        }
                    ],
                }
            ]
        },
    )
    parsed = parse_sarif(path)
    assert parsed.cve_ids == [
        "CVE-2023-1111",
        "CVE-2023-2222",
        "CVE-2023-3333",
        "CVE-2023-4444",
        "CVE-2023-5555",
        "CVE-2023-6666",
    ]


# ---------------------------------------------------------------------------
# Effective level (SARIF 2.1.0 section 3.27.10): result.level, then the
# defaultConfiguration.level of the rule the result references, then
# "warning". A result whose kind is not "fail" defaults to "none".
# ---------------------------------------------------------------------------


def _run(results: list[Any], rules: list[Any] | None = None, **extra: Any) -> dict[str, Any]:
    driver: dict[str, Any] = {"name": "semgrep"}
    if rules is not None:
        driver["rules"] = rules
    return {"runs": [{"tool": {"driver": driver}, "results": results, **extra}]}


_ERROR_RULE = {"id": "r-error", "defaultConfiguration": {"level": "error"}}
_NOTE_RULE = {"id": "r-note", "defaultConfiguration": {"level": "note"}}


@pytest.mark.parametrize(
    ("result", "bucket"),
    [
        ({"ruleId": "r-error"}, "high"),
        ({"ruleIndex": 1}, "high"),
        ({"rule": {"index": 1}}, "high"),
        ({"rule": {"id": "r-error"}}, "high"),
        ({"ruleId": "r-note"}, "low"),
        # An explicit result level wins over the rule default.
        ({"ruleId": "r-error", "level": "note"}, "low"),
        # No descriptor for the id: the SARIF default "warning".
        ({"ruleId": "unknown-rule"}, "medium"),
        # An index that points nowhere resolves nothing.
        ({"ruleIndex": 7}, "medium"),
        # Non-fail kinds default to "none".
        ({"ruleId": "r-error", "kind": "pass"}, "info"),
        ({"ruleId": "r-error", "kind": "notApplicable"}, "info"),
        ({"ruleId": "r-error", "kind": "informational"}, "info"),
        ({"ruleId": "r-error", "kind": "fail"}, "high"),
    ],
)
def test_effective_level_follows_the_sarif_procedure(
    tmp_path: Path, result: dict[str, Any], bucket: str
) -> None:
    parsed = parse_sarif(_write(tmp_path, _run([result], rules=[_NOTE_RULE, _ERROR_RULE])))
    assert parsed.total_findings == 1
    assert parsed.findings_count[bucket] == 1, parsed.findings_count


def test_rule_in_a_tool_extension_is_resolved(tmp_path: Path) -> None:
    # The codeql-action shape: the result names its rule through
    # rule.toolComponent.index into tool.extensions, sets no level, and the
    # rule carries defaultConfiguration "error" and security-severity 7.5.
    payload = {
        "runs": [
            {
                "tool": {
                    "driver": {"name": "CodeQL", "rules": []},
                    "extensions": [
                        {"name": "codeql/javascript-queries", "rules": []},
                        {
                            "name": "codeql/python-queries",
                            "rules": [
                                {
                                    "id": "py/clear-text-logging-sensitive-data",
                                    "defaultConfiguration": {"level": "error"},
                                    "properties": {"security-severity": "7.5"},
                                }
                            ],
                        },
                    ],
                },
                "results": [
                    {
                        "ruleId": "py/clear-text-logging-sensitive-data",
                        "rule": {
                            "id": "py/clear-text-logging-sensitive-data",
                            "index": 0,
                            "toolComponent": {"index": 1},
                        },
                    }
                ],
            }
        ]
    }
    parsed = parse_sarif(_write(tmp_path, payload))
    assert parsed.findings_count["high"] == 1


def test_tool_component_can_be_named(tmp_path: Path) -> None:
    payload = {
        "runs": [
            {
                "tool": {
                    "driver": {"name": "CodeQL"},
                    "extensions": [{"name": "pack", "rules": [_ERROR_RULE]}],
                },
                "results": [{"rule": {"id": "r-error", "toolComponent": {"name": "pack"}}}],
            }
        ]
    }
    assert parse_sarif(_write(tmp_path, payload)).findings_count["high"] == 1


@pytest.mark.parametrize(
    ("level", "security_severity", "bucket"),
    [
        # security-severity raises the bucket the level gives...
        ("warning", "8.1", "high"),
        ("warning", 9.8, "critical"),
        ("note", "4.0", "medium"),
        # ...and never lowers it.
        ("error", "5.0", "high"),
        ("error", "1.0", "high"),
        # Unusable values are ignored.
        ("warning", "high", "medium"),
        ("warning", "NaN", "medium"),
        ("warning", "11", "medium"),
    ],
)
def test_security_severity_informs_the_severity_bucket(
    tmp_path: Path, level: str, security_severity: object, bucket: str
) -> None:
    rule = {"id": "r", "properties": {"security-severity": security_severity}}
    parsed = parse_sarif(_write(tmp_path, _run([{"ruleId": "r", "level": level}], rules=[rule])))
    assert parsed.findings_count[bucket] == 1, parsed.findings_count


def test_security_severity_does_not_apply_to_a_passing_result(tmp_path: Path) -> None:
    rule = {"id": "r", "properties": {"security-severity": "9.8"}}
    parsed = parse_sarif(_write(tmp_path, _run([{"ruleId": "r", "kind": "pass"}], rules=[rule])))
    assert parsed.findings_count["info"] == 1


# ---------------------------------------------------------------------------
# Suppressions (SARIF sections 3.27.23 and 3.35.3). A result whose every
# suppression is accepted, or carries no status, is not an open finding; it
# is counted apart. underReview and rejected keep it open.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("suppressions", "open_findings", "suppressed"),
    [
        ([{"kind": "inSource"}], 0, 1),
        ([{"kind": "external", "status": "accepted"}], 0, 1),
        ([{"kind": "inSource", "status": "underReview"}], 1, 0),
        ([{"kind": "inSource", "status": "rejected"}], 1, 0),
        ([{"kind": "inSource", "status": "accepted"}, {"status": "underReview"}], 1, 0),
        ([], 1, 0),
        (["not-an-object"], 1, 0),
    ],
)
def test_suppression_status_decides_whether_a_result_is_open(
    tmp_path: Path, suppressions: list[Any], open_findings: int, suppressed: int
) -> None:
    result = {"ruleId": "r-error", "suppressions": suppressions}
    parsed = parse_sarif(_write(tmp_path, _run([result], rules=[_ERROR_RULE])))
    assert parsed.total_findings == open_findings
    assert parsed.findings_count["high"] == open_findings
    assert parsed.suppressed_count == suppressed


# ---------------------------------------------------------------------------
# Run-level signals: a failed invocation, an absent results array, and
# error notifications from the tool.
# ---------------------------------------------------------------------------


def test_failed_invocation_is_recorded(tmp_path: Path) -> None:
    payload = _run(
        [],
        invocations=[
            {
                "executionSuccessful": False,
                "exitCode": 2,
                "toolExecutionNotifications": [
                    {"level": "error", "message": {"text": "could not parse config"}}
                ],
            }
        ],
    )
    parsed = parse_sarif(_write(tmp_path, payload))
    assert parsed.execution_failed is True
    assert parsed.tool_error_count == 1


def test_successful_invocation_is_not_a_failure(tmp_path: Path) -> None:
    payload = _run([], invocations=[{"executionSuccessful": True}])
    parsed = parse_sarif(_write(tmp_path, payload))
    assert parsed.execution_failed is False
    assert parsed.tool_error_count == 0
    assert parsed.results_absent is False


@pytest.mark.parametrize("results", [None, "not-a-list"])
def test_absent_results_differ_from_an_empty_list(tmp_path: Path, results: object) -> None:
    run: dict[str, Any] = {"tool": {"driver": {"name": "semgrep"}}}
    if results is not None:
        run["results"] = results
    parsed = parse_sarif(_write(tmp_path, {"runs": [run]}))
    assert parsed.results_absent is True
    assert parsed.total_findings == 0


def test_only_error_notifications_count_as_tool_errors(tmp_path: Path) -> None:
    payload = _run(
        [],
        invocations=[
            {
                "executionSuccessful": True,
                "toolExecutionNotifications": [{"level": "warning", "message": {"text": "slow"}}],
                "toolConfigurationNotifications": [{"level": "error", "message": {"text": "x"}}],
            }
        ],
    )
    assert parse_sarif(_write(tmp_path, payload)).tool_error_count == 1
