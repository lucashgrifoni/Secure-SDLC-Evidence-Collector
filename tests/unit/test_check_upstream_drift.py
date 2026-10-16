"""The weekly upstream-drift check, exercised offline with canned responses."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "check_upstream_drift", Path("scripts/check_upstream_drift.py")
)
assert _SPEC is not None and _SPEC.loader is not None
drift = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = drift  # dataclasses resolve their module by name
_SPEC.loader.exec_module(drift)

_KSI_IDS = drift.cr26_indicator_ids()


def _rules(version: str, statement: str = "Persistently do it.") -> bytes:
    indicators = {
        kid: {
            "name": kid,
            "statement": statement,
            "controls": ["sa-9"],
            "updated": [{"date": "2026-06-24", "comment": "launch"}],
        }
        for kid in _KSI_IDS
    }
    return json.dumps(
        {"info": {"version": version}, "KSI": {"ALL": {"indicators": indicators}}}
    ).encode()


def _fetcher(responses: dict[str, tuple[int, bytes]]) -> Any:
    def fetch(url: str) -> tuple[int, bytes]:
        return responses[url]

    return fetch


def _healthy() -> dict[str, tuple[int, bytes]]:
    pinned = drift.cr26_url(drift.profiles.FEDRAMP_RULESET_COMMIT)
    version = drift.profiles.FEDRAMP_RULESET_VERSION
    osps = drift.pinned_osps_version()
    srp = drift.SRP_GLOSSARY.version
    return {
        pinned: (200, _rules(version)),
        drift.cr26_url("main"): (200, _rules(version)),
        drift.SRP_GLOSSARY.url: (
            200,
            f"<p><em>Version {srp}. Last update: 15 October 2026</em></p>".encode(),
        ),
        drift.OSPS_URL: (
            200,
            f'Current version: <a href="versions/x">v{osps}</a> (<a>checklist</a>)'.encode(),
        ),
        drift.SSDF_FINAL_URL: (404, b""),
    }


def test_the_pins_are_read_from_the_shipped_sources() -> None:
    assert drift.pinned_osps_version() == "2026.08.28"
    assert len(_KSI_IDS) == 6


def test_every_pinned_source_matching_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    assert drift.main(_fetcher(_healthy())) == 0
    assert "drift" not in capsys.readouterr().out.lower()


def test_a_new_cr26_version_with_the_same_statements_is_only_a_notice() -> None:
    responses = _healthy()
    responses[drift.cr26_url("main")] = (200, _rules("2099.01.01.01"))
    results = {r.source: r for r in drift.run_checks(_fetcher(responses))}
    assert results["FedRAMP CR26"].status == "notice"
    assert drift.main(_fetcher(responses)) == 0


@pytest.mark.parametrize(
    ("url_key", "response"),
    [
        ("cr26_main", (200, b"__statement__")),
        ("srp", (200, b"<em>Version 1.6. Last update: 1 March 2027</em>")),
        ("osps", (200, b'Current version: <a href="v">v2027.03.01</a>')),
        ("ssdf", (200, b"<title>SP 800-218 Rev. 1, Final</title>")),
        ("srp", (503, b"")),
        ("osps", (200, b"page layout changed")),
    ],
)
def test_drift_or_an_unreadable_source_exits_one(
    url_key: str, response: tuple[int, bytes], capsys: pytest.CaptureFixture[str]
) -> None:
    urls = {
        "cr26_main": drift.cr26_url("main"),
        "srp": drift.SRP_GLOSSARY.url,
        "osps": drift.OSPS_URL,
        "ssdf": drift.SSDF_FINAL_URL,
    }
    responses = _healthy()
    if response[1] == b"__statement__":
        response = (200, _rules(drift.profiles.FEDRAMP_RULESET_VERSION, "A new requirement."))
    responses[urls[url_key]] = response
    assert drift.main(_fetcher(responses)) == 1
    assert "DRIFT" in capsys.readouterr().out


def test_github_annotations_are_emitted_in_actions(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    responses = _healthy()
    responses[drift.OSPS_URL] = (200, b'Current version: <a href="v">v2027.03.01</a>')
    assert drift.main(_fetcher(responses)) == 1
    assert "::error title=Upstream drift: OSPS Baseline::" in capsys.readouterr().out
