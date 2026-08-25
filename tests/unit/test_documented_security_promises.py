"""Tests for the promises `docs/traceability.md` makes under "Security promises".

That table is the project's own claims-to-evidence map: each row states a
security property, the code that implements it, and the test that proves it.
Every test it named was gone — all six function names, across four security
rows and two determinism rows, resolved to nothing. The files existed; the
functions had been renamed or never written.

Two of the promises turned out to be covered under other names (defusedxml in
`test_hostile_input_containment.py`, determinism in `test_determinism.py` and
`test_bundle_snapshot.py`), and the doc now points at those. The two here had
no test under any name, so they are written rather than re-pointed: a promise
in that table is worth only as much as the check behind it.

The fourth row is not here because the promise itself was wrong — see the
comment on `--output-dir` in `docs/traceability.md`.
"""

from __future__ import annotations

import ast
import inspect
import logging
import re
from pathlib import Path

import httpx
import pydantic
import pytest

from evidence_collector.collectors.github import GitHubCollector, GitHubCollectorConfig
from evidence_collector.collectors.gitlab import GitLabCollector, GitLabCollectorConfig
from evidence_collector.domain import models
from evidence_collector.parsers.junit import parse_junit

# Distinctive enough that finding it anywhere in captured output is proof, and
# shaped like the real thing so nothing along the way rejects it early.
CANARY = "ghp_CanaryTokenMustNeverBeLogged00000001"


def _project_root() -> Path:
    """Repo root resolved from the package, never from the cwd."""
    return Path(models.__file__).resolve().parents[3]


def _canonical_models() -> list[tuple[str, type[pydantic.BaseModel]]]:
    """Every Pydantic model defined in `domain/models.py`, by name."""
    return [
        (name, obj)
        for name, obj in vars(models).items()
        if inspect.isclass(obj)
        and issubclass(obj, pydantic.BaseModel)
        and obj.__module__ == models.__name__
        and not name.startswith("_")
    ]


def test_every_canonical_model_is_configured_to_forbid_unknown_fields() -> None:
    """`extra="forbid"` is set once, on the shared base, and inherited.

    Which is why this checks the models rather than the base: a new type that
    subclasses `pydantic.BaseModel` directly instead of `_BaseModel` gets
    Pydantic's default of ignoring unknown fields, silently, and the promise
    would be false for that one type with nothing to say so.
    """
    canonical = _canonical_models()
    assert len(canonical) > 10, "model discovery found almost nothing; the filter is wrong"

    permissive = [name for name, model in canonical if model.model_config.get("extra") != "forbid"]
    assert permissive == [], f"models that would accept unknown fields: {permissive}"


def test_no_canonical_model_actually_accepts_an_unknown_field() -> None:
    """The configuration checked above, exercised rather than read.

    A bundle is consumed by other tools, so a field nobody recognises is a
    contract violation to reject, not data to carry along quietly.
    """
    accepted = []
    for name, model in _canonical_models():
        try:
            model.model_validate({"__definitely_not_a_real_field__": "x"})
        except pydantic.ValidationError as exc:
            if "extra_forbidden" not in str(exc):
                # Failed for a different reason (missing required fields), so
                # this input never reached the extra-field check.
                accepted.append(name)
        else:
            accepted.append(name)

    # Every model has required fields, so the unknown key is reported alongside
    # them. A model that got here without an `extra_forbidden` error either
    # ignored the key or accepted it.
    assert accepted == [], f"models that did not reject an unknown field: {accepted}"


def _capture_all_logging(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="evidence_collector")
    caplog.set_level(logging.DEBUG, logger="httpx")
    caplog.set_level(logging.DEBUG, logger="httpcore")


@pytest.mark.unit
def test_a_github_token_never_reaches_a_log_record(
    sample_release, caplog: pytest.LogCaptureFixture
) -> None:
    """The token is a bearer credential: a log line carrying it is a leak.

    The collector's own logging is only half of it — `httpx` and `httpcore`
    log request headers at DEBUG, and an operator who turns on debug logging
    to diagnose a collection is exactly the person who would then paste the
    output into an issue.
    """
    _capture_all_logging(caplog)

    def handler(request: httpx.Request) -> httpx.Response:
        # The token has to actually be on the wire, or this proves nothing.
        assert request.headers.get("Authorization") == f"Bearer {CANARY}"
        return httpx.Response(404, json={"message": "not found"})

    config = GitHubCollectorConfig(repository="acme/payments-api", token=CANARY)
    client = httpx.Client(
        base_url=config.api_base,
        transport=httpx.MockTransport(handler),
        headers={"Authorization": f"Bearer {CANARY}"},
    )
    try:
        collector = GitHubCollector(config=config, release=sample_release, client=client)
        with pytest.raises(Exception):  # noqa: B017 - any failure path; the point is the logs
            collector.collect_pull_request(184)
    finally:
        client.close()

    assert CANARY not in caplog.text


@pytest.mark.unit
def test_a_gitlab_token_never_reaches_a_log_record(
    sample_release, caplog: pytest.LogCaptureFixture
) -> None:
    """Same promise, other collector — the doc's row covers both."""
    _capture_all_logging(caplog)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("PRIVATE-TOKEN") == CANARY
        return httpx.Response(404, json={"message": "404 Not found"})

    config = GitLabCollectorConfig(project="acme/payments-api", token=CANARY)
    client = httpx.Client(
        base_url=config.api_base,
        transport=httpx.MockTransport(handler),
        headers={"PRIVATE-TOKEN": CANARY},
    )
    try:
        collector = GitLabCollector(config=config, release=sample_release, client=client)
        with pytest.raises(Exception):  # noqa: B017 - any failure path; the point is the logs
            collector.collect_merge_request(184)
    finally:
        client.close()

    assert CANARY not in caplog.text


@pytest.mark.parametrize(
    "config",
    [
        GitHubCollectorConfig(repository="acme/payments-api", token=CANARY),
        GitLabCollectorConfig(project="acme/payments-api", token=CANARY),
    ],
    ids=["github", "gitlab"],
)
def test_a_collector_config_does_not_render_its_token(
    config: GitHubCollectorConfig | GitLabCollectorConfig,
) -> None:
    """Adjacent to the documented promise, and worth pinning separately.

    Nothing logs these config objects, and the two tests above prove the token
    stays out of the log either way. But the dataclass default `repr` printed
    it in full, so one `logger.debug("config=%s", config)`, one traceback
    rendered with locals, or one `pytest --showlocals` on a failing collection
    would have written a live bearer token into output somebody pastes into an
    issue. `repr=False` costs nothing and removes the whole class of accident.
    """
    assert CANARY not in repr(config)
    assert CANARY not in str(config)
    # The token is still there to be used deliberately; it is only unprinted.
    assert config.token == CANARY


@pytest.mark.unit
def test_an_external_entity_is_never_expanded_when_parsing_junit_xml(tmp_path: Path) -> None:
    """XXE file disclosure, asserted on the outcome.

    Measured while writing this: CPython's own `ElementTree` also refuses this
    payload ("reference to external entity in attribute"), so what this pins
    is the outcome and not the mechanism — it would pass without `defusedxml`
    on a current interpreter. It is kept because the outcome is the thing that
    matters and interpreters change; the test below is the one that proves the
    guard is doing work the stdlib would not do.

    The secret must not survive anywhere in the result — including the error
    text, since an exception that quotes the expanded entity leaks the file
    just as effectively as a successful parse.
    """
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET-CONTENT-THAT-MUST-NOT-BE-READ", encoding="utf-8")

    hostile = tmp_path / "junit.xml"
    hostile.write_text(
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE testsuites [<!ENTITY xxe SYSTEM "file://{secret.as_posix()}">]>\n'
        '<testsuites name="&xxe;">\n'
        '  <testsuite name="&xxe;" tests="1" failures="0" errors="0" skipped="0">\n'
        '    <testcase name="&xxe;" classname="x" time="0.1"/>\n'
        "  </testsuite>\n"
        "</testsuites>\n",
        encoding="utf-8",
    )

    try:
        parsed = parse_junit(hostile)
    except Exception as exc:
        outcome = f"{type(exc).__name__}: {exc}"
    else:
        outcome = repr(parsed)

    assert "TOP-SECRET-CONTENT-THAT-MUST-NOT-BE-READ" not in outcome


@pytest.mark.unit
def test_entity_expansion_is_refused_rather_than_expanded(tmp_path: Path) -> None:
    """The half of the promise the standard library does not give for free.

    Nested internal entities are where `defusedxml` and `ElementTree` actually
    diverge. Measured on this payload: the stdlib parses it happily and
    expands the attribute to 10,000 characters, and each further level
    multiplies that by ten until it is a memory exhaustion; `defusedxml`
    rejects the construct. A scanner artifact is untrusted input, so parsing
    one must not be a way to exhaust the machine collecting evidence.
    """
    bomb = tmp_path / "junit.xml"
    bomb.write_text(
        """<?xml version="1.0"?>
<!DOCTYPE testsuites [
  <!ENTITY a "aaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
]>
<testsuites name="&d;">
  <testsuite name="s" tests="1" failures="0" errors="0" skipped="0">
    <testcase name="t" classname="x" time="0.1"/>
  </testsuite>
</testsuites>
""",
        encoding="utf-8",
    )

    with pytest.raises(Exception) as caught:
        parse_junit(bomb)

    # Refused, not expanded: a 10,000-character run of 'a' in the message
    # would mean the entity was resolved before something else objected.
    assert "a" * 200 not in str(caught.value)


def test_every_test_named_in_the_traceability_doc_exists() -> None:
    """The check that stops this drifting again.

    `docs/traceability.md` is the project's claims-to-evidence map, and its
    value is entirely in the pointers resolving. Every one of them was stale —
    six references, all naming functions that no longer existed — and nothing
    noticed, because a doc cannot fail a test suite. This one can.

    It reads the references out of the doc and asks the AST whether each
    function is really there. Renaming a test now breaks the build instead of
    quietly turning a documented promise into an unbacked claim.
    """
    doc = _project_root() / "docs" / "traceability.md"
    if not doc.is_file():  # pragma: no cover - only in a wheel-only install
        pytest.skip("docs/ is not shipped in an installed distribution")

    references = set(re.findall(r"(tests/[\w/]+\.py)::(\w+)", doc.read_text(encoding="utf-8")))
    assert references, "no test references found; the pattern no longer matches the doc"

    missing = []
    for relative, test_name in sorted(references):
        module = _project_root() / relative
        if not module.is_file():
            missing.append(f"{relative} (file does not exist)")
            continue
        tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
        defined = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        if test_name not in defined:
            missing.append(f"{relative}::{test_name}")

    assert missing == [], "docs/traceability.md names tests that do not exist: " + ", ".join(
        missing
    )
