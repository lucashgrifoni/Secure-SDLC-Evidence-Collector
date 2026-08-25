"""Every command that reads a bundle must fail the same way on a corrupt one.

Eight of them guarded the read with `OSError` and `json.JSONDecodeError` and
nothing else. That covers a missing file and a syntax error; it does not cover
what a corrupted file actually does on the way in. The rest reached the
top-level handler, so the exit code stayed right at 3 while the message became
a bare `ValueError: Exceeds the limit (4300 digits)... use
sys.set_int_max_str_digits()` — which names no file, and points at a remedy
that is not the problem. A pipeline running one of these over many bundles
could not tell which one failed.

`verify` matters most of the group: it is the integrity check, so it is the
command most likely to be run in a loop over artifacts of unknown quality.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from evidence_collector.cli._exit_codes import EXIT_INPUT_ERROR
from evidence_collector.cli.main import app

# Each entry builds the argv for one command from a bundle path. Commands that
# take the bundle positionally share a shape; `oscal` takes it behind a flag.
BUNDLE_COMMANDS: dict[str, list[str]] = {
    "verify": ["verify", "{bundle}"],
    "vex": ["vex", "{bundle}"],
    "guac": ["guac", "{bundle}"],
    "statement": ["statement", "{bundle}"],
    "enrich": ["enrich", "{bundle}"],
    "oscal": ["oscal", "--kind", "assessment-results", "--bundle", "{bundle}"],
}

MALFORMED: dict[str, bytes] = {
    "nested-past-the-stack-limit": b"[" * 60_000 + b"]" * 60_000,
    "int-past-the-4300-digit-cap": b'{"evidence":[{"n":' + b"9" * 5_000 + b"}]}",
    "undecodable-byte": b'{"evidence":[{"x":"\xff\xfe"}]}',
    "truncated-mid-object": b'{"evidence":[{"x"',
    "html-error-page": b"<html><body>504</body></html>",
}


def _invoke(command: str, bundle: Path) -> tuple[int, str]:
    """Run one command and return its exit code and its output as one line.

    Rich wraps a long path across several lines, so the output is rejoined
    before anything looks for a filename in it — otherwise the assertion would
    depend on how wide the terminal happened to be.
    """
    argv = [part.format(bundle=str(bundle)) for part in BUNDLE_COMMANDS[command]]
    result = CliRunner().invoke(app, argv)
    return result.exit_code, "".join(result.output.split())


@pytest.mark.parametrize("command", sorted(BUNDLE_COMMANDS))
@pytest.mark.parametrize("payload", sorted(MALFORMED))
def test_a_corrupt_bundle_is_reported_against_the_file_it_came_from(
    tmp_path: Path, command: str, payload: str
) -> None:
    bundle = tmp_path / "corrupt.json"
    bundle.write_bytes(MALFORMED[payload])

    code, output = _invoke(command, bundle)

    assert code == EXIT_INPUT_ERROR
    # The command's own handler ran, rather than the failure escaping to the
    # top-level one. That is the whole difference: both exit 3, but only this
    # path says which file and what the tool was trying to do with it. The
    # underlying exception text is still interpolated after the path — it is
    # the detail an operator may need, so it is kept, not suppressed.
    assert "Couldnotread" in output
    assert "corrupt.json" in output


@pytest.mark.parametrize("command", sorted(set(BUNDLE_COMMANDS) - {"verify"}))
def test_a_schema_mismatch_is_still_reported_as_a_schema_mismatch(
    tmp_path: Path, command: str
) -> None:
    """The half the widened guard could have broken.

    Pydantic's `ValidationError` is a `ValueError` subclass, so a guard wide
    enough to catch the malformed cases above can swallow it and report a
    schema mismatch as an unreadable file. `oscal` hangs both clauses off one
    `try`, where clause order decides which wins.

    `verify` is excluded because it hashes the JSON without validating it
    against the model, so it has no schema path to preserve.
    """
    bundle = tmp_path / "wrong-shape.json"
    bundle.write_text(json.dumps({"bundle_version": "1.0", "evidence": "not a list"}))

    code, output = _invoke(command, bundle)

    assert code == EXIT_INPUT_ERROR
    assert "doesnotmatchthecurrentschema" in output.lower()
