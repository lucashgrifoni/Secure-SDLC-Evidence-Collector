"""Safety guardrails of the shared parser helpers.

Covers the 25 MB input cap, missing-file behaviour, and JSON/YAML
error surfaces. These are part of the security promise documented in
`SECURITY.md § Product security posture`.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from evidence_collector.parsers._common import (
    MAX_INPUT_BYTES,
    ParseError,
    ensure_file,
    load_json,
    load_yaml_or_json,
)


def test_missing_file_raises_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        ensure_file(tmp_path / "nope.json")


def test_oversize_file_hits_safety_cap(tmp_path: Path) -> None:
    big = tmp_path / "big.sarif"
    # Create a sparse-like 26 MB file without burning disk/time.
    with big.open("wb") as handle:
        handle.seek(MAX_INPUT_BYTES + 1024)
        handle.write(b"x")
    assert big.stat().st_size > MAX_INPUT_BYTES
    with pytest.raises(ParseError, match="safety cap"):
        ensure_file(big)


def _file_of_size(path: Path, size: int) -> Path:
    """Write a sparse file of exactly `size` bytes.

    Same trick the oversize test above uses: seek then write one byte, so a
    25 MB boundary costs no real disk or time. `ensure_file` checks existence
    and size and does not read the content, so the hole is harmless.
    """
    with path.open("wb") as handle:
        handle.seek(size - 1)
        handle.write(b"x")
    assert path.stat().st_size == size, "the boundary file is not the size this test needs"
    return path


def test_exact_cap_is_accepted(tmp_path: Path) -> None:
    """A file of exactly `MAX_INPUT_BYTES` is inside the cap, not over it.

    This never reached the boundary before. It wrote two bytes and then padded
    only `if remaining < 64 * 1024`, but `remaining` is `MAX_INPUT_BYTES - 2`
    — about 25 MB — so the condition was always false and the padding never
    ran. The test was named for the cap and asserted nothing about a 2-byte
    file; its own comment said "the real test is that `ensure_file` doesn't
    raise on the boundary", which is precisely what it did not do.
    """
    at_cap = _file_of_size(tmp_path / "at-cap.json", MAX_INPUT_BYTES)
    assert ensure_file(at_cap) == at_cap


def test_one_byte_past_the_cap_is_rejected(tmp_path: Path) -> None:
    """The other side of the boundary, off by exactly one.

    `test_oversize_file_hits_safety_cap` uses cap + 1024, which proves the cap
    exists but not where it is. A comparison written `>=` instead of `>` passes
    that test and fails this one.
    """
    with pytest.raises(ParseError, match="safety cap"):
        ensure_file(_file_of_size(tmp_path / "over-cap.json", MAX_INPUT_BYTES + 1))


def test_load_json_rejects_malformed(tmp_path: Path) -> None:
    f = tmp_path / "bad.json"
    f.write_text("{not: valid}", encoding="utf-8")
    with pytest.raises(ParseError, match="Invalid JSON"):
        load_json(f)


def test_load_json_rejects_non_object(tmp_path: Path) -> None:
    f = tmp_path / "list.json"
    f.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ParseError, match="top-level JSON object"):
        load_json(f)


def test_load_yaml_rejects_malformed(tmp_path: Path) -> None:
    f = tmp_path / "bad.yaml"
    f.write_text("controls: [unterminated:\n", encoding="utf-8")
    with pytest.raises(ParseError, match="Invalid YAML"):
        load_yaml_or_json(f)


def test_load_yaml_rejects_non_mapping(tmp_path: Path) -> None:
    f = tmp_path / "list.yaml"
    f.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ParseError, match="top-level mapping"):
        load_yaml_or_json(f)


def test_load_yaml_accepts_json_document(tmp_path: Path) -> None:
    # YAML is a JSON superset; `.json` payloads fed into
    # `load_yaml_or_json` must still parse cleanly.
    f = tmp_path / "mixed.yaml"
    f.write_text('{"kind": "release_approval", "approver": "sre"}\n', encoding="utf-8")
    assert load_yaml_or_json(f) == {"kind": "release_approval", "approver": "sre"}


def test_ensure_file_normalizes_user_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # `~` should expand to the real home dir, not stay literal.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Windows
    real = tmp_path / ".sdlc" / "evidence.json"
    real.parent.mkdir()
    real.write_text("{}", encoding="utf-8")
    resolved = ensure_file("~/.sdlc/evidence.json")
    assert resolved.is_file()
    assert os.fspath(resolved).endswith("evidence.json")


# ---------------------------------------------------------------------------
# Text-encoding guardrails (ING-01)
#
# The loaders used to let a UnicodeDecodeError escape as-is. Because it is a
# ValueError (not an OSError or a JSONDecodeError), every `except ParseError`
# in the collector missed it and a single mis-encoded file aborted the whole
# run with a raw traceback and no bundle. They must degrade like any other
# malformed input: a ParseError that names the file.
# ---------------------------------------------------------------------------


def test_load_json_raises_parse_error_on_invalid_encoding(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(b'{"runs": [], "x": "\xff\xfe"}')
    with pytest.raises(ParseError) as excinfo:
        load_json(path)
    assert "Invalid text encoding" in str(excinfo.value)
    assert "bad.json" in str(excinfo.value)


def test_load_json_raises_parse_error_on_utf16_document(tmp_path: Path) -> None:
    """A *valid* JSON document saved as UTF-16 (PowerShell's default redirect)."""
    path = tmp_path / "utf16.json"
    path.write_bytes('{"runs": []}'.encode("utf-16"))
    with pytest.raises(ParseError) as excinfo:
        load_json(path)
    assert "Invalid text encoding" in str(excinfo.value)


def test_load_yaml_or_json_raises_parse_error_on_invalid_encoding(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_bytes(b"control_id: \xff\xfe\n")
    with pytest.raises(ParseError) as excinfo:
        load_yaml_or_json(path)
    assert "Invalid text encoding" in str(excinfo.value)


# ---------------------------------------------------------------------------
# The advertised input cap must also cover detection (PERF-01)
#
# MAX_INPUT_BYTES lived only inside `ensure_file`, which runs *after* the
# collector's detection chain. A 40 MB JSON was therefore fully deserialized —
# measured seven times, peak heap 2.4x the file size — before the cap rejected
# it. SECURITY.md advertises the cap as the input guardrail, so it has to hold
# on the first path that touches the file, not the last.
# ---------------------------------------------------------------------------


def test_detection_refuses_a_file_over_the_cap_without_parsing_it(tmp_path: Path) -> None:
    from evidence_collector.collectors.local import _peek_json

    oversized = tmp_path / "big.json"
    # A structurally valid document that would otherwise parse cleanly.
    oversized.write_bytes(b'{"runs": [' + b'{"x": 1},' * 10 + b'{"x": 1}]}')
    os.truncate(oversized, MAX_INPUT_BYTES + 1)

    assert _peek_json(oversized) is None


def test_detection_still_reads_a_file_within_the_cap(tmp_path: Path) -> None:
    from evidence_collector.collectors.local import _peek_json

    ok = tmp_path / "small.json"
    ok.write_text('{"runs": []}', encoding="utf-8")
    assert _peek_json(ok) == {"runs": []}


def test_detection_reparses_when_the_file_changes(tmp_path: Path) -> None:
    """The memo is keyed on (path, mtime, size), so edits are never stale."""
    import os as _os

    from evidence_collector.collectors.local import _peek_json

    path = tmp_path / "changing.json"
    path.write_text('{"runs": []}', encoding="utf-8")
    assert _peek_json(path) == {"runs": []}

    path.write_text('{"runs": [1, 2]}', encoding="utf-8")
    _os.utime(path, (0, 0))  # force a different mtime even on coarse clocks
    assert _peek_json(path) == {"runs": [1, 2]}
