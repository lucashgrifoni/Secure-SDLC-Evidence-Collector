"""JSON log records stay JSON when the host already configured logging."""

from __future__ import annotations

import io
import json
import logging
from collections.abc import Iterator

import pytest

from evidence_collector.cli._logging import configure_logging
from evidence_collector.cli._state import set_json_logs


@pytest.fixture
def plain_root() -> Iterator[io.StringIO]:
    """A root logger configured with a plain-text handler, as a host would."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    try:
        yield stream
    finally:
        root.removeHandler(handler)
        set_json_logs(False)
        configure_logging(verbose=False)


def _json_handler() -> logging.Handler:
    package = logging.getLogger("evidence_collector")
    (handler,) = [h for h in package.handlers if h.formatter is not None]
    return handler


def test_json_mode_formats_package_records_despite_a_configured_root(
    plain_root: io.StringIO,
) -> None:
    set_json_logs(True)
    configure_logging(verbose=False)
    handler = _json_handler()
    record = logging.LogRecord(
        "evidence_collector.collectors.local",
        logging.WARNING,
        __file__,
        1,
        "skipped %s",
        ("x",),
        None,
    )
    payload = json.loads(handler.format(record))
    assert payload == {
        "event": "log",
        "level": "warning",
        "logger": "evidence_collector.collectors.local",
        "message": "skipped x",
    }
    logging.getLogger("evidence_collector.collectors.local").warning("hidden from root")
    assert "hidden from root" not in plain_root.getvalue()


def test_leaving_json_mode_removes_the_handler(plain_root: io.StringIO) -> None:
    set_json_logs(True)
    configure_logging(verbose=False)
    set_json_logs(False)
    configure_logging(verbose=False)
    package = logging.getLogger("evidence_collector")
    assert package.propagate is True
    assert not [h for h in package.handlers if h.formatter is not None]
    package.warning("back on the root")
    assert "back on the root" in plain_root.getvalue()
