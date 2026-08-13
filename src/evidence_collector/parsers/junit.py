"""JUnit XML parser.

Reads standard JUnit XML (both a single `testsuite` root and a `testsuites`
root containing multiple suites) and returns aggregated counters.

XML safety: parsing is delegated to `defusedxml`, which hardens against
billion-laughs, quadratic-blowup, and external entity expansion. The stdlib
`xml.etree.ElementTree` is kept only for its element API (`Element`) — it
never performs parsing here.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Element and ParseError are used only for typing and exception handling.
# All parsing is delegated to defusedxml below.
from xml.etree.ElementTree import (  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml
    Element,  # nosec B405 - type only
)
from xml.etree.ElementTree import (  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml
    ParseError as StdParseError,  # nosec B405 - exception only
)

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from evidence_collector.parsers._common import (
    ParsedArtifact,
    ParseError,
    describe,
    ensure_file,
)


@dataclass
class ParsedJUnit:
    artifact: ParsedArtifact
    total: int
    failures: int
    errors: int
    skipped: int
    time_seconds: float
    suite_name: str | None


def _parse_int(value: str | None, default: int = 0) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _parse_float(value: str | None, default: float = 0.0) -> float:
    # JUnit `time` values are wall-clock seconds — reject anything that
    # is non-finite (`nan`, `inf`, `-inf`) or negative. A producer that
    # emits those is broken; treating it as the default is safer than
    # propagating nonsense into downstream coverage/score calculations.
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError:
        return default
    import math

    if not math.isfinite(parsed) or parsed < 0.0:
        return default
    return parsed


def _parse_tree(path: Path) -> Element:
    try:
        tree = SafeET.parse(path)
    except StdParseError as exc:
        raise ParseError(f"Invalid JUnit XML in {path}: {exc}") from exc
    except DefusedXmlException as exc:
        # This is the XXE guard doing its job — and it took the whole run down
        # with it. `defusedxml` raises EntitiesForbidden / DTDForbidden /
        # ExternalReferenceForbidden, none of which is a ParseError or an
        # OSError, so it escaped the collector's guard: one hostile or merely
        # DTD-using JUnit file discarded every other artifact in the directory.
        # A blocked document is a rejected input, which is exactly what
        # ParseError means.
        raise ParseError(f"Unsafe XML construct rejected in {path}: {exc}") from exc
    except RecursionError as exc:
        raise ParseError(f"XML in {path} is nested too deeply to parse") from exc
    root = tree.getroot()
    if not isinstance(root, Element):
        raise ParseError(f"Unexpected XML root object in {path}: {type(root).__name__}")
    return root


def parse_junit(path: str | Path) -> ParsedJUnit:
    resolved = ensure_file(path)
    root = _parse_tree(resolved)

    if root.tag == "testsuites":
        suites = list(root.findall("testsuite"))
        suite_name = root.get("name")
    elif root.tag == "testsuite":
        suites = [root]
        suite_name = root.get("name")
    else:
        raise ParseError(f"Unexpected JUnit root element <{root.tag}> in {resolved}")

    total = 0
    failures = 0
    errors = 0
    skipped = 0
    time_seconds = 0.0
    for suite in suites:
        total += _parse_int(suite.get("tests"))
        failures += _parse_int(suite.get("failures"))
        errors += _parse_int(suite.get("errors"))
        skipped += _parse_int(suite.get("skipped") or suite.get("skip"))
        time_seconds += _parse_float(suite.get("time"))

    if total == 0 and not suites:
        raise ParseError(f"JUnit file {resolved} contained no test suites")

    artifact = describe(resolved, content_type="application/xml")
    return ParsedJUnit(
        artifact=artifact,
        total=total,
        failures=failures,
        errors=errors,
        skipped=skipped,
        time_seconds=time_seconds,
        suite_name=suite_name,
    )
