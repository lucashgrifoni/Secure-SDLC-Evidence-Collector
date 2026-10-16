"""Inject and check the CLI facts shown on the GitPage landing page.

The landing page (gitpage/index.html) shows the collector version, the verdict
of the sample release, a not_ready example and the number of evidence types.
Each value sits in an element marked ``data-fact="<name>"`` (its text, plus a
``data-counter`` attribute or a ``chip--<status>`` class on the same tag) or
``data-fact-attrs="<name>"`` (its ``data-meter`` attribute and ``--w`` width).

``inject`` rewrites those values from real CLI output. ``check`` changes
nothing and exits 1 when the page differs from that output or a marker is
missing, so the Pages build cannot publish stale facts.

Run from the repository root with the package installed; the Pages workflow
passes the bundles it generated, the ``schema`` output and ``--version``.

Exit codes: 0 page matches (check) or was written (inject); 1 a fact differs,
a marker is missing, or the example is no longer not_ready; 2 unusable input.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# The page text around the example describes a release missing critical
# evidence, so the example run must still produce this verdict.
EXAMPLE_STATUS = "not_ready"

REQUIRED_FACTS = (
    "version",
    "evidence_types",
    "sample.coverage",
    "sample.confidence",
    "sample.status",
    "sample.evidence",
    "example.coverage",
    "example.confidence",
    "example.status",
    "example.missing",
    "example.excerpt",
)

TEXT_FACT = re.compile(
    r'<(?P<tag>[a-z][a-z0-9]*)(?P<attrs>\s[^>]*?\bdata-fact="(?P<name>[^"]+)"[^>]*)>'
    r"(?P<body>.*?)</(?P=tag)>",
    re.S,
)
ATTR_FACT = re.compile(
    r'<(?P<tag>[a-z][a-z0-9]*)(?P<attrs>\s[^>]*?\bdata-fact-attrs="(?P<name>[^"]+)"[^>]*)>'
)
VERSION = re.compile(r"^\d+\.\d+\.\d+[0-9A-Za-z.+-]*$")


class InputError(Exception):
    """A bundle, schema or version argument cannot be used."""


@dataclass(frozen=True)
class Fact:
    text: str
    number: int | float | None = None
    status: str | None = None

    @property
    def html(self) -> str:
        return html.escape(self.text, quote=False)


def _load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InputError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise InputError(f"{path} is not a JSON object")
    return data


def _number(value: Any, where: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise InputError(f"{where} is not a number: {value!r}")
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _summary(bundle: dict[str, Any], where: str) -> dict[str, Any]:
    summary = bundle.get("summary")
    if not isinstance(summary, dict) or not isinstance(summary.get("release_status"), str):
        raise InputError(f"{where} has no summary.release_status")
    return summary


def compute_facts(
    sample: dict[str, Any], example: dict[str, Any], schema: dict[str, Any], version: str
) -> dict[str, Fact]:
    version = version.strip().removeprefix("v")
    if not VERSION.match(version):
        raise InputError(f"--version is not a version string: {version!r}")

    try:
        evidence_types = schema["$defs"]["EvidenceType"]["enum"]
    except (KeyError, TypeError) as exc:
        raise InputError("schema has no $defs.EvidenceType.enum") from exc

    s_sum = _summary(sample, "sample bundle")
    e_sum = _summary(example, "example bundle")
    s_cov = _number(s_sum.get("evidence_coverage_score"), "sample coverage")
    s_conf = _number(s_sum.get("confidence_score"), "sample confidence")
    e_cov = _number(e_sum.get("evidence_coverage_score"), "example coverage")
    e_conf = _number(e_sum.get("confidence_score"), "example confidence")
    evidence = sample.get("evidence")
    if not isinstance(evidence, list):
        raise InputError("sample bundle has no evidence list")
    missing = e_sum.get("missing_critical_evidence") or []

    release = example.get("release") or {}
    excerpt = {
        "bundle_version": example.get("bundle_version"),
        "release": {key: release.get(key) for key in ("release_id", "commit_sha", "branch")},
        "summary": {
            key: e_sum.get(key)
            for key in (
                "evidence_coverage_score",
                "confidence_score",
                "release_status",
                "missing_critical_evidence",
            )
        },
    }

    return {
        "version": Fact(f"v{version}"),
        "evidence_types": Fact(str(len(evidence_types))),
        "sample.coverage": Fact(f"{s_cov}%", number=s_cov),
        "sample.confidence": Fact(f"{s_conf}%", number=s_conf),
        "sample.status": Fact(s_sum["release_status"], status=s_sum["release_status"]),
        "sample.evidence": Fact(str(len(evidence)), number=len(evidence)),
        "example.coverage": Fact(str(e_cov), number=e_cov),
        "example.confidence": Fact(str(e_conf), number=e_conf),
        "example.status": Fact(e_sum["release_status"], status=e_sum["release_status"]),
        "example.missing": Fact("missing: " + (", ".join(map(str, missing)) or "none")),
        "example.excerpt": Fact(json.dumps(excerpt, indent=2, ensure_ascii=False)),
    }


def render(page: str, facts: dict[str, Fact]) -> tuple[str, set[str], list[str]]:
    """Return the page with every marked fact rewritten, the names seen, and unknown names."""
    seen: set[str] = set()
    unknown: list[str] = []

    def text_sub(match: re.Match[str]) -> str:
        name, attrs = match["name"], match["attrs"]
        fact = facts.get(name)
        if fact is None:
            unknown.append(name)
            return match[0]
        seen.add(name)
        if fact.number is not None:
            attrs = re.sub(r'\bdata-counter="[^"]*"', f'data-counter="{fact.number}"', attrs)
        if fact.status is not None:
            attrs = re.sub(r"\bchip--[a-z-]+", "chip--" + fact.status.replace("_", "-"), attrs)
        return f"<{match['tag']}{attrs}>{fact.html}</{match['tag']}>"

    def attr_sub(match: re.Match[str]) -> str:
        name, attrs = match["name"], match["attrs"]
        fact = facts.get(name)
        if fact is None or fact.number is None:
            unknown.append(name)
            return match[0]
        seen.add(name)
        attrs = re.sub(r'\bdata-meter="[^"]*"', f'data-meter="{fact.number}"', attrs)
        attrs = re.sub(r"--w:\s*[0-9.]+%", f"--w:{fact.number}%", attrs)
        return f"<{match['tag']}{attrs}>"

    page = TEXT_FACT.sub(text_sub, page)
    page = ATTR_FACT.sub(attr_sub, page)
    return page, seen, unknown


def stale_facts(page: str, facts: dict[str, Fact]) -> list[str]:
    """Name each marked element whose current markup differs from the CLI value."""
    stale = []
    for match in TEXT_FACT.finditer(page):
        rendered, _, _ = render(match[0], facts)
        if rendered != match[0]:
            stale.append(f"{match['name']}: page has {match['body'].strip()[:60]!r}")
    for match in ATTR_FACT.finditer(page):
        rendered, _, _ = render(match[0], facts)
        if rendered != match[0]:
            stale.append(f"{match['name']} (attributes)")
    return stale


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inject or check the CLI facts on the landing page."
    )
    parser.add_argument("mode", choices=("inject", "check"))
    parser.add_argument("--page", type=Path, required=True, help="landing page HTML")
    parser.add_argument("--sample", type=Path, required=True, help="bundle.json of the sample")
    parser.add_argument("--example", type=Path, required=True, help="bundle.json of the example")
    parser.add_argument("--schema", type=Path, required=True, help="output of the schema command")
    parser.add_argument("--version", required=True, help="output of --version")
    args = parser.parse_args(argv)

    try:
        facts = compute_facts(
            _load(args.sample), _load(args.example), _load(args.schema), args.version
        )
        page = args.page.read_text(encoding="utf-8")
    except (InputError, OSError) as exc:
        print(f"page_facts: {exc}", file=sys.stderr)
        return 2

    status = facts["example.status"].text
    if status != EXAMPLE_STATUS:
        print(
            f"page_facts: the example run is {status}, but the page describes a "
            f"{EXAMPLE_STATUS} release; update the scoring section of gitpage/index.html",
            file=sys.stderr,
        )
        return 1

    rendered, seen, unknown = render(page, facts)
    missing = [name for name in REQUIRED_FACTS if name not in seen]
    problems = [f"unknown fact marker: {name}" for name in unknown]
    problems += [f"no element carries fact: {name}" for name in missing]

    if args.mode == "check":
        problems += [f"stale fact {item}" for item in stale_facts(page, facts)]
        for problem in problems:
            print(f"page_facts: {problem}", file=sys.stderr)
        if problems:
            return 1
        print(f"page_facts: {len(seen)} facts in {args.page} match the CLI output")
        return 0

    for problem in problems:
        print(f"page_facts: {problem}", file=sys.stderr)
    if problems:
        return 1
    changed = stale_facts(page, facts)
    args.page.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"page_facts: wrote {args.page}; {len(changed)} marked elements updated")
    for item in changed:
        print(f"  {item}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
