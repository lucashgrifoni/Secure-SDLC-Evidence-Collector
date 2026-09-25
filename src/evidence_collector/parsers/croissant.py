"""Croissant dataset metadata parser (MLCommons, spec 1.0 and 1.1).

Croissant is JSON-LD built on schema.org ``Dataset``: dataset hubs publish
it to describe what a dataset is, where its files live, how its records are
structured and under which terms it may be used. For this collector it is
the machine-readable form of training-data lineage.

A file is read when its dataset-level ``conformsTo`` (or the prefixed
``dct:conformsTo``) names ``http://mlcommons.org/croissant/1.0`` or ``/1.1``.
In 1.1 the property may be a list, so a dataset can also declare other specs;
any other version under the Croissant prefix is not read.
Keys are accepted with or without their JSON-LD prefix (``license`` or
``sc:license``), because a document may compact them either way.

What is read, all at dataset level: name, version, url, licenses,
``datePublished``, the PROV-O terms present (``wasDerivedFrom``,
``wasGeneratedBy``, ``wasAttributedTo``), whether ``usageInfo`` carries a
usage policy, and the number of record sets and distribution files (and how
many of those carry a ``sha256``).

Spec references
* Croissant 1.1: https://docs.mlcommons.org/croissant/docs/croissant-spec-1.1.html
* Croissant 1.0: https://docs.mlcommons.org/croissant/docs/croissant-spec.html
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from evidence_collector.parsers._common import (
    ParsedArtifact,
    ParseError,
    describe,
    ensure_file,
    load_json,
)

CROISSANT_URI_PREFIX = "http://mlcommons.org/croissant/"
SUPPORTED_VERSIONS = ("1.0", "1.1")
_PROV_TERMS = ("wasDerivedFrom", "wasGeneratedBy", "wasAttributedTo")


@dataclass
class ParsedCroissant:
    artifact: ParsedArtifact
    croissant_version: str
    name: str | None = None
    dataset_version: str | None = None
    url: str | None = None
    licenses: list[str] = field(default_factory=list)
    date_published: str | None = None
    provenance: list[str] = field(default_factory=list)
    has_usage_policy: bool = False
    record_set_count: int = 0
    distribution_count: int = 0
    distribution_with_sha256: int = 0


def _get(data: dict[str, Any], key: str, *prefixes: str) -> Any:
    """Value of ``key`` under its bare name or any of its JSON-LD prefixes."""
    for candidate in (key, *(f"{prefix}:{key}" for prefix in prefixes)):
        if candidate in data:
            return data[candidate]
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def croissant_version(data: Any) -> str | None:
    """The supported Croissant version a document declares, or None.

    Only the versions this parser implements count. A document that declares
    only some other version under the same prefix (a future 2.0, a typo) is
    not read, so it cannot satisfy a lineage control on a shape nobody checked.
    """
    if not isinstance(data, dict):
        return None
    for uri in _as_list(_get(data, "conformsTo", "dct")):
        if isinstance(uri, str) and uri.startswith(CROISSANT_URI_PREFIX):
            version = uri[len(CROISSANT_URI_PREFIX) :].strip("/")
            if version in SUPPORTED_VERSIONS:
                return version
    return None


def _text(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, dict):
        for key in ("@id", "url", "name"):
            if isinstance(value.get(key), str) and value[key].strip():
                return str(value[key]).strip()
    return None


def _version(value: Any) -> str | None:
    """Dataset version as text; schema.org allows a Number as well as Text.

    Kaggle and OpenML publish ``"version": 1``. A bool is not a version (it is
    an ``int`` in Python), and neither is the NaN or Infinity ``json`` accepts.
    Only a float is checked for that: ``math.isfinite`` converts an int to a
    float, which overflows for an int past about 309 digits.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(value) if math.isfinite(value) else None
    return _text(value)


def _name(value: Any) -> str | None:
    """Dataset name, including the language-tagged forms Croissant 1.1 allows.

    Besides a plain string, ``name`` may be a value object (``{"@value": ...,
    "@language": ...}``), a language map (``{"en": ..., "de": ...}``, declared
    with ``"@container": "@language"``) or a list of those. The choice is
    deterministic, so the same file always gives the same evidence: in a list
    the first entry that reads, in a language map the exact ``en`` tag, then
    the untagged ``@none`` value, then the first language tag in sorted order.
    """
    for entry in _as_list(value):
        text = _text(entry) or _language_tagged(entry)
        if text:
            return text
    return None


def _language_tagged(value: Any) -> str | None:
    """The string a JSON-LD value object or language map carries, or None."""
    if not isinstance(value, dict):
        return None
    if "@value" in value:
        tagged = value["@value"]
        return _text(tagged) if isinstance(tagged, str) else None
    tags = sorted(key for key in value if not key.startswith("@"))
    for tag in ("en", "@none", *tags):
        for candidate in _as_list(value.get(tag)):
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
    return None


def parse_croissant(path: str | Path) -> ParsedCroissant:
    resolved = ensure_file(path)
    data = load_json(resolved)
    version = croissant_version(data)
    if version is None:
        raise ParseError(
            f"{resolved} is not Croissant 1.0 or 1.1: no dataset-level conformsTo "
            f"naming {CROISSANT_URI_PREFIX}1.0 or {CROISSANT_URI_PREFIX}1.1."
        )
    licenses = [text for text in map(_text, _as_list(_get(data, "license", "sc"))) if text]
    distribution = [d for d in _as_list(_get(data, "distribution", "sc")) if isinstance(d, dict)]
    return ParsedCroissant(
        artifact=describe(resolved, content_type="application/ld+json"),
        croissant_version=version,
        name=_name(_get(data, "name", "sc")),
        dataset_version=_version(_get(data, "version", "sc")),
        url=_text(_get(data, "url", "sc")),
        licenses=licenses,
        date_published=_text(_get(data, "datePublished", "sc")),
        provenance=[term for term in _PROV_TERMS if _get(data, term, "prov") is not None],
        has_usage_policy=bool(_as_list(_get(data, "usageInfo", "sc"))),
        record_set_count=len(_as_list(_get(data, "recordSet", "cr"))),
        distribution_count=len(distribution),
        distribution_with_sha256=sum(1 for d in distribution if _get(d, "sha256", "sc")),
    )
