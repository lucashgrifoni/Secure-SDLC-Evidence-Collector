"""Parser for formal Secure SDLC exceptions (waivers).

An exception file is a YAML or JSON document describing a time-bound
approval that allows a control to be considered satisfied in the absence
of its required evidence. The expected schema:

```yaml
exception_id: "EXC-2026-001"
control_id: "SSDF-PW.1"
approver: "appsec-lead@example.com"
approved_at: "2026-04-10T10:00:00Z"
expires_at: "2026-07-10T10:00:00Z"
justification: >-
  No new trust boundaries are introduced. A full threat model update is
  scheduled for the next quarter.
reference: "JIRA-1234"
scope:
  application: "payments-api"       # optional, restricts to this app
  release_id: "2026.04.10"          # optional, restricts to this release
```

`expires_at` must be strictly after `approved_at`. `justification` must be
at least 10 characters — generic boilerplate ("see ticket") is rejected
at the Pydantic layer to discourage rubber-stamping.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, cast

from evidence_collector.domain.models import EvidenceException, ExceptionScope
from evidence_collector.parsers._common import (
    ParseError,
    ensure_file,
    load_yaml_or_json,
)

_REQUIRED_FIELDS = (
    "exception_id",
    "control_id",
    "approver",
    "approved_at",
    "expires_at",
    "justification",
)


def _parse_datetime(value: Any, source: Path, field_name: str) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ParseError(
                f"Invalid ISO 8601 datetime in '{field_name}' in {source}: {value}"
            ) from exc
    raise ParseError(f"Unsupported {field_name} type in {source}: {type(value).__name__}")


def parse_exception(path: str | Path) -> EvidenceException:
    resolved = ensure_file(path)
    data = load_yaml_or_json(resolved)

    missing = [key for key in _REQUIRED_FIELDS if not data.get(key)]
    if missing:
        raise ParseError(f"Exception file {resolved} is missing required fields: {missing}")

    raw_scope = data.get("scope") or {}
    if not isinstance(raw_scope, dict):
        raise ParseError(f"Exception scope in {resolved} must be a mapping")
    scope = ExceptionScope(
        application=cast("str | None", raw_scope.get("application")),
        release_id=cast("str | None", raw_scope.get("release_id")),
    )

    try:
        return EvidenceException(
            exception_id=str(data["exception_id"]),
            control_id=str(data["control_id"]),
            approver=str(data["approver"]),
            approved_at=_parse_datetime(data["approved_at"], resolved, "approved_at"),
            expires_at=_parse_datetime(data["expires_at"], resolved, "expires_at"),
            justification=str(data["justification"]).strip(),
            reference=(str(data["reference"]) if data.get("reference") is not None else None),
            scope=scope,
        )
    except ValueError as exc:
        raise ParseError(f"Invalid exception file {resolved}: {exc}") from exc
