"""Environment checks that must keep working on a broken install.

Everything here imports the standard library only. A missing runtime
dependency (``defusedxml``, say) used to crash every command at import time
with a raw traceback, ``doctor`` included, so the one command meant to diagnose
a broken install could never report its own ``Import:`` failures. The CLI entry
point wraps its imports in :func:`exit_on_missing_dependency`, which answers
``doctor`` from here and turns any other command into a one-line error.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Final

CheckResult = tuple[str, bool, str]

# Same value as `cli._exit_codes.EXIT_INPUT_ERROR`, which cannot be imported
# here because that module needs Typer. A test pins the two together.
EXIT_INPUT_ERROR: Final[int] = 3

# Import name -> distribution name, where the two differ.
_DISTRIBUTIONS: Final[dict[str, str]] = {"yaml": "PyYAML"}
_REQUIRED_MODULES: Final[tuple[str, ...]] = (
    "typer",
    "pydantic",
    "jinja2",
    "yaml",
    "httpx",
    "rich",
    "defusedxml",
)
_GLOBAL_FLAGS: Final[frozenset[str]] = frozenset({"-v", "--verbose", "--json-logs", "--version"})


def doctor_checks() -> list[CheckResult]:
    """Run the health checks. Returns (label, ok, detail) per check.

    Pure function so it can be unit-tested without invoking Typer.
    """
    results: list[CheckResult] = []

    # Python version: the package declares requires-python >= 3.12.
    py_ok = sys.version_info >= (3, 12)
    results.append(
        (
            "Python version",
            py_ok,
            f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} "
            f"({'>=3.12' if py_ok else 'requires >=3.12'})",
        )
    )

    # Required runtime dependencies. We import them lazily so a partial
    # install fails loudly instead of crashing every command silently.
    for module in _REQUIRED_MODULES:
        try:
            __import__(module)
            results.append((f"Import: {module}", True, "ok"))
        except ImportError as exc:
            results.append((f"Import: {module}", False, str(exc)))

    # Optional credentials. These are not required for local runs. Without
    # GITHUB_TOKEN, `run --pull-request/--workflow-run` still calls the GitHub
    # API, just unauthenticated. No CLI command collects from GitLab.
    for token_var, label, present_detail, absent_detail in (
        (
            "GITHUB_TOKEN",
            "GitHub token (optional)",
            "present (used by run --pull-request/--workflow-run)",
            "absent (run --pull-request/--workflow-run call the GitHub API "
            "unauthenticated: rate-limited, and private repositories return 404)",
        ),
        (
            "GITLAB_TOKEN",
            "GitLab token (optional)",
            "present (library use only; no CLI command reads it)",
            "absent (only read by the GitLabCollector library API; no CLI command uses it)",
        ),
    ):
        present = bool(os.environ.get(token_var))
        # Optional checks always count as "ok" — we just report status.
        detail = present_detail if present else absent_detail
        results.append((label, True, detail))

    # Schema export sanity. Confirms Pydantic + the bundle model are in
    # a healthy state without writing anything to the user's tree. Imported
    # here, not at module level, so a broken install still gets this far.
    try:
        from evidence_collector.domain.models import EvidenceBundle

        EvidenceBundle.model_json_schema()
        results.append(("Schema export", True, "EvidenceBundle.model_json_schema() ok"))
    except Exception as exc:
        results.append(("Schema export", False, f"{type(exc).__name__}: {exc}"))

    # Write permissions. We never write outside an explicit --output-dir,
    # but it is useful to confirm the user's cwd is writable.
    results.append(("Write permission in cwd", *_cwd_write_check()))

    # Optional cosign — used by the release workflow for keyless signing.
    cosign_path = shutil.which("cosign")
    cosign_detail = cosign_path or "not installed (only needed for signed releases)"
    results.append(("cosign (optional)", True, cosign_detail))

    return results


def _cwd_write_check() -> tuple[bool, str]:
    """Create and remove one uniquely named file in the cwd, exactly once.

    ``tempfile.NamedTemporaryFile`` was used here and hung ``doctor`` forever
    at 100% CPU in a read-only directory on Windows: CPython's tempfile reads a
    PermissionError in a directory that looks writable as a name collision and
    retries with a new name up to TMP_MAX, which is 2**31 - 1 on Windows. One
    ``O_CREAT | O_EXCL`` attempt on a random name answers the same question and
    always returns.
    """
    try:
        cwd = Path.cwd()
        probe = cwd / f".sdlc-evidence-doctor-{uuid.uuid4().hex}.tmp"
        fd = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"
    os.close(fd)
    try:
        os.unlink(probe)
    except OSError as exc:
        return False, f"created {probe.name} but could not remove it: {type(exc).__name__}: {exc}"
    return True, str(cwd)


def doctor_payload(results: list[CheckResult]) -> dict[str, object]:
    """The ``{"checks": [...], "failed": n}`` shape ``doctor`` emits as JSON."""
    return {
        "checks": [{"check": label, "ok": ok, "detail": detail} for label, ok, detail in results],
        "failed": sum(1 for _, ok, _ in results if not ok),
    }


@contextlib.contextmanager
def exit_on_missing_dependency() -> Iterator[None]:
    """Turn a missing third-party module into a clean exit instead of a traceback.

    Wraps the CLI's own imports. ``doctor`` still runs and prints its checks
    (exit 1, as documented); any other command prints one line naming the
    missing package and exits ``EXIT_INPUT_ERROR`` (3). A missing module of
    this package itself is a different bug and is re-raised untouched.
    """
    try:
        yield
    except ModuleNotFoundError as exc:
        module = (exc.name or "").partition(".")[0]
        if not module or module == "evidence_collector":
            raise
        raise SystemExit(_report_missing_dependency(module, exc, sys.argv[1:])) from exc


def _json_logs(argv: list[str]) -> bool:
    return "--json-logs" in argv or os.environ.get("SDLC_JSON_LOGS", "").lower() in {
        "1",
        "true",
        "yes",
    }


def force_utf8_std_streams() -> None:
    """Switch stdout and stderr to UTF-8 so non-ASCII output cannot crash.

    Windows terminals default to cp1252 and fail on Rich's separators or on
    a non-ASCII path in a check detail. The missing-dependency guard exits
    before ``main()`` runs, so it calls this itself.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(OSError, ValueError):
            reconfigure(encoding="utf-8", errors="replace")


def _report_missing_dependency(module: str, exc: ModuleNotFoundError, argv: list[str]) -> int:
    force_utf8_std_streams()
    positional = [arg for arg in argv if arg not in _GLOBAL_FLAGS]
    if positional[:1] == ["doctor"] and not {"--help", "-h"} & set(argv):
        return _plain_doctor(module, exc, argv)
    distribution = _DISTRIBUTIONS.get(module, module)
    message = (
        f"sdlc-evidence: required dependency '{distribution}' is not installed ({exc}). "
        "Reinstall the collector with its dependencies: "
        "pip install --force-reinstall secure-sdlc-evidence-collector"
    )
    if _json_logs(argv):
        event = {"event": "command_failed", "reason": message, "error_type": "ModuleNotFoundError"}
        print(json.dumps(event, ensure_ascii=False, sort_keys=True))
    else:
        print(message, file=sys.stderr)
    return EXIT_INPUT_ERROR


def _plain_doctor(module: str, exc: ModuleNotFoundError, argv: list[str]) -> int:
    """Run ``doctor`` without Typer or Rich, which may be what is missing."""
    results = doctor_checks()
    # Report the module that stopped the CLI unless a failed Import row already
    # names it; an unrelated failure (an unwritable cwd) must not hide it.
    represented = any(
        not ok and label.removeprefix("Import: ").partition(".")[0] == module
        for label, ok, _ in results
        if label.startswith("Import: ")
    )
    if not represented:
        results.append((f"Import: {module}", False, str(exc)))
    payload = doctor_payload(results)
    if _json_logs(argv):
        print(
            json.dumps({"event": "doctor_checked", **payload}, ensure_ascii=False, sort_keys=True)
        )
    elif "--json" in argv:
        print(json.dumps(payload, indent=2))
    else:
        width = max(len(label) for label, _, _ in results)
        print("sdlc-evidence doctor")
        for label, ok, detail in results:
            print(f"{label.ljust(width)}  {'ok' if ok else 'FAIL'}  {detail}")
        print(f"{payload['failed']} required check(s) failed.")
    return 1
