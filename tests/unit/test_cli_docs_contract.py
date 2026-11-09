"""The CLI help and the documentation describe the same interface.

The README and `--help` drifted apart several times: the published wheel
printed `{bundle_path}` and `{before} {after}` while the README said
BUNDLE_PATH and BEFORE AFTER, `bundle --help` called the command a plain alias
of `evaluate` although it lacks six of its options, and `run --help` hid that
`--exceptions-dir` repeats. The JSON-logs page called itself the full list of
events while missing `bundle_built`, the gate event itself.

These tests read the README, docs/json-logs.md and the Click command tree the
CLI really builds, so the next drift fails the suite instead of a user.
"""

from __future__ import annotations

import ast
import inspect
import json
import re
import shutil
from pathlib import Path
from typing import Any

import pytest
import typer
import yaml
from typer.testing import CliRunner

from evidence_collector.cli._errors import report_error
from evidence_collector.cli.main import app

_README = Path("README.md")
_EVENTS_DOC = Path("docs/json-logs.md")
_CLI_PACKAGE = Path("src/evidence_collector/cli")

# Wide enough that no usage line wraps.
_RUNNER = CliRunner(env={"COLUMNS": "200", "NO_COLOR": "1"})


# Typer 0.27 vendors its own Click (typer._click) and older releases use the
# click package, so the command tree is inspected by duck typing, not isinstance.
def _leaf_commands() -> dict[str, Any]:
    """Every runnable command keyed by its path, e.g. ``exceptions list``."""
    leaves: dict[str, Any] = {}

    def walk(group: Any, prefix: str) -> None:
        for name, command in group.commands.items():
            path = f"{prefix}{name}"
            if hasattr(command, "commands"):
                walk(command, f"{path} ")
            else:
                leaves[path] = command

    walk(typer.main.get_command(app), "")
    return leaves


def _options(command: Any) -> list[Any]:
    return [param for param in command.params if param.param_type_name == "option"]


def _readme_synopsis() -> dict[str, list[str]]:
    """Command path -> positional placeholders, from the README's CLI block."""
    text = _README.read_text(encoding="utf-8")
    block = re.search(r"## CLI\n+```\n(.*?)```", text, re.DOTALL)
    assert block, "README.md has no fenced block under '## CLI'"
    commands = set(_leaf_commands())
    synopsis: dict[str, list[str]] = {}
    for line in block.group(1).splitlines():
        words = line.split("#", 1)[0].split()
        if len(words) < 2 or words[0] != "sdlc-evidence" or words[1].startswith("-"):
            continue
        path = " ".join(words[1:3]) if " ".join(words[1:3]) in commands else words[1]
        rest = words[1 + len(path.split()) :]
        placeholders: list[str] = []
        for word in rest:
            if word.startswith(("-", "[")):
                break
            placeholders.append(word)
        synopsis.setdefault(path, placeholders)
    return synopsis


# Typer forces terminal rendering when GITHUB_ACTIONS is set, and reads that at
# import time, so on CI the help carries style codes whatever the runner's env says.
_STYLE_CODE = re.compile(r"\x1b\[[0-9;]*m")


def _help(path: str) -> str:
    result = _RUNNER.invoke(app, [*path.split(), "--help"])
    assert result.exit_code == 0, result.output
    return _STYLE_CODE.sub("", result.output)


def _usage_placeholders(path: str) -> list[str]:
    usage = next(line for line in _help(path).splitlines() if "Usage:" in line)
    after = usage.split("[OPTIONS]", 1)[1].split()
    # Typer 0.27 marks a required argument as {NAME}; older releases print NAME.
    return [word.strip("{}[]") for word in after]


def test_readme_lists_every_command_the_cli_registers() -> None:
    assert set(_readme_synopsis()) == set(_leaf_commands())


@pytest.mark.parametrize("path", sorted(_readme_synopsis()))
def test_readme_argument_names_match_the_help_usage_line(path: str) -> None:
    assert _readme_synopsis()[path] == _usage_placeholders(path), (
        f"README shows `sdlc-evidence {path} {' '.join(_readme_synopsis()[path])}` but "
        f"`{path} --help` shows {_usage_placeholders(path)}"
    )


def _option_names(command: Any) -> set[str]:
    return {
        opt
        for param in _options(command)
        for opt in param.opts
        if opt.startswith("--") and opt != "--help"
    }


def _readme_paragraph(starting_with: str) -> str:
    text = _README.read_text(encoding="utf-8")
    start = text.index(starting_with)
    end = text.index("\n\n", start)
    return " ".join(text[start:end].split())


def test_bundle_help_and_readme_name_every_evaluate_option_bundle_lacks() -> None:
    commands = _leaf_commands()
    missing = _option_names(commands["evaluate"]) - _option_names(commands["bundle"])
    assert missing, "bundle now accepts every evaluate option; update the docs"
    bundle_help = commands["bundle"].help or ""
    readme = _readme_paragraph("`bundle` is a partial alias of `evaluate`")
    for option in sorted(missing):
        assert option in bundle_help, f"bundle --help does not say it lacks {option}"
        assert option in readme, f"README does not say bundle lacks {option}"
    assert "Partial alias" in bundle_help.splitlines()[0]


@pytest.mark.parametrize("path", ["run", "evaluate", "collect"])
def test_repeatable_options_say_so_in_the_help(path: str) -> None:
    repeatable = [param for param in _options(_leaf_commands()[path]) if param.multiple]
    assert repeatable, f"{path} no longer has a repeatable option; drop it from this test"
    for param in repeatable:
        assert "multiple times" in (param.help or ""), (
            f"{path} {param.opts[0]} is repeatable but its help does not say so"
        )


def test_readme_marks_the_repeatable_run_options() -> None:
    text = _README.read_text(encoding="utf-8")
    section = text[text.index("### Ingestion options") : text.index("### GitHub integration")]
    repeatable = [param for param in _options(_leaf_commands()["run"]) if param.multiple]
    assert repeatable, "run no longer has a repeatable option"
    for param in repeatable:
        bullet = re.search(rf"- `{re.escape(param.opts[0])} [^\n]*(?:\n  [^\n]*)*", section)
        assert bullet, f"README has no bullet for {param.opts[0]}"
        assert "repeatable" in bullet.group(0), f"README does not mark {param.opts[0]} repeatable"


def _option_help(path: str, option: str) -> str:
    for param in _options(_leaf_commands()[path]):
        if option in param.opts:
            return str(param.help or "")
    raise AssertionError(f"{path} has no {option}")


def test_catalog_help_is_the_same_on_every_evaluating_command() -> None:
    helps = {path: _option_help(path, "--catalog") for path in ("run", "evaluate", "bundle")}
    assert len(set(helps.values())) == 1, helps


def test_fail_on_ready_caveat_is_in_the_help_and_the_readme() -> None:
    for path in ("run", "evaluate"):
        assert "'ready' is accepted and behaves like conditional" in _option_help(path, "--fail-on")
    readme = _readme_paragraph("- `--fail-on ready|conditional|not_ready`")
    assert "`ready` is accepted and behaves like `conditional`" in readme


def _emitted_events() -> set[str]:
    """Every event name the CLI can print, read from the source with the AST."""
    events = {str(inspect.signature(report_error).parameters["event"].default)}
    for module in sorted(_CLI_PACKAGE.rglob("*.py")):
        for node in ast.walk(ast.parse(module.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
                values: list[ast.expr] = []
                if name == "emit_event" and node.args:
                    values.append(node.args[0])
                values += [kw.value for kw in node.keywords if kw.arg == "event"]
                events.update(
                    v.value
                    for v in values
                    if isinstance(v, ast.Constant) and isinstance(v.value, str)
                )
            elif isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values, strict=True):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "event"
                        and isinstance(value, ast.Constant)
                        and isinstance(value.value, str)
                    ):
                        events.add(value.value)
    return events


def _documented_events() -> set[str]:
    text = _EVENTS_DOC.read_text(encoding="utf-8")
    return set(re.findall(r"^\| `([a-z_]+)` \|", text, re.MULTILINE))


def test_every_emitted_event_is_documented_and_every_documented_event_exists() -> None:
    emitted = _emitted_events()
    documented = _documented_events()
    assert "bundle_built" in emitted, "the AST scan no longer finds the gate event"
    assert emitted - documented == set(), f"undocumented events: {sorted(emitted - documented)}"
    assert documented - emitted == set(), (
        f"documented but never emitted: {sorted(documented - emitted)}"
    )


def test_readme_points_at_the_event_reference() -> None:
    assert "docs/json-logs.md" in _README.read_text(encoding="utf-8")


_REPO_FILE_URL = "https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/"


def _readme_link_targets() -> list[str]:
    return re.findall(r"\]\(([^)\s]+)\)", _README.read_text(encoding="utf-8"))


def test_readme_has_no_relative_link() -> None:
    """README.md is the PyPI description, and PyPI does not resolve relative links."""
    targets = _readme_link_targets()
    assert targets, "README.md has no Markdown link"
    assert [t for t in targets if not t.startswith(("https://", "#", "mailto:"))] == []


def test_readme_links_into_the_repository_name_files_that_exist() -> None:
    paths = [
        target.removeprefix(_REPO_FILE_URL).split("#", 1)[0]
        for target in _readme_link_targets()
        if target.startswith(_REPO_FILE_URL)
    ]
    assert paths, "README.md links no repository file"
    assert [path for path in paths if not Path(path).exists()] == []


def test_readme_states_the_fail_on_default_of_the_action_and_the_gitlab_component() -> None:
    action = yaml.safe_load(Path("action.yml").read_text(encoding="utf-8"))
    component_spec = next(
        yaml.safe_load_all(
            Path("examples/gitlab-component/templates/collect.yml").read_text(encoding="utf-8")
        )
    )
    readme = " ".join(_README.read_text(encoding="utf-8").split())
    action_default = action["inputs"]["fail-on"]["default"]
    component_default = component_spec["spec"]["inputs"]["fail-on"]["default"]
    assert f"GitHub Action (`action.yml`): `fail-on` defaults to `{action_default}`" in readme
    assert (
        "GitLab CI/CD Catalog component (`examples/gitlab-component`): `fail-on` defaults to "
        f"`{component_default}`" in readme
    )


_CATALOG_DATA = Path("src/evidence_collector/controls/data")


def _criticality_by_required_type(catalog: str) -> dict[str, set[str]]:
    from evidence_collector.controls.catalog import load_catalog

    by_type: dict[str, set[str]] = {}
    for control in load_catalog(_CATALOG_DATA / catalog):
        for evidence_type in control.required_evidence_types:
            by_type.setdefault(evidence_type.value, set()).add(control.criticality.value)
    return by_type


def test_readme_names_the_critical_and_high_controls_of_the_default_catalog() -> None:
    """README and limitations §4/§11 say which default gaps block and which do not."""
    by_type = _criticality_by_required_type("catalog.yaml")
    critical = {t for t, levels in by_type.items() if "critical" in levels}
    assert critical == {
        "sbom",
        "code_review",
        "release_approval",
        "rollback_plan",
        "artifact_signature",
    }
    for scanner_or_test in ("sast_scan", "sca_scan", "secrets_scan", "test_result"):
        assert by_type[scanner_or_test] == {"high"}, scanner_or_test


def test_the_cr26_catalog_has_no_critical_control() -> None:
    """The docs say catalog-fedramp-cr26 can never return not_ready."""
    levels = set().union(*_criticality_by_required_type("catalog-fedramp-cr26.yaml").values())
    assert "critical" not in levels


def _run_without_scanner_or_test_output(tmp_path: Path, sample: Path, *extra: str) -> Any:
    """`run` on the sample release with only its SBOM and attestations."""
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    shutil.copy(sample / "artifacts" / "sbom.cdx.json", artifacts)
    return _RUNNER.invoke(
        app,
        [
            "run",
            "--application",
            "payments-api",
            "--repository",
            "acme/payments-api",
            "--release-id",
            "2026.04.10",
            "--commit-sha",
            "abcdef1234567890",
            "--artifacts-dir",
            str(artifacts),
            "--attestations-dir",
            str(sample / "attestations"),
            "--output-dir",
            str(tmp_path / "out"),
            *extra,
        ],
    )


def test_a_release_with_no_scanner_or_test_evidence_passes_the_default_gate(
    tmp_path: Path, sample_release_root: Path
) -> None:
    """README and limitations §4: the critical controls are met, so it is conditional."""
    result = _run_without_scanner_or_test_output(tmp_path, sample_release_root)
    bundle = json.loads((tmp_path / "out" / "bundle.json").read_text(encoding="utf-8"))
    assert bundle["summary"]["release_status"] == "conditional"
    assert result.exit_code == 0, result.output


def test_fail_on_conditional_stops_a_release_with_no_scanner_or_test_evidence(
    tmp_path: Path, sample_release_root: Path
) -> None:
    result = _run_without_scanner_or_test_output(
        tmp_path, sample_release_root, "--fail-on", "conditional"
    )
    assert result.exit_code == 1, result.output


def test_every_adr_is_in_the_adr_index_and_the_site_nav() -> None:
    index = Path("docs/adr/README.md").read_text(encoding="utf-8")
    nav = Path("mkdocs.yml").read_text(encoding="utf-8")
    adrs = sorted(Path("docs/adr").glob("[0-9][0-9][0-9][0-9]-*.md"))
    assert adrs, "no ADR files found"
    for adr in adrs:
        assert f"./{adr.name}" in index, f"docs/adr/README.md does not link {adr.name}"
        assert f"adr/{adr.name}" in nav, f"mkdocs.yml nav does not list {adr.name}"
