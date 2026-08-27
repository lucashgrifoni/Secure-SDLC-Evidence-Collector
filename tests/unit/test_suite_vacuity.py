"""The suite checks itself for tests that can pass without testing anything.

Four were found by hand during one audit pass, all of them green the whole time:

* a plugin guard that built a cwd-relative path, so it scanned nothing when
  pytest ran from anywhere else;
* a tag-format guard anchored only at the start, which accepted the very
  injection payload it was written to reject;
* a verdict-degrade test whose single meaningful assertion sat behind an `if`
  that never ran, passing on an `else` that restated its own premise;
* a cap test named for a 25 MB boundary that padded only `if remaining <
  64 * 1024` — always false — and so asserted on a two-byte file.

A count of passing tests is not evidence of coverage. These are the shapes that
let a test pass vacuously and that a machine can find, so the suite looks for
them on every run instead of waiting for the next audit.

Not everything vacuous is mechanical: a test can assert the wrong thing, or the
right thing about the wrong input, and still look perfect here. This closes the
cheap half.
"""

from __future__ import annotations

import ast
from pathlib import Path

import evidence_collector

TESTS_ROOT = Path(evidence_collector.__file__).resolve().parents[2] / "tests"

# Tests whose body legitimately has no `assert` and no `pytest.raises`, because
# the call completing at all is the claim. Each entry needs a reason: adding one
# is a decision a reviewer can see, which is the point.
NO_ASSERT_ALLOWED: dict[str, str] = {}


def _test_functions() -> list[tuple[Path, ast.FunctionDef | ast.AsyncFunctionDef]]:
    found: list[tuple[Path, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    for path in sorted(TESTS_ROOT.rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name.startswith(
                "test_"
            ):
                found.append((path, node))
    return found


def _identify(path: Path, node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    return f"{path.relative_to(TESTS_ROOT.parent).as_posix()}::{node.name}"


def _asserts(node: ast.AST) -> list[ast.Assert]:
    return [n for n in ast.walk(node) if isinstance(n, ast.Assert)]


def _has_raising_context(node: ast.AST) -> bool:
    """`pytest.raises` / `pytest.warns` / mock `assert_called*` count as claims."""
    for inner in ast.walk(node):
        if isinstance(inner, ast.With | ast.AsyncWith):
            for item in inner.items:
                if any(
                    marker in ast.unparse(item.context_expr)
                    for marker in ("raises", "warns", "deprecated_call")
                ):
                    return True
        if isinstance(inner, ast.Call) and ".assert_" in ast.unparse(inner.func):
            return True
    return False


def _parametrized_names(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    names: list[str] = []
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call) or "parametrize" not in ast.unparse(decorator.func):
            continue
        if not decorator.args:
            continue
        target = decorator.args[0]
        if isinstance(target, ast.Constant) and isinstance(target.value, str):
            names += [part.strip() for part in target.value.split(",") if part.strip()]
        elif isinstance(target, ast.Tuple | ast.List):
            names += [
                element.value.strip()
                for element in target.elts
                if isinstance(element, ast.Constant) and isinstance(element.value, str)
            ]
    return names


def test_the_scanner_can_see_the_suite() -> None:
    """Guards the guard: a path mistake here would silently pass everything.

    Resolved from the installed package rather than the working directory,
    because a cwd-relative path is exactly how one of the tests above came to
    scan an empty directory and pass.
    """
    functions = _test_functions()
    assert len(functions) > 500, f"only {len(functions)} tests discovered under {TESTS_ROOT}"


def test_no_test_is_parametrized_over_an_argument_it_ignores() -> None:
    """An unused parametrize argument runs the same assertion N times.

    It reads as N cases in the output and is one case in fact, so a reviewer
    counting coverage is counting something that is not there.
    """
    offenders: list[str] = []
    for path, node in _test_functions():
        names = _parametrized_names(node)
        if not names:
            continue
        used = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
        used |= {n.arg for n in ast.walk(node) if isinstance(n, ast.arg)} - {
            a.arg for a in node.args.args
        }
        referenced = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
        unused = [name for name in names if name not in referenced]
        if unused:
            offenders.append(f"{_identify(path, node)} ignores {', '.join(unused)}")
    assert offenders == [], "parametrized over arguments they never use:\n  " + "\n  ".join(
        offenders
    )


def test_no_test_hides_all_of_its_assertions_behind_a_branch() -> None:
    """If every assertion sits inside an `if`, a false condition tests nothing.

    The condition is usually a fact about the fixture rather than the behaviour
    under test, so it can turn false silently — which is what happened when a
    catalog grew and a `ready` baseline quietly became `not_ready`.
    """
    offenders: list[str] = []
    for path, node in _test_functions():
        assertions = _asserts(node)
        if not assertions:
            continue
        guarded = {
            id(assertion)
            for branch in ast.walk(node)
            if isinstance(branch, ast.If)
            for assertion in _asserts(branch)
        }
        if all(id(assertion) in guarded for assertion in assertions):
            offenders.append(_identify(path, node))
    assert offenders == [], "every assertion is behind a condition:\n  " + "\n  ".join(offenders)


def test_every_test_makes_a_claim() -> None:
    """No `assert`, no `pytest.raises`, no mock assertion — nothing is checked.

    A test whose only claim is "this call did not raise" is legitimate, and it
    belongs in `NO_ASSERT_ALLOWED` with a reason, so the exemption is a visible
    decision rather than an oversight.
    """
    offenders = [
        _identify(path, node)
        for path, node in _test_functions()
        if not _asserts(node)
        and not _has_raising_context(node)
        and _identify(path, node) not in NO_ASSERT_ALLOWED
    ]
    assert offenders == [], "assert nothing:\n  " + "\n  ".join(offenders)
