"""Documentation claims that can be checked against the repository.

Not a style pass — these are statements a reader can act on, where being wrong
costs them a failed command:

* `docs/index.md` (the published site's Home) taught `cosign verify` against
  `v1.1.0`, a tag that never existed. The tag list jumps v1.0.1 → v2.0.0, PyPI
  has no 1.1.0, and the GitHub Releases API returns 404 for it. All three
  commands failed 100% of the time, on the page whose whole purpose is proving
  the supply chain is verifiable. It also under-claimed: the recipe was written
  in the future tense while nine signed releases already existed.
* `README.md` pinned the pre-commit example at `rev: v2.1.0`, a tag published
  before `.pre-commit-hooks.yaml` existed. `pre-commit` reads the manifest
  right after cloning, so the copy-pasted block raised InvalidManifestError and
  aborted before installing a single hook.

Both failed closed rather than producing a false "verified", which is why they
are documentation bugs and not security ones — but both wasted the reader's
time on the two pages most likely to be a first impression.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from evidence_collector.domain.enums import EvidenceType

_DOCS_INDEX = Path("docs/index.md")
_README = Path("README.md")
_HOOKS_MANIFEST = Path(".pre-commit-hooks.yaml")


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    # `-c safe.directory` so the test still runs on a checkout git considers
    # foreign-owned (common on Windows). Without it every git call fails and
    # the skip below would silently swallow the check.
    return subprocess.run(
        ["git", "-c", f"safe.directory={Path.cwd()}", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _git_is_usable() -> bool:
    return _git("rev-parse", "--git-dir").returncode == 0


def _tag_exists(tag: str) -> bool:
    return _git("rev-parse", "-q", "--verify", f"refs/tags/{tag}").returncode == 0


def test_docs_index_does_not_reference_a_version_that_was_never_released() -> None:
    text = _DOCS_INDEX.read_text(encoding="utf-8")
    assert "1.1.0" not in text, (
        "docs/index.md references 1.1.0, which was never tagged, published to "
        "PyPI, or released on GitHub. The verification recipe on that page must "
        "work against a real artifact."
    )


@pytest.mark.parametrize("path", [_README, _HOOKS_MANIFEST])
def test_pre_commit_pin_points_at_a_tag_that_ships_the_manifest(path: Path) -> None:
    """A `rev:` older than the manifest breaks before installing any hook."""
    if not _git_is_usable():
        pytest.skip("git is not usable here; cannot resolve tags")
    text = path.read_text(encoding="utf-8")
    revs = re.findall(r"rev:\s*(v[0-9]+\.[0-9]+\.[0-9]+)", text)
    assert revs, f"{path} pins no rev — the pre-commit example must pin a tag"
    for rev in revs:
        if not _tag_exists(rev):
            pytest.skip(f"tag {rev} not present in this checkout (shallow clone?)")
        found = _git("cat-file", "-e", f"{rev}:{_HOOKS_MANIFEST.as_posix()}")
        assert found.returncode == 0, (
            f"{path} pins {rev}, but {_HOOKS_MANIFEST} does not exist at that "
            "tag — `pre-commit` fails with InvalidManifestError before "
            "installing any hook."
        )


def test_readme_lists_every_shipped_evidence_type() -> None:
    """The README's enum block drifted six values behind the code.

    It named 15 types while 21 shipped — the five AI types added in T6.5 and
    `iac_scan` added with the native Trivy parser were all missing. A reader
    building a pipeline against that list would conclude the collector cannot
    represent an IaC finding, when it can and does.

    The enum is the single source of truth. This test does not check prose, it
    checks that every shipped value is reachable from the README, so the next
    addition cannot land without the docs following.
    """
    readme = (Path(__file__).resolve().parents[2] / "README.md").read_text(encoding="utf-8")
    missing = [
        evidence_type.value
        for evidence_type in EvidenceType
        if f"`{evidence_type.value}`" not in readme
    ]
    assert not missing, f"README does not mention shipped evidence types: {missing}"
