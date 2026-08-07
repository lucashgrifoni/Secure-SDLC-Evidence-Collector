"""Rewriting artifact paths against `--artifact-root`.

The flag exists so a bundle that gets published records repo-relative paths
"instead of leaking local filesystem locations" — its own help text. A leaf
module so both the normalizers and the collector can use one implementation
without either importing the other.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["relative_to_root"]


def relative_to_root(path: Path, root: str | Path | None) -> Path:
    """Return `path` relative to `root`, or `path` unchanged if it is outside it.

    Both sides are resolved to absolute paths first. Without that,
    `Path.relative_to` compares the strings as given and raises `ValueError`
    the moment the two are expressed differently — `--artifact-root .` against
    an absolute artifact path, an absolute root against paths collected from a
    relative `--artifacts-dir`, `..` in either. The old code caught that
    `ValueError` and fell back to the full path, so the flag silently did
    nothing and the bundle shipped `/home/alice/clients/acme/...` while the
    operator believed it had been stripped. A privacy control that fails open
    and says nothing is worse than one that is not there.

    A path genuinely outside the root is still returned unchanged: making it
    relative would produce a `../../..` chain that leaks the same information
    while also being wrong.
    """
    if root is None:
        return path
    try:
        resolved_root = Path(root).expanduser().resolve()
        resolved_path = path.expanduser().resolve()
    except OSError:
        return path
    try:
        return resolved_path.relative_to(resolved_root)
    except ValueError:
        return path
