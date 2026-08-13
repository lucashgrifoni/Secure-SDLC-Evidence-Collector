"""Rewriting artifact paths against `--artifact-root`.

The flag exists so a bundle that gets published records repo-relative paths
"instead of leaking local filesystem locations" — its own help text. A leaf
module so both the normalizers and the collector can use one implementation
without either importing the other.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["redact_path_in", "relative_to_root"]


def redact_path_in(message: str, path: Path, relative: Path) -> str:
    """Replace every rendering of `path` in `message` with `relative`.

    Parser and OS errors embed the filename in their own text, so the message
    leaks the absolute path even when the `path` field beside it was rewritten.
    A plain `str.replace` is not enough: `str(OSError)` renders the filename
    through `repr()`, which doubles every backslash, so `C:\\work\\a.json`
    appears in the message as `C:\\\\work\\\\a.json` and never matches. Both
    renderings are substituted, longest first so the doubled form is not
    half-consumed by the plain one.
    """
    if path == relative:
        return message
    renderings = sorted(
        {str(path), str(path).replace("\\", "\\\\")},
        key=len,
        reverse=True,
    )
    replacements = {
        str(path): str(relative),
        str(path).replace("\\", "\\\\"): str(relative).replace("\\", "\\\\"),
    }
    for rendering in renderings:
        message = message.replace(rendering, replacements[rendering])
    return message


def relative_to_root(path: Path, root: str | Path | None) -> Path:
    """Return `path` relative to `root`, or `path` unchanged if it is outside it.

    Two attempts, in this order, because neither alone is correct.

    **Lexically first**, on the paths as they were written. This is what the
    original code did, and it is right whenever the two are expressed
    compatibly — including the case that matters most for privacy: an
    `artifacts/` directory that is a symlink or junction into a shared cache,
    a standard CI layout. Resolving there follows the link out from under the
    root, `relative_to` fails, and the full absolute path ships. Trying
    lexically first also keeps the *link's* name rather than its target, so a
    neutral `artifacts` link over `.internal-clientA-staging` does not publish
    the directory name it was hiding.

    **Resolved second**, when the lexical comparison fails only because the
    two sides are written differently — `--artifact-root .` against paths a
    runner already expanded to absolute, an absolute root against paths
    collected from a relative `--artifacts-dir`, a `..` in either. That
    mismatch used to be swallowed, so the flag silently did nothing and the
    bundle shipped `/home/alice/clients/acme/...` while the operator believed
    it had been stripped. A privacy control that fails open and says nothing is
    worse than one that is not there.

    A path genuinely outside the root is still returned unchanged: making it
    relative would produce a `../../..` chain that leaks the same information
    while also being wrong.
    """
    if root is None:
        return path
    root_path = Path(root).expanduser()
    try:
        return path.expanduser().relative_to(root_path)
    except ValueError:
        pass
    try:
        return path.expanduser().resolve().relative_to(root_path.resolve())
    except (OSError, ValueError):
        return path
