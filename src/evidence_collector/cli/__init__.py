"""CLI package.

Kept deliberately empty to avoid importing ``evidence_collector.cli.main``
at package-load time. Importing it here would cause Python to load
``main.py`` twice (once as ``evidence_collector.cli.main`` and once as
``__main__``) when the CLI is invoked via ``python -m
evidence_collector.cli.main``, which triggers a ``RuntimeWarning``.
"""

from __future__ import annotations

__all__: list[str] = []
