# Plugin contract

The Secure SDLC Evidence Collector exposes two extension points so
third-party packages can add parsers and collectors **without forking**.

## Why this exists

Adopters who use proprietary scanners (Veracode, Checkmarx One,
Fortify, Snyk Premium, in-house tools) need to ingest those formats as
first-class evidence. Hard-coding every possible parser into this
project would create churn for everyone; a plugin system pushes that
ownership outward.

## Discovery API

```python
from evidence_collector.plugins import discover_parsers, discover_collectors, list_plugins

parsers = discover_parsers()       # name → callable
collectors = discover_collectors() # name → class
list_plugins()                     # {"parsers": [...], "collectors": [...]}
```

## Extension points

### `evidence_collector.parsers`

Each entry must be a **callable** that:

- accepts a single positional argument: `str | pathlib.Path`
- returns a parsed-artifact dataclass containing at minimum:
  - `artifact: ParsedArtifact`  (see [`parsers/_common.py`](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/src/evidence_collector/parsers/_common.py))
  - format-specific counters (e.g. `total`, `findings_count`)
- raises `evidence_collector.parsers._common.ParseError` for malformed
  input, never a generic `Exception`

The 25 MB safety cap and SHA-256 integrity hashing are applied by
`ensure_file()` and `describe()` from `_common.py`. Plugins should call
those helpers rather than reinventing the safety net.

### `evidence_collector.collectors`

Each entry must be a **class** that:

- accepts keyword-only configuration in `__init__`
- exposes a public `collect()` method returning either:
  - `LocalCollectionReport` (preferred), or
  - any structure with `evidence: list[NormalizedEvidence]` and
    `errors: list[LocalCollectionError]` attributes
- never persists tokens, never logs them, never writes outside the
  caller-provided output directory

## Registering a plugin

In your package's `pyproject.toml`:

```toml
[project.entry-points."evidence_collector.parsers"]
fortify = "my_pkg.parsers.fortify:parse_fortify"
checkmarx = "my_pkg.parsers.checkmarx:parse_checkmarx"

[project.entry-points."evidence_collector.collectors"]
internal_audit_log = "my_pkg.collectors.audit:AuditCollector"
```

After `pip install my_pkg` the names show up in
`sdlc-evidence plugins`. Wiring discovered parsers into the run pipeline
is currently the caller's responsibility (call `discover_parsers()` and
dispatch explicitly). Auto-wiring into `LocalArtifactCollector` is
planned but not in 1.x — track it under T4.1 follow-up in
[`MATURITY_ROADMAP.md`](./MATURITY_ROADMAP.md).

## Versioning the contract

The plugin contract is part of the public surface and follows SemVer:

- a **patch** release of this project will not break a working plugin,
- a **minor** release may add new entry-point groups but not change
  the existing ones,
- a **major** release may rename or remove a group; consumers will get
  a deprecation cycle of at least one minor release before that
  happens.

Plugins should pin their dependency on this project to a major-version
range (e.g. `secure-sdlc-evidence-collector>=1,<2`).
