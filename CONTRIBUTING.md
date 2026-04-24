# Contributing to Secure SDLC Evidence Collector

Thanks for your interest in contributing. This document captures the
minimum bar for a useful PR and how to move through the review cycle
quickly.

## Ground rules

1. Every change must keep the evidence model honest. The tool's value
   comes from auditors trusting its bundles, so schema changes, scoring
   logic, and control semantics need explicit rationale.
2. Public contracts (bundle schema, CLI flags, environment variables)
   are stable once tagged. Breaking them requires a major-version bump
   and documented migration guidance.
3. Security-critical code (parsers, collectors, signing) must stay
   boring: minimal dependencies, no dynamic imports, no silent failures.

## Development setup

```bash
git clone https://github.com/LucasGrifoni/secure-sdlc-evidence-collector
cd secure-sdlc-evidence-collector
python -m venv .venv
source .venv/bin/activate        # PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pre-commit install
```

## Quality gates

Every PR must pass the following locally and in CI:

```bash
ruff check src tests
ruff format --check src tests
mypy src tests
pytest
```

Coverage must stay at 70% or higher (the pytest config fails the run
otherwise). Integration tests under `tests/integration/` exercise the
orchestrator and CLI against `examples/sample_release/`.

## Branch and commit conventions

- Branch names use `type/short-slug`, e.g. `feat/gitlab-collector` or
  `fix/sarif-severity-bucketing`.
- Commits use the conventional-commits prefix (`feat:`, `fix:`, `docs:`,
  `test:`, `chore:`, `ci:`). The history should still read as a story
  after squash.
- Every commit should leave the tree green on all quality gates.

## Pull request checklist

- [ ] The change is scoped to one concern.
- [ ] Tests cover the happy path and the main failure paths.
- [ ] README / CHANGELOG / docs updated where relevant.
- [ ] No secrets, tokens, PII, or internal URLs in examples or fixtures.
- [ ] `examples/self_release/` regenerated if control semantics changed.

## Adding a new parser / normalizer

1. Implement the parser under `src/evidence_collector/parsers/`. The
   parser must return a plain dataclass and refuse malformed inputs via
   `ParseError`.
2. Add a normalizer under `src/evidence_collector/normalizers/` that
   builds a canonical `NormalizedEvidence`.
3. Wire format detection into `collectors/local.py` so end users don't
   have to tell the tool which file is which.
4. Add unit tests with at least one happy path and one malformed input.
5. Document the new evidence type in `docs/bundle_schema.md` and the
   README.

## Adding or changing a control

1. Edit `src/evidence_collector/controls/data/catalog.yaml`. Every
   control must declare `criticality` and at least one
   `required_evidence_types` or `recommended_evidence_types`.
2. Update the relevant integration tests and the self-release README if
   the change affects the dogfood verdict.
3. Document the mapping to NIST SSDF / OWASP SAMM / internal framework.

## Reporting vulnerabilities

See [SECURITY.md](./SECURITY.md). Please do not open public issues for
security-sensitive reports.

## License

By contributing you agree that your contribution is licensed under the
project's Apache-2.0 license.
