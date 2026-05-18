# Release readiness checklist

Formal go/no-go criteria for tagging a new public release of the Secure
SDLC Evidence Collector. The project does **not** ship until every
criterion is ticked and the evidence linked below is current.

For turning the private repository public, use the stricter
[public repository readiness gate](./publication-readiness.md), currently
targeted at **2026-06-05**. That gate supersedes the older 2026-05-01
publication target.

**Last local validation pass: 2026-05-17 (post-publication hardening
pass v1.1.1) — 233 tests passing, coverage 87.68 %, `ruff check src tests
scripts` clean, `ruff format --check` clean, `mypy --strict src tests`
clean (89 source files — full visibility into `tests/` and the `[api]`
extra), `actionlint` clean across all workflows, `gitleaks detect
--source . --no-git --redact --exit-code 1` clean (`.gitleaks.toml`
extended to allowlist `.venv*` and cache directories so the local
gate is not poisoned by third-party SPDX indexes), `python -m
pip_audit .` clean (project scope), `python -m bandit -r src` clean
(0 issues across 4148 LOC), `semgrep scan --config p/security-audit
--config p/secrets` clean (148 rules across 263 files;
`.semgrepignore` added so semgrep-core does not exhaust its stack on
Windows), `pre-commit run --all-files` clean (all 16 hooks green for
the first time end-to-end after fixing the `mypy` hook's missing
`additional_dependencies` and adding an explicit `src` target).
Sample release `ready` (coverage 100, confidence 59, 13/13 controls
met). Sample release without `--attestations-dir` `not_ready` with
the four expected missing critical controls (`ORG-CODE-REVIEW`,
`ORG-RELEASE-APPROVAL`, `ORG-REL-ROLLBACK`, `SSDF-PS.2`) and exit
code 2 by design. Self-release dogfood (`make run-self-release`)
`ready` (coverage 100, confidence 54, 13/13 met). All 7 labs under
`examples/labs/` produce the expected `not_ready` with exit 2.
Determinism back-to-back: identical SHA. Docker daemon not active in
this pass — Docker build remains a release-time dependency
(unchanged from 2026-05-10). Trivy not installed on the validation
host — still covered as a required check in `security-ci-cd.yml`.**

**Re-validation completed on 2026-05-17 (cross-OS hardening pass,
branch `chore/post-publication-hardening-v1-1-1`).** The headline
change is the **cross-OS structural-SHA fix** in
`src/evidence_collector/application/integrity.py`:
`normalize_bundle()` now POSIX-normalizes
`evidence[*].raw.artifact_path` at hash time so Windows and Linux
runs of the same inputs produce the same digest. The snapshot test
in `tests/integration/test_bundle_snapshot.py` was also updated to
pass `artifact_root=repo_root` to `run_pipeline()`, which rebases
absolute paths to repo-relative form (without this, even with POSIX
normalization the digest would still embed the runner's home
directory). The fixture
`tests/fixtures/sample_release_snapshot.sha256` was bumped from
`34f3025e3791616b4490784cad12b61f3cf208a9f665ae73bfa6bdfa6e16ae93`
to `a42920b3b7b5fcaf676fa7b4a3ec66ed94de82d37f6b0add7584b4ef508c60b2`
(2026-05-17) and again to
`5e1498cdfdca997707c70707b9df558c18383bc064a91a1ced2de962201a5066`
(2026-05-18) after the `mixed-line-ending` pre-commit hook
renormalized the sample-release input fixtures from CRLF to LF (which
changed their `raw.integrity_hash` in the bundle). Both digests were
re-confirmed identical on Windows and Linux-simulated runs. The change is locked
by 6 new unit tests in `tests/unit/test_integrity.py` so a regression
in the helper fails a granular test before the snapshot. The pass
also: (a) regenerated `examples/sample_release/output/*` and
`examples/self_release/output/*` so the committed canonical bundles
match the v1.1.0 schema (now includes the `classification` field
introduced in fase 7); (b) corrected `docs/traceability.md §4` lab
critical counts from a stale "6 missing critical" to the actual 4
missing critical (5 for `04-data-batch-lab`); (c) made the local
gates reproducible by fixing `.gitleaks.toml`, `.semgrepignore`,
`.pre-commit-config.yaml`, and adding `make run-self-release`.
Evidence pack:
[`output/publication-2026-05-17/`](../output/publication-2026-05-17/);
session handoff:
[`docs/program/HANDOFF-2026-05-17.md`](program/HANDOFF-2026-05-17.md).

---

## Quality gates

- [ ] `ruff check src tests scripts` → clean.
- [ ] `ruff format --check src tests scripts` → clean.
- [ ] `mypy --strict src tests` → zero errors.
- [ ] `pytest` → all tests pass and `--cov-fail-under=80` is met.
- [ ] `sdlc-evidence` console script installs from a clean venv
      (`python -m pip install -e ".[dev]"`) on Linux **and** Windows.
- [ ] Docker image builds from `Dockerfile` and runs the sample bundle as a
      non-root user.

## Dogfood gates

- [ ] Sample release (`examples/sample_release/`) produces `release_status =
      ready`, coverage **100**, 13/13 controls met.
- [ ] Self-release (`examples/self_release/`) produces `release_status =
      ready` (or `conditional` with documented recommended-only gaps).
- [ ] Sample release without `--attestations-dir` produces
      `release_status = not_ready` with the expected missing critical
      controls listed in `docs/traceability.md §4`.
- [ ] `sdlc-evidence compare before.json after.json` reports zero deltas
      for two back-to-back runs on the same inputs.

## External-lab evidence

- [ ] Every lab in `examples/labs/` has a recorded `artifacts/` directory
      and an `output/bundle.json`.
- [ ] Each lab's obtained verdict matches the expected verdict in
      `docs/traceability.md §3–§4`.
- [ ] Any drift (expected ≠ obtained) is triaged — either code change,
      catalog change, or documented limitation in `docs/limitations.md`.

## Documentation gates

- [ ] `README.md` claims match implementation (no dead badges, correct
      workflow filenames, correct control count, correct example commands).
- [ ] `CHANGELOG.md` up to date with the tag being released.
- [ ] `docs/bundle_schema.md` matches the current Pydantic schema
      (validated by `sdlc-evidence schema` diff against the committed
      copy).
- [ ] `docs/traceability.md` reflects the current scenarios and verdicts.
- [ ] `docs/limitations.md` lists every known FP/FN and scope exclusion.

## Security gates

- [ ] `security-ci-cd.yml` (Semgrep + pip-audit + Trivy + actionlint)
      passes on the release commit.
- [ ] No hardcoded secrets (`gitleaks` clean, `trivy secret` clean).
- [ ] No local file paths in any tracked file (grep for
      `C:\\Users`, `/home/`, `/Users/` returns zero hits outside
      fixtures explicitly marked as scrubbed).
- [ ] All GitHub workflows use `persist-credentials: false`, least
      privilege `permissions:` blocks, and SHA-pinned third-party
      actions (or explicit tag pins where SHA is not available).
- [ ] Dependabot is green or every open alert has a waiver.

## Release integrity gates

- [ ] `release.yml` signs wheel + sdist + `bundle.json` keyless with
      cosign.
- [ ] `sigstore` transparency-log entries are reachable for the latest
      release (verified with `cosign verify-blob --certificate-identity
      ... --certificate-oidc-issuer https://token.actions.githubusercontent.com`).
- [ ] `SHA256SUMS` published alongside release assets.

## Governance gates

- [ ] `SECURITY.md` reporting address is active.
- [ ] Issue / PR templates render correctly on GitHub.
- [ ] `CODEOWNERS` resolves to an active reviewer.
- [ ] `CONTRIBUTING.md` describes the sign-off, DCO, and test-run
      expectations.
- [ ] `CODE_OF_CONDUCT.md` reference is current.

## Go / no-go

The maintainer signs off the release only when all boxes above are
checked. A failure in any single box blocks the release until the root
cause is either fixed or documented as an accepted limitation in
`docs/limitations.md` with explicit rationale.

---

## How to run this checklist

```bash
# Quality gates
make lint typecheck test

# Dogfood gates
make run-example
python -m evidence_collector.cli.main run \
  --application payments-api --repository acme/payments-api \
  --release-id 2026.04.10 --commit-sha abcdef1234567890 \
  --artifacts-dir examples/sample_release/artifacts \
  --output-dir output/ready-check

python -m evidence_collector.cli.main compare \
  output/ready-check/bundle.json \
  examples/sample_release/output/bundle.json

# External-lab evidence
bash scripts/scan_all_labs.sh

# Security gates (locally, before tagging)
gitleaks detect --source . --redact
trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL .
semgrep scan --config p/security-audit --config p/secrets --error

# Reproducibility (clean container)
docker build -t sdlc-evidence:check . && \
  docker run --rm -v "$PWD/examples/sample_release:/data:ro" \
    sdlc-evidence:check run \
      --application payments-api --repository acme/payments-api \
      --release-id 2026.04.10 --commit-sha abcdef1234567890 \
      --artifacts-dir /data/artifacts --attestations-dir /data/attestations \
      --output-dir /tmp/bundle
```
