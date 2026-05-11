# Release readiness checklist

Formal go/no-go criteria for tagging a new public release of the Secure
SDLC Evidence Collector. The project does **not** ship until every
criterion is ticked and the evidence linked below is current.

For turning the private repository public, use the stricter
[public repository readiness gate](./publication-readiness.md), currently
targeted at **2026-06-05**. That gate supersedes the older 2026-05-01
publication target.

**Last local validation pass: 2026-05-10 (post-publication hardening
pass) — 227 tests passing, coverage 87.43 %, `ruff check src tests scripts`
clean, `ruff format --check` clean, `mypy --strict src tests` clean
(61 source files), `actionlint` clean, `gitleaks detect --source .
--no-git --redact` clean, `python -m pip_audit .` clean (project
scope), Trivy `fs --scanners secret,misconfig` clean (Dockerfile 0
misconfigurations), `python -m bandit -r src` clean (0 issues across
3697 LOC), `semgrep scan --config p/security-audit --config p/secrets`
clean (148 rules, 0 findings) after relocating the `# nosemgrep`
suppression to the line where the `from xml.etree.ElementTree import`
statement actually starts in `src/evidence_collector/parsers/junit.py`
(parsing itself remains delegated to `defusedxml`). Sample release
`ready` (coverage 100, confidence 59, 13/13 controls met). Sample
release without `--attestations-dir` `not_ready` with the four
expected missing critical controls (`ORG-CODE-REVIEW`,
`ORG-RELEASE-APPROVAL`, `ORG-REL-ROLLBACK`, `SSDF-PS.2`) and exit
code 2 by design. `compare` of the sample bundle against itself
reports 0 deltas. `oscal` and `schema` exports succeed. Docker daemon
not active in this pass — Docker build remains a release-time
dependency.**

**Re-validation completed on 2026-05-10 (post-publication hardening
pass, branch `chore/post-publication-hardening-v1-1-1`).** The pass
changed the CLI module layout (commands split under `cli/commands/`),
raised `--cov-fail-under` from 70 to 80, added the `sdlc-evidence
verify` command, promoted classification confidence to a first-class
bundle field, added a deterministic `bundle.json` SHA-256 snapshot
test, and inserted `step-security/harden-runner` in all GitHub
Actions Linux jobs (windows runners and the SLSA generator reusable
workflow are documented exclusions). All local gates listed above
were re-run on 2026-05-10 against the branch tip: `pytest` 227
passed, coverage 87.43 % (above the new 80 % floor), `ruff check`
clean, `ruff format --check` clean, `mypy --strict` clean (88 source
files), `actionlint` clean, `python -m bandit -r src` clean, `python
-m pip_audit .` clean (project scope). `gitleaks` and `semgrep` were
not available on the local machine for this pass — both still run as
required checks in `security-ci-cd.yml`. The sample release still
produces `ready 13/13` with structural SHA-256
`34f3025e3791616b4490784cad12b61f3cf208a9f665ae73bfa6bdfa6e16ae93`
(matches `tests/fixtures/sample_release_snapshot.sha256`).

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
