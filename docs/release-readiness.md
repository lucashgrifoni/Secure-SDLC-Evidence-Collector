# Release readiness checklist

Formal go/no-go criteria for tagging a new public release of the Secure
SDLC Evidence Collector. The project does **not** ship until every
criterion is ticked and the evidence linked below is current.

The criteria below are the project's public answer to the 15-criteria
publication gate used for the 2026-05-01 public-repository decision.

**Last validation pass: 2026-04-24 — 114 tests passing, coverage 76%,
ruff + mypy strict clean, local Semgrep/Trivy/Gitleaks/Bandit/pip-audit
clean on runtime deps, 7/7 labs produce the expected `not_ready`
baseline, determinism confirmed on two consecutive runs.**

---

## Quality gates

- [ ] `ruff check src tests` → clean.
- [ ] `ruff format --check src tests` → clean.
- [ ] `mypy --strict src tests` → zero errors.
- [ ] `pytest` → all tests pass and `--cov-fail-under=70` is met.
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
