# Release notes draft — v1.2.0

This is the human-curated draft for the GitHub Release body when
`v1.2.0` is cut. `release-please` will generate a mechanical changelog
from `feat:`, `fix:`, `docs:`, etc. commits, but the GitHub Release page
itself reads better when a maintainer adds context, screenshots, and an
upgrade note.

**Why minor, not patch.** The hardening pass on the previous branch
(`chore/post-publication-hardening-v1-1-1`) was patch-shaped (cross-OS
SHA fix + dogfood + tooling). On top of it, the Tier 5 branch
(`feat/tier-5-evidence-enrichment`) adds four CLI commands and two
optional fields on `NormalizedEvidence`. New CLI surface is a minor
bump under SemVer, so the first signed public release becomes **v1.2.0**
rather than v1.1.1. The earlier `v1.1.0` cut prepared in code stayed
internal — no signed asset was ever published — so v1.2.0 cleanly
becomes the first signed public release without a confusing gap.

**When to publish.** After all Blocks in
[`EXTERNAL-ACTIONS-2026-05-18.md`](EXTERNAL-ACTIONS-2026-05-18.md) are
green, merge the `release-please--branches--main` PR (which
`release.yml` will then trigger).

> Suggestion: set `"draft": true` in `.github/release-please-config.json`
> for this first signed public release so you can review the auto-built
> GitHub Release page before publishing. Flip back to `false` for
> v1.2.1+.

---

## v1.2.0 — Cross-OS determinism, dogfood refresh, and evidence enrichment

**Release date:** TBD

**Highlights.** First signed public release. Bundles the
post-publication hardening pass (cross-OS structural SHA, dogfood
refresh, tooling reproducibility) with the Tier 5 evidence-enrichment
work (EPSS + KEV intelligence, OpenVEX export, OSCAL Assessment
Results, in-toto Statement wrapper). Bundle schema is fully
backwards-compatible with v1.1.0: every new field is optional with a
safe default.

### Why upgrade

- **Cross-OS reproducibility.** Two CI runners (Linux + Windows)
  hitting `sdlc-evidence verify` on the same bundle now return the same
  digest. Before v1.2.0, the helper baked the host path separator (`\`
  vs `/`) into the hash, so the cross-OS gate was effectively
  decorative.
- **Risk signal beyond CVSS.** New `sdlc-evidence enrich` attaches
  EPSS + CISA KEV intelligence to every CVE the parsers extract from
  scanner output. Only ~2.3 % of CVSS 7+ CVEs are actually exploited;
  EPSS percentile + KEV flag let downstream consumers prioritise
  patching by what attackers really hit.
- **Standards-shaped output.** `sdlc-evidence vex` emits OpenVEX
  0.2.0 (required for EU CRA by September 2026), `sdlc-evidence
  oscal --kind assessment-results` emits OSCAL 1.1.2 Assessment
  Results (required for FedRAMP 20x by September 2026), and
  `sdlc-evidence statement` wraps the bundle as an in-toto Statement
  v1 ready for `cosign attest`. Every consumer that already speaks
  these formats can ingest the collector's output with zero glue
  code.
- **Cleaner local pre-publication gate.** `pre-commit run
  --all-files` now passes all 16 hooks for the first time
  end-to-end. The `mypy` hook was missing six dependencies it needed
  to type-check the CLI and the optional `[api]` extra; `gitleaks`
  was flooding the local gate with 200 false positives from
  third-party SPDX indexes; `semgrep` was exhausting its stack on
  the venv. All fixed.

### Added

- **`sdlc-evidence enrich BUNDLE`** — attaches EPSS + CISA KEV
  intelligence to a bundle. Air-gap friendly: no network in the CLI;
  the user supplies feed files via `--epss-feed` (CSV or .csv.gz) and
  `--kev-feed` (JSON). New `evidence_collector.intelligence` package
  is purely loader + pure function; CI-friendly.
- **`sdlc-evidence vex BUNDLE`** — emits OpenVEX 0.2.0 JSON. Each CVE
  the parsers extracted becomes one VEX statement
  (`under_investigation` by default; `affected` when CISA KEV lists
  it; `not_affected` when a bundle exception covers the current
  application + release).
- **`sdlc-evidence oscal --kind assessment-results --bundle BUNDLE`**
  — renders bundle evaluations as an OSCAL 1.1.2 `assessment-results`
  document. UUIDs are deterministic UUIDv5 across runs.
- **`sdlc-evidence statement BUNDLE`** — wraps the bundle as an
  in-toto Statement v1 with a project-specific predicateType.
  Optional `--dsse-envelope` writes an unsigned DSSE envelope ready
  for `cosign sign-blob`. Signing stays out of the collector — keeping
  private keys out is the right boundary for an audit tool.
- **`evidence[*].cve_ids`** and **`evidence[*].vulnerability_intelligence`**
  on `NormalizedEvidence`. Both optional, defaulting to `[]` and
  `None` respectively, so existing consumers see no behaviour change.
- **`TopRiskCve` and `VulnerabilityIntelligence`** models exposed
  from `evidence_collector.domain.models`.

### Fixed

- `normalize_bundle()` POSIX-normalizes
  `evidence[*].raw.artifact_path` before hashing, so structural
  SHA-256 is identical on Windows and Linux runs.
- `test_bundle_snapshot.py` now passes `artifact_root=repo_root`, so
  recorded paths are repo-relative (not embedding the runner's home
  directory).
- Cross-OS determinism gate job in `.github/workflows/github-ci-cd.yml`
  now consumes the same `structural_sha256()` helper as the CLI and
  the unit tests, so the in-repo helper and the CI gate cannot drift
  apart again.
- Pre-commit `mypy` hook passes explicit `src` target plus missing
  `additional_dependencies` (`typer`, `rich`, `fastapi`, `httpx`,
  `jinja2`, `defusedxml`, `types-defusedxml`).
- Pre-commit `check-json` excludes intentionally-malformed lab SBOMs.
- `.gitleaks.toml` allowlists `.venv*` + cache directories so
  `gitleaks --no-git` does not poison the local gate with third-party
  SPDX indexes.
- `.semgrepignore` ensures `semgrep scan` is reproducible on Windows
  developer machines.
- Ruff version alignment: pre-commit `ruff-pre-commit` `rev:` bumped
  from `v0.6.9` to `v0.9.10` so it matches the constraint CI resolves
  (`ruff>=0.6,<1.0` → 0.9.x). The two versions disagreed on
  multi-line `assert (...), msg` layout.

### Documentation

- `docs/MATURITY_STATUS.md` and `docs/release-readiness.md` refreshed
  with the 2026-05-17 baseline.
- New `docs/MATURITY_ROADMAP.md` Tier 5 section with 15 items, 4 of
  them marked shipped (T5.1, T5.2, T5.3, T5.5).
- `docs/traceability.md §4` lab critical counts corrected from a
  stale "6 missing critical" to the current 4 for most labs / 5 for
  `04-data-batch-lab`.
- New `docs/program/HANDOFF-2026-05-17.md` — session continuity doc.
- New `docs/program/EXTERNAL-ACTIONS-2026-05-18.md` — owner checklist
  for every external action between PR merge and `v1.2.0` tag.
- New `docs/program/RELEASE-NOTES-v1.2.0-draft.md` (this file).
- `examples/self_release/README.md` updated from the v0.1.0 baseline
  (10 met / 12 evidence) to the v1.1.0 baseline (13 met / 13
  evidence).

### Build

- New `make run-self-release` Makefile target.
- `make run-example` now passes `--artifact-root .` so paths in the
  generated bundle are repo-relative.
- New `evidence_collector.intelligence` package shipped as part of
  the wheel; no new optional extras required.

### Internal

- 31 lab/self-release fixtures auto-normalized from CRLF to LF by
  the `mixed-line-ending` pre-commit hook. Content byte-equivalent;
  no scanner findings, SARIF results, or SBOM components were added,
  removed, or modified.
- Snapshot fixture bumped from `34f3025e…` through three intermediate
  values to `7d8b94c781ae46ed1c51a39e528eb2410bf3c51e6477fc1851196863b1989465`
  (the addition of `cve_ids` / `vulnerability_intelligence` changed
  the canonical JSON layout).

### Migration

None. v1.2.0 is fully wire-compatible with v1.1.0:

- All v1.1.0 bundle.json fields are still present and unchanged.
- Two new fields (`cve_ids`, `vulnerability_intelligence`) default
  to `[]` and `None`. Consumers that ignore unknown / null fields
  see the same shape as v1.1.0.
- No CLI flag changed; no command removed.
- No public Python API changed; new symbols (`TopRiskCve`,
  `VulnerabilityIntelligence`, `intelligence` package, `vex`/`intoto`
  exporters) are additive.

If you were relying on the old structural SHA-256
(`34f3025e3791…`), regenerate your baseline once — the new digest
(`7d8b94c781ae…`) is the canonical one going forward.

### Verifying this release

After publish:

```bash
# Wheel
pip download secure-sdlc-evidence-collector==1.2.0

# Cosign signature (keyless, Sigstore Rekor)
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature secure_sdlc_evidence_collector-1.2.0-py3-none-any.whl.sig \
  secure_sdlc_evidence_collector-1.2.0-py3-none-any.whl

# Container (ghcr.io)
docker pull ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:v1.2.0
cosign verify ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:v1.2.0 \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# SBOM (CycloneDX, signed)
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature sbom.cdx.json.sig \
  sbom.cdx.json

# in-toto Statement (NEW in v1.2.0)
sdlc-evidence statement /path/to/bundle.json --output statement.intoto.json
cosign attest --predicate statement.intoto.json --type custom \
  --certificate-identity-regexp '...' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  <subject-ref>
```

### Acknowledgements

This release came out of two structured passes that surfaced
concrete gaps: a 2026-05-17 pre-publication validation pack
(cross-OS issue, dogfood drift, traceability counts) and a 2026-05-18
market scan (EPSS/KEV, EU CRA, FedRAMP 20x, OpenVEX, in-toto).
Validation pack: [`output/publication-2026-05-17/`](../../output/publication-2026-05-17/).
Roadmap with the 11 remaining Tier 5 items:
[`docs/MATURITY_ROADMAP.md`](../MATURITY_ROADMAP.md).
