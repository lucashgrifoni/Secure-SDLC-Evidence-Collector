# Release notes draft — v1.1.1

This is the human-curated draft for the GitHub Release body when
`v1.1.1` is cut. `release-please` will generate a mechanical changelog
from `fix:`, `feat:`, `docs:`, etc. commits, but the GitHub Release page
itself reads better when a maintainer adds context, screenshots, and an
upgrade note.

**When to publish.** After all Blocks in
[`EXTERNAL-ACTIONS-2026-05-18.md`](EXTERNAL-ACTIONS-2026-05-18.md) are
green, merge the `release-please--branches--main` PR (which `release.yml`
will then trigger).

> Suggestion: set `"draft": true` in `.github/release-please-config.json`
> for this first signed public release so you can review the auto-built
> GitHub Release page before publishing. Flip back to `false` for
> v1.1.2+.

---

## v1.1.1 — Cross-OS determinism and dogfood refresh

**Release date:** TBD (after `v1.1.0` is published)

**Highlights.** First post-publication hardening cut. No behavior or
schema change for end users — every output a `v1.1.0` consumer was
parsing still parses identically. The change is internal: the structural
SHA-256 of `bundle.json` is now stable across Linux and Windows runners,
which closes the only documented limitation of the determinism gate.

### Why upgrade

- **Cross-OS reproducibility.** Two CI runners (Linux + Windows) hitting
  `sdlc-evidence verify` on the same bundle now return the same digest.
  Before v1.1.1, the helper baked the host path separator (`\` vs `/`)
  into the hash, so the cross-OS gate was effectively decorative.
  Locked by the new `tests/unit/test_integrity.py` (6 tests) and the
  CI `Cross-OS determinism gate` job (which now consumes the same helper
  as the CLI and the unit tests instead of an inline copy).
- **Dogfood that actually proves what we claim.** `examples/self_release/`
  bundle was last regenerated in early May and shipped the v1.0.1 schema
  shape (no `classification` field). After v1.1.1 the dogfood is
  regenerated against the same schema the runtime emits, with a new
  `make run-self-release` target so contributors don't have to remember
  the 9-argument invocation.
- **Cleaner local pre-publication gate.** `pre-commit run --all-files`
  now passes all 16 hooks for the first time end-to-end. Before, the
  `mypy` hook was missing six dependencies it needed to type-check the
  CLI and the optional `[api]` extra, and `gitleaks` was flooding the
  local gate with 200 false positives from third-party SPDX indexes.

### Fixed

- `normalize_bundle()` now POSIX-normalizes
  `evidence[*].raw.artifact_path` at hash time, so the structural
  SHA-256 is identical on Windows and Linux runs. The bundle written
  to disk is unchanged; only the hash-time view sees normalized paths.
- `tests/integration/test_bundle_snapshot.py` now passes
  `artifact_root=repo_root` to `run_pipeline()` so the recorded path is
  repo-relative rather than embedding the runner's home directory.
- `Cross-OS determinism gate` CI job no longer reimplements bundle
  normalization inline — it calls
  `evidence_collector.application.integrity.structural_sha256()`, so
  the in-repo helper and the gate cannot drift apart.
- `tests/fixtures/sample_release_snapshot.sha256` bumped to
  `5e1498cdfdca997707c70707b9df558c18383bc064a91a1ced2de962201a5066`.
- `docs/traceability.md §4` lab critical counts corrected from a stale
  "6 missing critical" to the current 4 for most labs / 5 for
  `04-data-batch-lab`.
- Pre-commit `mypy` hook now passes an explicit `src` target plus the
  missing `additional_dependencies` (`typer`, `rich`, `fastapi`,
  `httpx`, `jinja2`, `defusedxml`, `types-defusedxml`). Pre-commit
  `check-json` excludes intentionally-malformed lab SBOMs.
- Ruff version alignment: pre-commit ruff `rev:` bumped from `v0.6.9`
  to `v0.9.10` so it matches the constraint CI resolves (`ruff>=0.6,<1.0`
  picks 0.9.x). The two ruff versions disagreed on multi-line
  `assert (...), msg` layout.

### Documentation

- `docs/MATURITY_STATUS.md` and `docs/release-readiness.md` refreshed
  with the 2026-05-17 baseline (233 tests, 87.68 % coverage, mypy strict
  89 source files).
- New `docs/program/HANDOFF-2026-05-17.md` — session continuity doc.
- New `docs/program/EXTERNAL-ACTIONS-2026-05-18.md` — owner checklist
  for every external action between PR merge and `v1.1.1` tag.
- New `docs/program/RELEASE-NOTES-v1.1.1-draft.md` (this file).
- `examples/self_release/README.md` updated from v0.1.0 baseline (10
  met / 12 evidence) to v1.1.0 baseline (13 met / 13 evidence).

### Build

- New `make run-self-release` Makefile target.
- `make run-example` now passes `--artifact-root .` so paths in the
  generated bundle are repo-relative.
- `.gitleaks.toml` allowlist extended to `.venv*` and the usual cache
  directories.
- New `.semgrepignore` so `semgrep scan` is reproducible on Windows
  developer machines.

### Internal

31 lab/self-release fixtures auto-normalized from CRLF to LF by the
`mixed-line-ending` pre-commit hook. Content byte-equivalent; no scanner
findings, SARIF results, or SBOM components were added, removed, or
modified.

### Migration

None. v1.1.1 is fully wire-compatible with v1.1.0:

- The `bundle.json` schema did not change.
- No CLI flag changed.
- No public Python API changed.

If you were relying on the old structural SHA-256
(`34f3025e3791…`), regenerate your baseline once — the new digest
(`5e1498cdfdca…`) is the canonical one going forward.

### Verifying this release

After publish:

```bash
# Wheel
pip download secure-sdlc-evidence-collector==1.1.1

# Cosign signature (keyless, Sigstore Rekor)
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature secure_sdlc_evidence_collector-1.1.1-py3-none-any.whl.sig \
  secure_sdlc_evidence_collector-1.1.1-py3-none-any.whl

# Container (ghcr.io)
docker pull ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:v1.1.1
cosign verify ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:v1.1.1 \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# SBOM (CycloneDX, signed)
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature sbom.cdx.json.sig \
  sbom.cdx.json
```

### Acknowledgements

This release came out of a structured pre-publication validation pass
that surfaced the cross-OS issue. Validation pack:
[`output/publication-2026-05-17/`](../../output/publication-2026-05-17/).
