# Policy snippets

The repository ships small policy files that read a collector `bundle.json`
directly. They are starting points to copy and adapt, not a complete
enforcement strategy, and they live in the
[`policies/`](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/tree/main/policies)
directory of the repository rather than on this site.

| File | Tool | What it does |
|---|---|---|
| [`rego/release-ready.rego`](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/policies/rego/release-ready.rego) | OPA / conftest | Gates on the bundle summary (`deny` blocks, `warn` flags) |
| [`rego/release-items.rego`](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/policies/rego/release-items.rego) | OPA / conftest | Checks individual waivers and KEV-listed CVEs |
| [`kyverno/require-evidence.yaml`](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/policies/kyverno/require-evidence.yaml) | Kyverno | Admission-time backstop that requires a `secure-sdlc.io/release-status=ready` annotation linked to a bundle SHA-256 |

The Rego files have `conftest verify` tests next to them, and the
`policy-tests.yml` workflow runs those tests and syntax-checks the Kyverno
policy. Usage, the `--namespace release_ready` flag that `conftest test`
needs, and how to raise the default floors are in
[`policies/README.md`](https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/blob/main/policies/README.md).
