# `policies/` — ready-to-use admission and CI gate snippets

Ship-along policy files that consume a Secure SDLC Evidence Collector
`bundle.json` directly. Each snippet is small enough to read in a
sitting and intended as a starting point, not as a full enforcement
strategy.

## What lives here

| Directory | Tool | Purpose |
|---|---|---|
| `rego/` | [OPA / conftest](https://www.openpolicyagent.org/) | Pure functions over the bundle JSON. `deny[msg]` blocks the release; `warn[msg]` flags review-worthy state. `release-ready.rego` gates on the summary; `release-items.rego` checks individual waivers and KEV CVEs. Tests via `conftest verify`. |
| `kyverno/` | [Kyverno](https://kyverno.io/) | Admission-time backstop. Requires namespaces (and the workloads inside them) to carry a `secure-sdlc.io/release-status=ready` annotation linked to a bundle SHA-256. |

## Quick start

### Run the Rego policy against a bundle in CI

```bash
# CI gate before tagging
conftest test --policy policies/rego/release-ready.rego output/bundle.json

# With stricter floors
conftest test \
  --policy policies/rego/release-ready.rego \
  --data '{"release_ready":{"thresholds":{"coverage":100,"confidence":70}}}' \
  output/bundle.json
```

### Check individual waivers and KEV CVEs

`release-items.rego` is a separate package, so it only runs when you ask
for its namespace. It denies a waiver whose `expires_at` has passed when
the gate runs, and a CVE that `sdlc-evidence enrich` found in CISA KEV
unless an inline CycloneDX analysis in the bundle marks it `not_affected`
or `false_positive`.

```sh
conftest test --policy policies/rego/ --namespace release_items output/bundle.json
```

Two limits. KEV matches come from the enrichment's top-risk list, which
holds the highest-EPSS CVEs only; a warning names any evidence whose KEV
count is higher than the CVEs it lists. VEX documents passed to
`sdlc-evidence vex --consume` are not stored in the bundle, so they cannot
clear a KEV CVE in this check.

### Verify the policy itself

```bash
conftest verify --policy policies/rego/
```

### Apply the Kyverno policy to a cluster

```bash
kubectl apply -f policies/kyverno/require-evidence.yaml
```

### Test the Kyverno policy locally

```bash
kyverno apply policies/kyverno/require-evidence.yaml \
  --resource <namespace.yaml> \
  --resource <deployment.yaml>
```

## Why these are not opinionated

The collector emits a stable bundle shape; **what counts as a passing
release is your call**, not the tool's. These policies encode the most
common interpretation (`release_status=ready`, no missing critical
evidence, coverage 100, no missing controls). Fork them, tighten or
relax the thresholds, and pin the result in your release pipeline.

## License

Apache-2.0, same as the rest of the project.
