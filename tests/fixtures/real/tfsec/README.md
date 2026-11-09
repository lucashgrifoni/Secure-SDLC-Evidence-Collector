# tfsec capture

Written by tfsec v1.28.14 from the official image
(`aquasec/tfsec:v1.28.14`, digest
`sha256:ac46d48a384ae2c0bbd0413cd2a18229e45e21a44d22c8be28b56de5b38d74c3`),
offline, on 2026-11-09, over the same `tf/main.tf` as
`../checkov/README.md`. The file is as tfsec wrote it.

```sh
docker run --rm --network none --pull never -v "$PWD:/src" -w /src \
  aquasec/tfsec:v1.28.14 tf --format sarif --out out/tfsec.sarif --no-colour
```

tfsec exited 1. The SARIF driver is named `defsec`, after the library that
formats the report, and not `tfsec`. It has twelve rules with no
`defaultConfiguration` and twelve results, each with its own `level`
(seven `error`, two `warning`, three `note`) and a `ruleIndex`.
