# KICS capture

Written by KICS v2.1.20 from the official image
(`checkmarx/kics:v2.1.20-alpine`), offline, on 2026-10-16, over the same
`tf/main.tf` as `../checkov/README.md`. KICS names its output file
`results.sarif`; it was renamed to `kics.sarif`, content unchanged.

```sh
docker run --rm --network none --pull never -v "$PWD:/path" -w /path \
  checkmarx/kics:v2.1.20-alpine scan -p tf -o out --report-formats sarif \
  --disable-secrets --no-progress --silent
```

KICS exited 50. The SARIF has driver `KICS` and eleven results with no
`level`, each pointing at its rule through `ruleIndex`. The rules carry
`defaultConfiguration.level` `error`, `warning`, `note` or `none`. Six
results have `kind: fail` and five `kind: informational`.
