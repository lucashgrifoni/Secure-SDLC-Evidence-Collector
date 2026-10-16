# Trivy captures

Written by Trivy 0.74.0 on 2026-10-16, offline, secret scanner only. The
files are byte for byte what Trivy wrote.

```sh
trivy fs --offline-scan --skip-db-update --scanners secret --format json -o clean.json empty
trivy fs --offline-scan --skip-db-update --scanners secret --format json -o secret.json leak
```

- `clean.json`: `empty` is an empty directory. Trivy wrote
  `SchemaVersion`, `Trivy`, `ReportID`, `CreatedAt`, `ArtifactName` and
  `ArtifactType`, and no `Results` key.
- `secret.json`: `leak/config.py` assigns the public jwt.io example token
  (see `../gitleaks/README.md`). Trivy reported one `jwt-token` secret with
  severity `MEDIUM` and masked the value in the report.
