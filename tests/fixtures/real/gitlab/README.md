# GitLab Security Report captures

Written on 2026-11-13 by GitLab's public analyzer images, run locally with
Docker 29.9.3 on Windows (Linux containers). The images were pulled from
`registry.gitlab.com/security-products/` at the major tags GitLab's CI
templates use. Apart from the one redaction below, every file is byte for
byte what the analyzer wrote.

The sample code is small and written for these captures:

- `sample/app/app.py`: `subprocess.call(cmd, shell=True)`, `hashlib.md5` and
  `eval(expression)`.
- `sample/app/settings.py`: one line assigning a randomly generated value in
  the shape of a GitLab personal access token. It never was a credential.
- `sample/requirements.txt`: `requests==2.19.0` and `pyyaml==5.3`.
- `clean/app.py`: a two-line function with nothing to report.

Each analyzer ran with the project mounted at `/code` and
`CI_PROJECT_DIR=/code`, as a GitLab job runs it.

| File | Image | Analyzer and scanner | Command |
|---|---|---|---|
| `gl-sast-report.json` | `semgrep:6` | semgrep 6.33.0, Semgrep 1.185.0 | `docker run --rm -v <sample>:/code -e CI_PROJECT_DIR=/code -w /code registry.gitlab.com/security-products/semgrep:6 /analyzer run` |
| `gl-sast-report-clean.json` | `semgrep:6` | same | same command on `clean/` |
| `gl-secret-detection-report.json` | `secrets:7` | secrets 7.43.0, Gitleaks 8.30.1 | `docker run --rm -v <sample>:/code -e CI_PROJECT_DIR=/code -w /code registry.gitlab.com/security-products/secrets:7 /analyzer run` |
| `gl-secret-detection-report-clean.json` | `secrets:7` | same | same command on `clean/` |
| `gl-dependency-scanning-report.json` | `gemnasium-python:6` | gemnasium-python 6.6.5 | `docker run --rm -v <deps>:/code -e CI_PROJECT_DIR=/code -w /code registry.gitlab.com/security-products/gemnasium-python:6 /analyzer run` (`<deps>` holds only `requirements.txt`) |
| `gl-container-scanning-report.json` | `container-scanning:8` | gcs 8.7.1, Trivy 0.76.0 | `docker run --rm -e CS_IMAGE=docker.io/library/alpine:3.14.0 -e CI_PROJECT_DIR=/code -v <out>:/code -w /code registry.gitlab.com/security-products/container-scanning:8 gtcs scan` |
| `gl-container-scanning-report-clean.json` | `container-scanning:8` | same | same command with `CS_IMAGE=cgr.dev/chainguard/static:latest` |
| `gl-dast-report.json` | `dast:6` | browserker 6.43.0 | `docker run --rm --network <net> -e DAST_TARGET_URL=http://glweb:8000 -e CI_PROJECT_DIR=/output -v <out>:/output -w /output registry.gitlab.com/security-products/dast:6 /analyze` |

Image digests at capture time:

- `semgrep:6` `sha256:c0edbc4277c50b95a52a6e3661e1d5c7720e38e8f35c43ff4e6ba93b1d0a659c`
- `secrets:7` `sha256:1945637ddbbda5373a7186991d2674987231fe74b22a7a4341f84ac799281833`
- `gemnasium-python:6` `sha256:17c210a236fc1d5e469aff41868283e75df2914f886eb88ae3a3de31a7d87309`
- `container-scanning:8` `sha256:bb16d1dd1ff9b9f65244b50fb952bb4c4cfea733a31310f141b27e0fb83fa7c2`
- `dast:6` `sha256:0f8bdb93adbeac9156fa6b5190b40179e0dc4eaddbf2defde847aa13a5afb4a3`

What each run reported:

- SAST: schema 15.2.4, `scan.status` `success`, two High (`bandit.B307`
  eval, `bandit.B602` shell) and one Medium (`bandit.B303-1` MD5). The
  `cve` field of each finding is a location key, not a CVE.
- Secret detection: schema 15.2.4, one Critical finding for rule
  `gitlab_personal_access_token`. The clean run has `vulnerabilities: []`.
- Dependency scanning: schema 15.2.2, 2 Critical, 6 High and 13 Medium,
  with identifiers typed `gemnasium`, `cve` and `ghsa`.
- Container scanning: schema 15.1.1, 4 Critical, 34 High and 10 Medium for
  `alpine:3.14.0`; each finding names the image in `location.image`. The
  Chainguard static image gave `vulnerabilities: []`.
- DAST: schema 15.0.6, two Low and one Info against a local
  `python -m http.server` serving two static pages from a container named
  `glweb`.

Redaction: in `gl-secret-detection-report.json` the token value in
`raw_source_code_extract` was replaced with `glpat-REDACTED`. Nothing else
in that file was changed. The `cve` field keeps the analyzer's hash.

Not captured: a report with `scan.status: failure`. A DAST run against a
host that does not resolve exited 1 and wrote no report at all, so the
failure tests change that one field in a real capture and say so.

This directory is covered by the path allowlist in `.gitleaks.toml`.
