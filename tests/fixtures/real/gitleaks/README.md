# Gitleaks captures

Written by the Gitleaks 8.30.1 binary on 2026-10-16. Its SARIF reports the
driver `semanticVersion` as `v8.0.0`; that is what Gitleaks writes. The
files are byte for byte what Gitleaks wrote.

```sh
gitleaks detect --no-git --no-banner -s leak -f sarif -r leak.sarif
gitleaks detect --no-git --no-banner -s clean -f sarif -r clean.sarif
```

- `leak.sarif`: `leak/config.py` is one line assigning the public HS256
  example token shown on https://jwt.io (subject `1234567890`, name
  `John Doe`) to `AUTH_TOKEN`. It is a published sample, not a credential.
  Gitleaks exited 1 with one result for rule `jwt`, with no `level`, and
  that rule has no `defaultConfiguration`.
- `clean.sarif`: `clean/app.py` is `print("hello")`. Gitleaks exited 0
  with `results: []`.

Both files list Gitleaks' 222 default rules in `tool.driver.rules`. This
directory is covered by the path allowlist in `.gitleaks.toml`.
