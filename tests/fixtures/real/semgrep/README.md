# Semgrep captures

Written by Semgrep OSS 1.179.0 from the official image
(`semgrep/semgrep`, image id `93963d9295a3`), offline, on 2026-10-16. The
files are byte for byte what Semgrep wrote.

## semgrep.sarif

```sh
docker run --rm --network none --pull never -v "$PWD:/src" -w /src \
  semgrep/semgrep semgrep scan --metrics off --disable-version-check \
  --config rules.yml --sarif -o semgrep.sarif src
```

Semgrep printed `Ran 2 rules on 1 file: 2 findings.` The SARIF holds three
results with no `level`; the rules carry `defaultConfiguration.level`
`error` (`subprocess-shell-true`) and `warning` (`eval-use`). The third
result is on a `# nosemgrep` line and carries
`suppressions: [{"kind": "inSource"}]`.

`rules.yml`:

```yaml
rules:
  - id: subprocess-shell-true
    languages: [python]
    severity: ERROR
    message: subprocess call with shell=True
    pattern: subprocess.run(..., shell=True, ...)
  - id: eval-use
    languages: [python]
    severity: WARNING
    message: use of eval
    pattern: eval(...)
```

`src/app.py`:

```python
import subprocess


def run(cmd):
    subprocess.run(cmd, shell=True)


def calc(expr):
    return eval(expr)


def legacy(cmd):
    subprocess.run(cmd, shell=True)  # nosemgrep
```

## rule-error.sarif

Same command and source, with a rule whose pattern does not parse:

```yaml
rules:
  - id: broken
    languages: [python]
    severity: ERROR
    message: broken rule
    pattern: subprocess.run(
```

Semgrep exited 2 and wrote `executionSuccessful: true`, an error-level
`toolExecutionNotifications` entry (`Rule parse error`), no rules and no
results.
