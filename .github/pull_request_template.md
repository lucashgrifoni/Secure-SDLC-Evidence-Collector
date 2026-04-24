<!--
Thanks for the pull request! A few fast checks before we merge:
-->

## What changed
<!-- One or two bullets describing the change in plain terms. -->

## Why
<!-- Motivation: user story, incident, audit finding, etc. -->

## How was it validated

- [ ] `ruff check src tests`
- [ ] `ruff format --check src tests`
- [ ] `mypy src tests`
- [ ] `pytest`
- [ ] `examples/self_release/` regenerated if control semantics changed

## Impact on public contracts

- [ ] Bundle schema unchanged
- [ ] CLI flags unchanged
- [ ] Environment variable names unchanged
- [ ] Control catalog unchanged

If any box above is unchecked, this is a **breaking change** and needs
a major version bump + migration notes in the PR description.

## Related issues
<!-- Closes #… -->
