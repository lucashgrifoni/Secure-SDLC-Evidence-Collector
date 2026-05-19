# Maintainers

Current maintainer roster for the Secure SDLC Evidence Collector. See
[`GOVERNANCE.md`](./GOVERNANCE.md) for the model and
[`CONTRIBUTING.md`](./CONTRIBUTING.md#becoming-a-maintainer) for the
contributor ladder.

## Active maintainers

| Name | GitHub | Role | Subsystems |
|---|---|---|---|
| Lucas Henrique Grifoni | [@lucashgrifoni](https://github.com/lucashgrifoni) | BDFL / sole maintainer | all |

## Active triagers

None yet. The Triager role activates when the maintainer roster grows
or when an outside contributor sustains the bar described in
[`CONTRIBUTING.md`](./CONTRIBUTING.md#becoming-a-maintainer).

## Past maintainers

None. This section will hold the names of maintainers who have
stepped down, with a date and a one-line note. Adding a maintainer
here is the only intended public step for "stepping down" — there is
no emeritus tier yet.

## Security contact

For private vulnerability reports, follow [`SECURITY.md`](./SECURITY.md).
The maintainer responds within five business days.

## How to reach the maintainer

In order of preference:

1. **Bug, feature, or evidence-model question:** open a GitHub Issue.
2. **Security report:** the channel listed in
   [`SECURITY.md`](./SECURITY.md). Do not file a public Issue first.
3. **Anything else:** GitHub Discussions, once enabled (see
   [`docs/program/EXTERNAL-ACTIONS-2026-05-18.md`](docs/program/EXTERNAL-ACTIONS-2026-05-18.md)
   Block C).

The maintainer does not handle support requests over email, DMs, or
private chats. The visible audit trail is part of the OSS contract.

## Updating this file

Adding, promoting, or removing a maintainer happens in a PR that
the affected person opens (or, if they cannot, that the BDFL opens
on their behalf with a written reason). The PR description names
the qualifying work and links to it. Merge requires:

- the BDFL's approval, and
- (once the roster grows past one) consent from all other active
  maintainers within seven days, or absence of objection.

This file is the authoritative roster. CODEOWNERS in
`.github/CODEOWNERS` should match this list; if it ever drifts,
this file wins and CODEOWNERS gets fixed in the same PR.
