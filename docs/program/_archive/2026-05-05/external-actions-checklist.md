# Checklist de acoes externas para publicacao

Data: 2026-05-05

Estas tarefas dependem de GitHub UI, PyPI UI ou configuracoes de plataforma.
Claude Code/Codex pode orientar e validar, mas nao deve afirmar conclusao sem
evidencia da API/UI.

## GitHub Repository

- [ ] Tornar o repositorio publico quando a publicacao for decidida.
- [ ] Definir description.
- [ ] Definir topics.
- [ ] Confirmar que a licenca aparece como Apache-2.0 apos ajuste do `LICENSE`.
- [ ] Habilitar Discussions, se mantido como requisito Tier 4.
- [ ] Confirmar Issues habilitado.
- [ ] Confirmar GitHub Pages servindo `/` e `/docs/`.

Validacao:

```powershell
gh repo view lucashgrifoni/Secure-SDLC-Evidence-Collector --json visibility,description,repositoryTopics,licenseInfo,hasDiscussionsEnabled,hasIssuesEnabled
Invoke-WebRequest -UseBasicParsing https://lucashgrifoni.github.io/Secure-SDLC-Evidence-Collector/
Invoke-WebRequest -UseBasicParsing https://lucashgrifoni.github.io/Secure-SDLC-Evidence-Collector/docs/
```

## GitHub Actions

- [ ] Confirmar que Actions esta habilitado.
- [ ] Confirmar que workflow runs aparecem na API.
- [ ] Rodar `GitHub CI/CD`.
- [ ] Rodar `Security CI/CD`.
- [ ] Rodar `CodeQL`.
- [ ] Rodar `Deploy GitHub Pages`.
- [ ] Rodar `OpenSSF Scorecard`.
- [ ] Investigar qualquer falha com URL de run/log.

Validacao:

```powershell
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/runs?per_page=20 --jq .
gh run list --repo lucashgrifoni/Secure-SDLC-Evidence-Collector --limit 20
```

Estado validado em 2026-05-05: workflows ativos, mas `workflow_runs=0`.

## GitHub Security

- [ ] Ativar branch protection em `main`.
- [ ] Exigir checks principais antes de merge.
- [ ] Ativar code scanning.
- [ ] Ativar secret scanning, se disponivel.
- [ ] Confirmar Dependabot alerts.
- [ ] Resolver ou documentar PRs Dependabot abertas.

Validacao:

```powershell
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/branches/main/protection --jq .
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/code-scanning/alerts --jq .
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/secret-scanning/alerts --jq .
gh pr list --repo lucashgrifoni/Secure-SDLC-Evidence-Collector --state open
```

Estado validado em 2026-05-05:

- Branch protection ausente.
- Code scanning desabilitado.
- Secret scanning desabilitado.
- 8 PRs Dependabot abertas.

## PyPI

- [ ] Criar projeto `secure-sdlc-evidence-collector` no PyPI.
- [ ] Criar/verificar conta com permissao de maintainer/owner.
- [ ] Configurar Trusted Publisher:
  - Owner: `lucashgrifoni`
  - Repository: `Secure-SDLC-Evidence-Collector`
  - Workflow: `release.yml`
  - Environment: `pypi`
- [ ] Criar GitHub Environment `pypi`.
- [ ] Confirmar que nao ha necessidade de `PYPI_API_TOKEN`.

Validacao:

```powershell
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/environments/pypi --jq .
Invoke-WebRequest -UseBasicParsing https://pypi.org/pypi/secure-sdlc-evidence-collector/json
```

Estado validado em 2026-05-05:

- PyPI retorna 404.
- GitHub environment `pypi` retorna 404.

## GHCR e assinaturas

- [ ] Confirmar que `GITHUB_TOKEN` tem permissao `packages: write` no workflow.
- [ ] Apos release, confirmar imagem em GHCR.
- [ ] Verificar assinatura da imagem com cosign.
- [ ] Verificar `bundle.json`, wheel, sdist e SBOM com cosign.
- [ ] Verificar SLSA provenance.

Validacao pos-release:

```powershell
cosign verify ghcr.io/lucashgrifoni/Secure-SDLC-Evidence-Collector:v1.1.0 `
  --certificate-identity-regexp "https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector" `
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

Observacao:

- So executar apos release real com imagem e assets publicados.
