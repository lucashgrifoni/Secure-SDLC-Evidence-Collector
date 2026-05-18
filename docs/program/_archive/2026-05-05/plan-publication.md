# Plano de acao para publicacao v1.1.0

Data: 2026-05-05
Status inicial: `NO-GO`
Release alvo recomendada: `v1.1.0`

## Principios de execucao

1. Nao mover tags existentes.
2. Nao reescrever historico.
3. Nao apagar mudancas locais sem decisao explicita.
4. Nao afirmar que scanner, CI, release, assinatura ou publish passou sem evidencia.
5. Separar pendencias de codigo de pendencias externas.
6. Preservar arquivos ja existentes em `melhorias/`.
7. Trabalhar em branch `codex/release-readiness-v1.1.0`, se possivel.
8. Se o worktree sujo impedir troca de branch segura, parar e reportar.

## Fase 0 - Congelar estado e proteger trabalho local

Objetivo: evitar perda de trabalho e estabelecer baseline confiavel.

Tarefas:

- Rodar `git status --short --branch`.
- Rodar `git diff --name-status` e `git diff --stat`.
- Identificar quais mudancas locais devem ser mantidas.
- Nao descartar `Plano de acao e execucao - Claude.md` sem decisao explicita; hoje ele aparece deletado localmente.
- Nao sobrescrever `melhorias/plano-acao-maturidade-higiene-codex-gpt-5-2026-05-05.md`.
- Nao sobrescrever `melhorias/prompt-cursor-maturidade-higiene-codex-gpt-5-2026-05-05.md`.

Aceite:

- Estado inicial documentado.
- Nenhum arquivo de usuario revertido ou removido sem aprovacao.

## Fase 1 - Higiende do worktree e gates locais

Objetivo: deixar o repo local internamente consistente antes de mexer em release.

Tarefas:

- Corrigir a formatacao de `scripts/scrub_lab_artifacts.py`.
- Confirmar se as mudancas ja existentes em README, CHANGELOG, Dockerfile, Makefile, workflow e docs devem ser mantidas.
- Se mantidas, garantir que elas passem nos gates.
- Se alguma mudanca for removida, justificar e preservar o que for de usuario.

Comandos obrigatorios:

```powershell
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src tests
python -m pytest
$exe = Join-Path $HOME '.local\bin\actionlint.exe'; $files = Get-ChildItem .github\workflows -File -Include *.yml,*.yaml | ForEach-Object { $_.FullName }; & $exe @files
python -m pip_audit .
gitleaks detect --source . --redact --verbose
trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --skip-dirs .git --skip-dirs .mypy_cache --skip-dirs .pytest_cache --skip-dirs .ruff_cache --skip-dirs build --skip-dirs output .
```

Aceite:

- Todos os comandos acima passam ou qualquer indisponibilidade fica documentada com causa objetiva.
- Nao ha claim em docs que contradiga os comandos executados.

## Fase 2 - Corrigir identidade publica do repositorio

Objetivo: alinhar package metadata, docs e action com o repo real.

Tarefas:

- Substituir URLs antigas `https://github.com/LucasGrifoni/secure-sdlc-evidence-collector` por `https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector` onde for link para o repo atual.
- Atualizar `pyproject.toml` URLs.
- Atualizar `action.yml` install fallback para o repo real.
- Atualizar Dockerfile `org.opencontainers.image.source`.
- Atualizar `CONTRIBUTING.md`, issue templates, `docs/github_action.md` e docs relacionadas.
- Revisar CODEOWNERS/Dependabot reviewer: GitHub e case-insensitive, mas usar `@lucashgrifoni` se o objetivo for padronizacao.

Aceite:

- `Select-String` nao encontra mais os links antigos fora de contexto historico explicitamente documentado.
- README e docs apontam para o mesmo owner/repo do remoto.

## Fase 3 - Corrigir licenca e metadata GitHub

Objetivo: fazer GitHub detectar Apache-2.0 e preparar a pagina publica.

Tarefas de codigo:

- Revisar `LICENSE`. Hoje GitHub detecta `Other`.
- Trocar para o texto canonico completo Apache License 2.0, preservando copyright.
- Ajustar `pyproject.toml` para metadata moderna, preferencialmente `license = "Apache-2.0"` ou `license-files`, conforme suporte do setuptools usado.
- Avaliar remocao ou ajuste do classifier de licenca se ele gerar warning de build.

Tarefas via GitHub/API:

- Definir description.
- Definir topics.

Sugestao de description:

```text
CLI and GitHub Action to collect, normalize, evaluate, and bundle Secure SDLC release evidence.
```

Sugestao de topics:

```text
appsec, devsecops, secure-sdlc, ssdf, evidence, release-readiness, sarif, sbom, sigstore, compliance
```

Aceite:

- `gh repo view ... --json licenseInfo,description,repositoryTopics` mostra licenca Apache-2.0, description preenchida e topics.
- `python -m build --sdist --wheel` nao gera warning critico de metadata de licenca, ou o warning fica documentado como nao bloqueante.

## Fase 4 - Ajustar claims publicos de supply chain

Objetivo: docs nao devem prometer artefatos assinados/publicados antes da primeira release assinada existir.

Tarefas:

- Revisar README, `docs/index.md`, `docs/MATURITY_STATUS.md`, `docs/release-readiness.md`.
- Trocar afirmacoes absolutas como "signed/published" por "configured in release workflow" quando ainda nao houver artefato publico.
- Manter claims fortes apenas apos release real com assets e verificacao.
- Incluir `docs/plugins.md` no `mkdocs.yml` nav.
- Corrigir promessa de SPDX em `release.yml`: gerar SPDX de fato ou remover comentario/promessa.

Aceite:

- Docs distinguem `configurado`, `validado localmente`, `publicado` e `verificado`.
- `python -m mkdocs build --strict` passa sem pagina fora do nav.

## Fase 5 - Versionamento v1.1.0

Objetivo: preparar release atual sem adulterar `v1.0.1`.

Tarefas:

- Atualizar `pyproject.toml` de `1.0.1` para `1.1.0`.
- Atualizar `src/evidence_collector/__init__.py` para `1.1.0`.
- Atualizar README badge release para `v1.1.0`.
- Atualizar `CHANGELOG.md` com entrada `1.1.0` datada no dia do release.
- Atualizar `.github/.release-please-manifest.json` se a decisao for manter release-please alinhado.
- Garantir que a narrativa diga que `v1.1.0` incorpora Tier 1-4.

Aceite:

- `python -m evidence_collector.cli.main --version` retorna `1.1.0`.
- Build wheel/sdist gera `secure_sdlc_evidence_collector-1.1.0`.
- Nenhum arquivo publico continua sugerindo que o HEAD atual e `v1.0.1`.

## Fase 6 - Acoes externas obrigatorias

Objetivo: preparar plataformas antes de tag/release.

Tarefas externas:

- Tornar repo publico quando o dono decidir publicar.
- Habilitar GitHub Actions e confirmar que workflow runs aparecem.
- Habilitar branch protection em `main`.
- Habilitar code scanning.
- Habilitar secret scanning, se disponivel no plano/visibilidade do repo.
- Habilitar GitHub Discussions, se continuar como meta Tier 4.
- Criar GitHub environment `pypi`.
- Criar projeto `secure-sdlc-evidence-collector` no PyPI.
- Configurar PyPI Trusted Publisher:
  - Owner: `lucashgrifoni`
  - Repository: `Secure-SDLC-Evidence-Collector`
  - Workflow: `release.yml`
  - Environment: `pypi`

Aceite:

- `gh api .../branches/main/protection` nao retorna 404.
- `gh api .../environments/pypi` nao retorna 404.
- `https://pypi.org/pypi/secure-sdlc-evidence-collector/json` deixa de retornar 404 apos publish.

## Fase 7 - Validar GitHub Actions remoto

Objetivo: substituir "CI local verde" por evidencia remota.

Tarefas:

- Rodar workflows manualmente quando aplicavel:
  - GitHub CI/CD.
  - Security CI/CD.
  - CodeQL.
  - Deploy GitHub Pages.
  - OpenSSF Scorecard.
- Se `gh run list` continuar vazio, investigar GitHub Settings > Actions.
- Nao afirmar CodeQL failure sem link de run/log.
- Se houver falha real, corrigir a causa e registrar o run.

Aceite:

- `gh api repos/.../actions/runs?per_page=20` retorna runs.
- Runs principais concluem com `success`.
- README badges podem apontar para badges reais de workflow.

## Fase 8 - Tratar Dependabot

Objetivo: reduzir risco antes de release publica.

Tarefas:

- Avaliar 8 PRs abertas.
- Agrupar por ecossistema: GitHub Actions, pip runtime/dev.
- Para cada PR:
  - revisar changelog/release notes quando relevante;
  - rodar testes;
  - mergear ou fechar com justificativa.
- Cuidado com actions maiores: `checkout`, `upload-artifact`, `setup-python`, `trivy-action`, `actionlint`.

Aceite:

- Sem PR Dependabot aberta sem decisao.
- Dependabot alerts ficam verdes ou documentados.

## Fase 9 - Validar Docker, GHCR, cosign e SLSA

Objetivo: provar supply chain em ambiente completo.

Tarefas locais:

```powershell
docker build -t sdlc-evidence:check .
docker run --rm sdlc-evidence:check --version
```

Tarefas pos-release:

- Verificar assets da GitHub Release:
  - `.whl`
  - `.tar.gz`
  - `bundle.json`
  - `report.md`
  - `summary.html`
  - SBOM
  - SLSA provenance
  - signatures/certificates
  - checksums
- Verificar wheel via PyPI em venv limpo.
- Verificar imagem GHCR.
- Verificar cosign/SLSA com ferramentas adequadas.

Aceite:

- Claims de assinatura passam a ser verificaveis por comando e asset publico.

## Fase 10 - Tag, release e rollback

Objetivo: publicar somente apos gates e configuracoes.

Pre-condicoes:

- Worktree limpo.
- Branch mergeada em `main`.
- CI remoto verde.
- PyPI/GitHub env prontos.
- README/docs coerentes.
- Docker e build validados.

Execucao:

```powershell
git tag -a v1.1.0 -m "release v1.1.0"
git push origin v1.1.0
```

Rollback:

- Se workflow de release falhar antes de publicar assets, corrigir e rerun workflow.
- Se GitHub Release parcial for criada, marcar draft ou deletar release parcial antes de tentar novamente.
- Nao mover tag publica sem decisao explicita. Preferir `v1.1.1` se artefato publico ja foi consumido.

Aceite final:

- GitHub Release `v1.1.0` publicada.
- PyPI publica `1.1.0`.
- GHCR contem imagem `v1.1.0`.
- Pages atualizada.
- Release evidence bundle anexado.
- `pip install secure-sdlc-evidence-collector==1.1.0` funciona em venv limpo.

## Go/no-go por fase

- Fases 0-5: Claude Code pode executar por codigo/docs.
- Fase 6: depende do usuario em GitHub/PyPI.
- Fases 7-10: so executar apos Fase 6.

Decisao atual: `NO-GO` ate concluir Fases 0-7 no minimo.
