# Validacao cruzada - Codex + Claude Code

Data: 2026-05-05
Repositorio: `C:\Users\Lucas Grifoni\Downloads\My Projects - AppSec & DevSecOps\5.Projeto - Secure SDLC Evidence Collector`
HEAD remoto/local: `1f84619d8835bad8ad8ee818e36dfe2666225378`

## Objetivo

Consolidar o raio-x do Codex e o raio-x do Claude Code em um diagnostico unico,
separando:

- fatos confirmados por comando/API;
- fatos parcialmente verdadeiros;
- divergencias entre relatorios;
- pendencias de codigo;
- pendencias externas de GitHub/PyPI;
- prompts de execucao para a proxima rodada.

## Evidencia revalidada nesta rodada

### Git e versionamento

Comandos:

```powershell
git status --short --branch
git log --oneline --decorate -8
git describe --tags --always --dirty
git rev-parse HEAD
git rev-list --count v1.0.1..HEAD
git diff --name-status
git diff --stat
```

Resultado:

- Branch atual: `main...origin/main`.
- HEAD: `1f84619`.
- `main` esta 4 commits a frente de `v1.0.1`.
- `pyproject.toml` e `src/evidence_collector/__init__.py` ainda expõem versao `1.0.1`.
- Estado local esta sujo com 11 arquivos alterados/deletados e `melhorias/` nao rastreada.
- O estado descrito por `git describe`: `v1.0.1-4-g1f84619-dirty`.

Conclusao:

- Confirmado: nao e adequado publicar o HEAD atual como `v1.0.1`.
- Recomendacao: cortar `v1.1.0` em vez de mover tag antigo.

### Qualidade local

Comandos:

```powershell
python --version
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src tests
python -m pytest
```

Resultado:

- Python: `3.12.10`.
- `ruff check src tests scripts`: passou.
- `ruff format --check src tests scripts`: falhou porque `scripts/scrub_lab_artifacts.py` precisa de reformatacao.
- `mypy src tests`: passou, 61 source files.
- `pytest`: `143 passed`, cobertura total `77.39%`, gate de `70%` atingido.

Conclusao:

- Confirmado: o core local esta bom.
- Confirmado: a nova decisao de incluir `scripts` no format gate ainda nao esta satisfeita.

### Smoke test funcional

Comando:

```powershell
python -m evidence_collector.cli.main run `
  --application payments-api `
  --repository acme/payments-api `
  --release-id 2026.05.05 `
  --commit-sha abcdef1234567890 `
  --branch main `
  --artifacts-dir examples/sample_release/artifacts `
  --attestations-dir examples/sample_release/attestations `
  --output-dir $env:TEMP\sdlc-evidence-plan-smoke
```

Resultado:

- CLI version: `1.0.1`.
- `release_status=ready`.
- `evidence_coverage_score=100`.
- `controls=13/13`.

Conclusao:

- Confirmado: o sample positivo ainda prova o fluxo ponta a ponta.

### GitHub remoto

Comandos:

```powershell
gh repo view lucashgrifoni/Secure-SDLC-Evidence-Collector --json name,owner,visibility,defaultBranchRef,isPrivate,pushedAt,latestRelease,url,description,repositoryTopics,licenseInfo,hasDiscussionsEnabled,hasIssuesEnabled
gh release list --repo lucashgrifoni/Secure-SDLC-Evidence-Collector --limit 10
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/runs?per_page=20 --jq .
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/workflows --jq .
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/pages --jq .
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/branches/main/protection --jq .
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/environments/pypi --jq .
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/code-scanning/alerts --jq .
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/secret-scanning/alerts --jq .
gh pr list --repo lucashgrifoni/Secure-SDLC-Evidence-Collector --state open --json number,title,headRefName,baseRefName,createdAt,isDraft,url
```

Resultado:

- Repo: `PRIVATE`.
- Description: vazio.
- Topics: `null`.
- License detectada pelo GitHub: `Other`.
- Issues: habilitado.
- Discussions: desabilitado.
- Latest Release: `v1.0.0`.
- Nao ha GitHub Release `v1.0.1`.
- Workflows: 10 ativos.
- Workflow runs: `total_count=0`.
- Pages: configurado com `build_type=workflow`.
- Branch protection: ausente.
- Environment `pypi`: ausente.
- Code scanning: desabilitado.
- Secret scanning: desabilitado.
- PRs abertas: 8 Dependabot PRs.
- Issues abertas: 0.

Conclusao:

- Confirmado: o repo ainda nao esta pronto para publicacao publica madura.
- Confirmado: as workflows existem, mas nao ha evidencia remota de execucao.
- Divergencia: o relatorio do Claude Code citou 2 runs e CodeQL failure; a API atual retornou 0 runs. Tratar essa parte como nao confirmada ate verificacao pela UI do GitHub ou novo `gh api`.

### PyPI e Pages

Comandos:

```powershell
Invoke-WebRequest https://pypi.org/pypi/secure-sdlc-evidence-collector/json
Invoke-WebRequest https://lucashgrifoni.github.io/Secure-SDLC-Evidence-Collector/
Invoke-WebRequest https://lucashgrifoni.github.io/Secure-SDLC-Evidence-Collector/docs/
```

Resultado:

- PyPI: HTTP 404.
- Pages principal: HTTP 200.
- Pages docs: HTTP 200.

Conclusao:

- Confirmado: GitHub Pages esta publicado.
- Confirmado: PyPI ainda nao esta publicado.

### Seguranca local

Comandos ja executados nesta rodada e na rodada anterior:

```powershell
gitleaks detect --source . --redact --verbose
trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL ...
python -m pip_audit .
```

Resultado:

- Gitleaks: sem vazamentos.
- Trivy: sem achados HIGH/CRITICAL relevantes no escopo rodado.
- `python -m pip_audit .`: `No known vulnerabilities found`.

Limites:

- Semgrep nao foi executado nesta rodada.
- Bandit nao foi executado nesta rodada.
- Docker build nao foi validado porque o Docker daemon nao estava ativo na rodada anterior.
- Cosign e SLSA verifier nao foram validados localmente.

## Validacao dos principais pontos do Codex

| Ponto | Status |
|---|---|
| Projeto maduro, mas nao release-clean | Confirmado |
| Repo privado | Confirmado |
| Worktree local sujo | Confirmado |
| `v1.0.1` tag existe, mas sem GitHub Release | Confirmado |
| `main` 4 commits a frente de `v1.0.1` | Confirmado |
| PyPI inexistente | Confirmado |
| Pages no ar | Confirmado |
| Produto e CLI/GitHub Action/API opcional com UI estatica | Confirmado |
| `143 passed`, coverage `77.39%` | Confirmado |
| `ruff format --check scripts` falha | Confirmado |
| Branch protection ausente | Confirmado |
| Code scanning e secret scanning desabilitados | Confirmado |
| 8 Dependabot PRs abertas | Confirmado |
| Links antigos `LucasGrifoni/secure-sdlc-evidence-collector` | Confirmado |
| Docker build nao validado localmente | Confirmado pela rodada anterior |

## Validacao dos principais pontos do Claude Code

| Ponto | Status |
|---|---|
| Definicao do produto como CLI de evidencia Secure SDLC | Confirmado |
| Arquitetura por camadas entregue | Confirmado |
| CLI com `run`, `collect`, `evaluate`, `bundle`, `controls`, `compare`, `oscal`, `plugins`, `schema`, `doctor`, `exceptions` | Confirmado por codigo/docs |
| Tier 1-4 implementados no codigo/docs | Parcialmente confirmado: codigo/docs existem, mas release publica desses tiers nao existe |
| Tag `v1.0.1` atras de `main` | Confirmado |
| Nenhum release `v1.0.1` no GitHub | Confirmado |
| Workflows `on:push` sem evidencia remota | Confirmado como `workflow_runs=0` |
| CodeQL scheduled run falhando | Nao confirmado nesta validacao; API retornou 0 runs |
| Repo privado | Confirmado |
| Repo sem description/topics e license `Other` | Confirmado |
| README badges desatualizados | Confirmado no HEAD remoto; no worktree local ha alteracoes ainda nao commitadas para atualizar |
| PyPI Trusted Publisher pendente | Confirmado |
| Discussions desabilitado | Confirmado |
| Branch protection ausente | Confirmado |
| Risco de claims sobre cosign/SLSA antes de release assinada | Confirmado como risco documental |

## Divergencias resolvidas

1. Runs do GitHub Actions:
   - Claude Code: citou 2 runs e CodeQL failure.
   - Validacao atual: `actions/runs` retornou `total_count=0`.
   - Decisao: nao usar "CodeQL falhando" como fato ate evidenciar por UI/API. Usar "sem runs confirmados".

2. `pip-audit`:
   - Rodada anterior: ferramenta nao estava no PATH como comando `pip-audit`.
   - Validacao atual: `python -m pip_audit .` executou e retornou sem vulnerabilidades.
   - Decisao: documentar como validado quando usado via modulo Python, nao como comando global.

3. README badges:
   - HEAD remoto ainda tem numeros antigos.
   - Worktree local ja contem alteracao para `143` e `77%`, mas ainda nao foi commitada.
   - Decisao: tratar como pendencia ate commit/push.

4. Pasta `melhorias/`:
   - A pasta ja existia antes desta rodada com dois arquivos nao rastreados.
   - Decisao: preservar arquivos existentes e adicionar documentos novos.

## Bloqueadores reais antes de publicacao

### P0 - Bloqueadores de release

1. Worktree sujo e parcialmente inconsistente.
2. `ruff format --check src tests scripts` falha por `scripts/scrub_lab_artifacts.py`.
3. Versao `1.0.1` desalinhada do HEAD atual.
4. Nao ha GitHub Release para o conteudo atual.
5. PyPI ainda nao existe.
6. Environment GitHub `pypi` nao existe.
7. Actions sem runs confirmados.
8. Repo privado.
9. Branch protection ausente.
10. Code scanning e secret scanning desabilitados.
11. 8 PRs Dependabot abertas.

### P1 - Bloqueadores de maturidade publica

1. Links/metadados apontam para `LucasGrifoni/secure-sdlc-evidence-collector`, enquanto o repo real e `lucashgrifoni/Secure-SDLC-Evidence-Collector`.
2. License detectada como `Other`; o arquivo deve ser revisado para o texto Apache-2.0 canonico completo ou metadata adequada.
3. Docs afirmam signing/SLSA/PyPI como capacidade mais forte do que a evidencia publica atual.
4. `docs/plugins.md` existe mas nao esta no `mkdocs.yml` nav.
5. `docs/MATURITY_STATUS.md` diz artifacts signed yes, mas release assinada publica ainda nao existe.

## Go/no-go consolidado

Decisao: `NO-GO` para publicacao publica imediata.

Racional:

- `GO` para desenvolvimento local e dogfood.
- `NO-GO` para publicacao/release publica porque ainda falta limpar estado local,
  alinhar versao/tag/release, configurar GitHub/PyPI e obter evidencia remota
  de CI/release.

## Proxima decisao recomendada

Usar `v1.1.0` como proxima release publica.

Motivo:

- O HEAD atual contem Tier 1-4 apos `v1.0.1`.
- Essas mudancas incluem novas capacidades e maturidade relevante.
- Mover `v1.0.1` esconderia historico e causaria confusao de release.
