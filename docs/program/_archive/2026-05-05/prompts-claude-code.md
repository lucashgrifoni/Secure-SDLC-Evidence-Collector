# Prompts para Claude Code executar

Data: 2026-05-05
Repositorio: `C:\Users\Lucas Grifoni\Downloads\My Projects - AppSec & DevSecOps\5.Projeto - Secure SDLC Evidence Collector`

Use estes prompts em ordem. Cada prompt e uma unidade de trabalho. Nao misture
fases, porque ha dependencias externas entre elas.

## Prompt 0 - Auditoria inicial e protecao do worktree

```text
Voce esta no repositorio:
C:\Users\Lucas Grifoni\Downloads\My Projects - AppSec & DevSecOps\5.Projeto - Secure SDLC Evidence Collector

Objetivo: fazer uma auditoria inicial do estado atual antes de qualquer alteracao.

Regras:
- Nao altere arquivos nesta fase.
- Nao reverta nada.
- Nao apague arquivos.
- Nao sobrescreva arquivos em melhorias/.
- Separe mudancas ja existentes de mudancas que voce eventualmente recomendaria.
- Trate arquivos nao rastreados em melhorias/ como material do usuario.

Leia:
- melhorias/validacao-cruzada-codex-claude-2026-05-05.md
- melhorias/plano-de-acao-publicacao-v1-1-0-2026-05-05.md
- melhorias/checklist-acoes-externas-publicacao-2026-05-05.md

Execute:
git status --short --branch
git diff --name-status
git diff --stat
git log --oneline --decorate -8
git describe --tags --always --dirty
git rev-parse HEAD
git rev-list --count v1.0.1..HEAD

Depois responda com:
- estado do worktree;
- arquivos modificados/deletados/nao rastreados;
- riscos imediatos;
- se e seguro criar branch codex/release-readiness-v1.1.0;
- proxima acao recomendada.

Nao implemente nada ainda.
```

## Prompt 1 - Higiene local e gates

```text
Objetivo: deixar o worktree local consistente e os gates locais verdes, sem alterar escopo do produto.

Contexto:
- O worktree esta sujo.
- scripts/scrub_lab_artifacts.py precisa passar em ruff format quando scripts entra no gate.
- Existem mudancas locais em README, CHANGELOG, Dockerfile, Makefile, github-ci-cd.yml, docs e gitpage/README.
- Plano de acao e execucao - Claude.md aparece deletado localmente; nao confirme a remocao sem avaliar se ainda e referencia util.

Regras:
- Nao reverter mudancas do usuario sem aprovacao explicita.
- Nao criar feature nova.
- Nao criar comando, flag, schema, evidence type ou controle novo.
- Nao mover tag.
- Nao publicar release.
- Use uma branch codex/release-readiness-v1.1.0 se for seguro; se nao for, pare e explique.

Tarefas:
1. Corrigir formatacao de scripts/scrub_lab_artifacts.py.
2. Avaliar as mudancas locais ja existentes e manter apenas o que for coerente com release readiness.
3. Se a remocao de Plano de acao e execucao - Claude.md for mantida, justificar e garantir que nenhuma referencia versionada quebre.
4. Atualizar docs apenas para refletir evidencia real.
5. Nao afirmar Semgrep, Bandit, Docker, cosign ou SLSA se nao forem executados.

Comandos de validacao:
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src tests
python -m pytest
$exe = Join-Path $HOME '.local\bin\actionlint.exe'; $files = Get-ChildItem .github\workflows -File -Include *.yml,*.yaml | ForEach-Object { $_.FullName }; & $exe @files
python -m pip_audit .
gitleaks detect --source . --redact --verbose
trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --skip-dirs .git --skip-dirs .mypy_cache --skip-dirs .pytest_cache --skip-dirs .ruff_cache --skip-dirs build --skip-dirs output .

Entrega:
- patch minimo;
- lista de arquivos alterados;
- comandos executados e resultados;
- pendencias restantes.
```

## Prompt 2 - Corrigir identidade publica do repositorio

```text
Objetivo: alinhar todos os metadados e links publicos com o repositorio real:
https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector

Contexto:
- Ha links antigos para https://github.com/LucasGrifoni/secure-sdlc-evidence-collector.
- O repo real na API e owner lucashgrifoni, name Secure-SDLC-Evidence-Collector.
- PyPI ainda nao existe, entao docs devem dizer "configurado/pendente" ate publicar.

Regras:
- Nao alterar proposta do produto.
- Nao criar feature.
- Nao mexer em release/tag.
- Nao alterar links historicos se eles estiverem explicitamente documentando passado; caso contrario, padronize para o repo real.

Tarefas:
1. Atualizar pyproject.toml Homepage/Issues.
2. Atualizar action.yml install fallback.
3. Atualizar Dockerfile label source.
4. Atualizar CONTRIBUTING.md, docs/github_action.md e issue templates.
5. Revisar CODEOWNERS e dependabot reviewers para padronizacao de handle.
6. Rodar busca final para confirmar que links antigos nao ficaram por acidente.

Comandos:
Select-String -Path pyproject.toml,README.md,action.yml,Dockerfile,CONTRIBUTING.md,.github\CODEOWNERS,.github\dependabot.yml,.github\ISSUE_TEMPLATE\*.yml,docs\*.md -Pattern 'LucasGrifoni|secure-sdlc-evidence-collector' -CaseSensitive:$false
python -m ruff check src tests scripts
python -m pytest

Entrega:
- arquivos alterados;
- justificativa para qualquer link antigo mantido;
- validacoes.
```

## Prompt 3 - Corrigir LICENSE e metadata de package

```text
Objetivo: fazer o GitHub detectar a licenca como Apache-2.0 e limpar metadata de build.

Contexto:
- gh repo view retorna licenseInfo.name = Other.
- O arquivo LICENSE existe, mas parece nao ser reconhecido como Apache-2.0 canonico.
- python -m build gera warnings sobre project.license como tabela deprecated e license classifiers.

Regras:
- Preservar copyright do autor.
- Usar texto canonico Apache License 2.0 completo.
- Nao trocar a licenca do projeto.
- Nao criar arquivo de licenca custom.

Tarefas:
1. Substituir LICENSE pelo texto canonico completo Apache-2.0 com copyright apropriado.
2. Atualizar pyproject.toml para metadata moderna de licenca quando suportado.
3. Rodar build wheel/sdist.
4. Validar com gh repo view depois de commit/push ou registrar que deteccao GitHub so muda apos push.

Comandos:
python -m build --sdist --wheel --outdir $env:TEMP\sdlc-evidence-license-build
python -m pytest

Entrega:
- diff da licenca/metadata;
- warnings restantes, se houver;
- validacao.
```

## Prompt 4 - Ajustar claims de supply chain e docs

```text
Objetivo: tornar README/docs honestos sobre o que esta configurado, validado localmente, publicado e verificado.

Contexto:
- Release workflow existe com cosign/SLSA/PyPI/GHCR, mas a ultima GitHub Release publicada e v1.0.0.
- Nao existe release publica assinada do conteudo atual.
- PyPI retorna 404.
- Actions runs retornam 0 na API atual.
- docs/plugins.md existe mas mkdocs avisou que nao esta no nav.

Regras:
- Nao remover capacidades reais do projeto.
- Trocar linguagem absoluta por linguagem precisa quando a evidencia ainda nao existe.
- Nao declarar scanner limpo se nao foi executado.

Tarefas:
1. Revisar README, docs/index.md, docs/MATURITY_STATUS.md, docs/release-readiness.md, docs/traceability.md e CHANGELOG.md.
2. Incluir docs/plugins.md no mkdocs.yml nav.
3. Corrigir a promessa de SPDX em release.yml: gerar SPDX de fato ou remover o comentario/promessa.
4. Garantir consistencia dos numeros: 143 testes, 77.39% coverage, 61 mypy files.
5. Diferenciar: configured, locally validated, remotely validated, published.

Comandos:
python -m mkdocs build --strict --site-dir $env:TEMP\sdlc-evidence-mkdocs-check
python -m pytest
python -m ruff check src tests scripts

Entrega:
- docs ajustadas;
- claims removidos/baixados de intensidade;
- validacoes.
```

## Prompt 5 - Preparar versionamento v1.1.0

```text
Objetivo: preparar a proxima release como v1.1.0, sem mover v1.0.1.

Contexto:
- main esta 4 commits a frente de v1.0.1.
- Os commits adicionam Tier 1-4: Scorecard, CodeQL, pre-commit, determinismo, doctor, SLSA, SBOM, container, mutation, logs, ADRs, threat model, hypothesis, mkdocs, py3.13, plugins, FastAPI, OSCAL, labels/stale, release-please.
- Isso e mais adequado como v1.1.0 do que retag v1.0.1.

Regras:
- Nao criar tag ainda.
- Nao publicar release ainda.
- Nao mover tags existentes.

Tarefas:
1. Atualizar pyproject.toml para 1.1.0.
2. Atualizar src/evidence_collector/__init__.py para 1.1.0.
3. Atualizar README badge release.
4. Atualizar CHANGELOG com entrada 1.1.0.
5. Atualizar .github/.release-please-manifest.json se necessario.
6. Confirmar que docs nao chamam HEAD atual de v1.0.1.

Comandos:
python -m evidence_collector.cli.main --version
python -m build --sdist --wheel --outdir $env:TEMP\sdlc-evidence-v110-build
python -m pytest
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src tests

Entrega:
- versao alinhada;
- build 1.1.0 gerado;
- changelog coerente.
```

## Prompt 6 - Validar/acionar GitHub Actions remoto

```text
Objetivo: obter evidencia remota real de CI antes de release.

Contexto:
- A API atual retornou workflow_runs total_count=0, apesar de 10 workflows ativos.
- O relatorio anterior do Claude citou 2 runs e CodeQL failure, mas isso nao foi confirmado pela API atual.
- Nao afirmar falha CodeQL sem URL de run/log.

Regras:
- Nao publicar tag.
- Nao alterar workflow sem evidencia de falha.
- Se depender de UI, reportar exatamente o que o usuario precisa fazer.

Tarefas:
1. Rodar:
   gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/runs?per_page=20 --jq .
   gh run list --repo lucashgrifoni/Secure-SDLC-Evidence-Collector --all --limit 20
2. Se continuar vazio, verificar settings via API quando possivel:
   gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/permissions --jq .
3. Tentar disparar workflow manual permitido:
   gh workflow run github-ci-cd.yml --repo lucashgrifoni/Secure-SDLC-Evidence-Collector --ref main
4. Aguardar e coletar resultado:
   gh run list --repo lucashgrifoni/Secure-SDLC-Evidence-Collector --limit 10
5. Se falhar, usar gh run view <id> --log e corrigir causa.

Entrega:
- runs encontrados/disparados;
- URL dos runs;
- conclusao de cada workflow;
- se Settings/UI bloquear, lista precisa de acao externa.
```

## Prompt 7 - Acoes externas GitHub/PyPI

```text
Objetivo: orientar o usuario nas configuracoes externas e validar depois.

Contexto:
- Repo privado.
- Branch protection ausente.
- Code scanning desabilitado.
- Secret scanning desabilitado.
- Environment pypi ausente.
- PyPI retorna 404.
- Discussions desabilitado.

Nao tente fingir que isso foi resolvido por codigo.

Peça ao usuario executar no GitHub/PyPI:
1. Tornar repo publico quando estiver pronto.
2. Criar environment GitHub pypi.
3. Criar projeto secure-sdlc-evidence-collector no PyPI.
4. Configurar Trusted Publisher no PyPI:
   Owner lucashgrifoni
   Repository Secure-SDLC-Evidence-Collector
   Workflow release.yml
   Environment pypi
5. Ativar branch protection em main.
6. Ativar code scanning.
7. Ativar secret scanning, se disponivel.
8. Habilitar Discussions, se mantido.
9. Definir description/topics.

Depois valide:
gh repo view lucashgrifoni/Secure-SDLC-Evidence-Collector --json visibility,description,repositoryTopics,licenseInfo,hasDiscussionsEnabled
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/branches/main/protection --jq .
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/environments/pypi --jq .
Invoke-WebRequest -UseBasicParsing https://pypi.org/pypi/secure-sdlc-evidence-collector/json

Entrega:
- o que esta pronto;
- o que ainda depende do usuario;
- bloqueadores restantes.
```

## Prompt 8 - Dependabot triage

```text
Objetivo: tratar as 8 PRs Dependabot abertas antes da publicacao.

Contexto:
PRs abertas em 2026-05-05:
- #1 devops-actions/actionlint
- #2 actions/upload-artifact
- #3 actions/checkout
- #4 aquasecurity/trivy-action
- #6 pytest-cov
- #7 rich
- #8 pytest
- #9 actions/setup-python

Regras:
- Nao mergear tudo cegamente.
- Revisar uma por uma.
- Para actions, considerar pinning por SHA e compatibilidade com workflow atual.
- Para libs Python, rodar testes.

Tarefas:
1. Para cada PR, buscar diff e release notes quando necessario.
2. Classificar: merge, hold, close.
3. Aplicar uma decisao por PR.
4. Rodar gates apos merges.

Comandos:
gh pr list --repo lucashgrifoni/Secure-SDLC-Evidence-Collector --state open
gh pr view <numero> --repo lucashgrifoni/Secure-SDLC-Evidence-Collector --json title,body,files,commits,mergeable,statusCheckRollup
python -m pytest
python -m ruff check src tests scripts
$exe = Join-Path $HOME '.local\bin\actionlint.exe'; $files = Get-ChildItem .github\workflows -File -Include *.yml,*.yaml | ForEach-Object { $_.FullName }; & $exe @files

Entrega:
- decisao por PR;
- PRs mergeadas/fechadas/pendentes;
- validacoes.
```

## Prompt 9 - Docker, GHCR, cosign e SLSA

```text
Objetivo: validar supply chain em ambiente completo.

Pre-condicao:
- Docker daemon ativo.
- cosign instalado ou disponivel em CI.
- Release workflow pronto.

Tarefas locais:
docker build -t sdlc-evidence:check .
docker run --rm sdlc-evidence:check --version

Tarefas pos-release:
1. Verificar assets na GitHub Release v1.1.0.
2. Baixar checksums e validar hashes.
3. Verificar wheel/sdist/bundle/SBOM com cosign.
4. Verificar SLSA provenance.
5. Verificar imagem GHCR com cosign.
6. Testar:
   python -m venv %TEMP%\sdlc-pypi-test
   %TEMP%\sdlc-pypi-test\Scripts\python.exe -m pip install secure-sdlc-evidence-collector==1.1.0
   %TEMP%\sdlc-pypi-test\Scripts\sdlc-evidence.exe --version

Entrega:
- comandos e saidas;
- assets verificados;
- falhas e correcao recomendada.
```

## Prompt 10 - Final release gate e tag

```text
Objetivo: executar o gate final e publicar v1.1.0 somente se estiver tudo pronto.

Pre-condicoes obrigatorias:
- Worktree limpo.
- main atualizado.
- CI remoto verde.
- PyPI Trusted Publisher pronto.
- GitHub environment pypi pronto.
- Branch protection configurada.
- Code scanning habilitado ou excecao documentada.
- Secret scanning habilitado ou excecao documentada.
- Docker build validado.
- Docs coerentes.
- Dependabot PRs tratadas ou justificadas.

Nao continue se qualquer pre-condicao falhar.

Gate local:
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src tests
python -m pytest
$exe = Join-Path $HOME '.local\bin\actionlint.exe'; $files = Get-ChildItem .github\workflows -File -Include *.yml,*.yaml | ForEach-Object { $_.FullName }; & $exe @files
python -m build --sdist --wheel --outdir $env:TEMP\sdlc-evidence-final-build
python -m evidence_collector.cli.main run --application payments-api --repository acme/payments-api --release-id 2026.05.05 --commit-sha abcdef1234567890 --branch main --artifacts-dir examples/sample_release/artifacts --attestations-dir examples/sample_release/attestations --output-dir $env:TEMP\sdlc-evidence-final-smoke

Se tudo passar:
git tag -a v1.1.0 -m "release v1.1.0"
git push origin v1.1.0

Depois:
gh release view v1.1.0 --repo lucashgrifoni/Secure-SDLC-Evidence-Collector
gh run list --repo lucashgrifoni/Secure-SDLC-Evidence-Collector --limit 10

Entrega:
- decisao GO/NO-GO;
- se GO, tag criada/pushada e release workflow monitorado;
- se NO-GO, bloqueadores exatos.
```
