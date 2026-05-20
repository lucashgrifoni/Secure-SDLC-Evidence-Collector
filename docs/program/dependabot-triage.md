# Triagem Dependabot — Fase 8 do plano de publicacao v1.1.0

Data: 2026-05-05
Plano de origem: rodada privada de publicacao de 2026-05-05.
PR base mergeada: #10 (release-readiness para v1.1.0) em `main` (`17dede2`).

## Resumo executivo

Os **8 PRs Dependabot originais** abertos antes da execucao desta fase
estao todos resolvidos: todos mergeados via squash em `main`, com
validacao local antes de cada merge no caso das atualizacoes de
dependencias Python. As novas PRs criadas pelo proprio Dependabot
durante a sessao (gerados quando ele detectou novas versoes apos cada
merge anterior) ficam **abertas para decisao do owner**, com
classificacao registrada abaixo, porque tocam superficies de
release/supply-chain que so devem ser exercitadas apos a primeira
release publica assinada existir.

## PRs originais — status

| PR | Mudanca | Squash commit | Como foi validado |
|---|---|---|---|
| #1 | `devops-actions/actionlint` 0.1.3 -> 0.1.12 | `f967001` | patch wrapper, low risk |
| #2 | `actions/upload-artifact` 4.4.3 -> 7.0.1 | `54ca5ed` | major wrapper, mantem `subject-path`/`name`/`path` API |
| #3 | `actions/checkout` 4.2.2 -> 6.0.2 | `13cabfa` | major bump, mantem `persist-credentials: false` |
| #4 | `aquasecurity/trivy-action` 0.35.0 -> 0.36.0 | `9d8d0d4` | minor bump, sem mudanca de input |
| #6 | `pytest-cov<6.0` -> `<8.0` | `0ff98ed` | `python -m pytest` com pytest-cov 7.1.0: 143 passed |
| #7 | `rich<14.0` -> `<16.0` | `c27d0a0` | `python -m pytest` com rich 15.0.0: 143 passed |
| #8 | `pytest<9.0` -> `<10.0` | `dab1759` | `python -m pytest` com pytest 9.0.3: 143 passed |
| #9 | `actions/setup-python` 5.3.0 -> 6.2.0 | `e7c51b7` | major bump, mantem `python-version`/`cache: pip` |

Validacao consolidada da combinacao pytest 9 + pytest-cov 7 + rich 15
foi feita em **uma unica execucao** local com pytest passando os 143
testes e cobertura 77.39%. Apos cada merge a versao foi revertida ao
intervalo declarado em `pyproject.toml` no momento da execucao.

## PRs novos abertas durante a sessao — pendentes de decisao do owner

Estes PRs surgiram porque o Dependabot reavalia o manifest a cada
merge. Eles tocam superficies sensiveis (publish-pypi.yml, scorecard,
release-please) e **nao foram mergeados** porque mudar essas pecas
antes da primeira release publica assinada cria risco sem ganho
imediato.

| PR | Mudanca | Categoria | Recomendacao |
|---|---|---|---|
| #11 | `mutmut<3.0` -> `<4.0` | pip (mutmut major) | **HOLD**. mutmut 3.x e refatoracao grande do CLI. Validar localmente que `mutmut run --paths-to-mutate ...`, `mutmut results` e `mutmut html` continuam funcionando em 3.x antes de mergear. Workflow afetado: `.github/workflows/mutation.yml`. |
| #12 | `googleapis/release-please-action` 4.2.0 -> 5.0.0 | action (major, breaking: node24) | **HOLD**. Breaking change e upgrade para Node 24. Validar apos primeira release-please real funcionar com a versao atual. |
| #13 | `actions/attest-build-provenance` v1 -> v4 | action (major) | **HOLD**. Critico para SLSA provenance. So mexer apos primeira release publica funcionar com v1, garantindo baseline antes de bumpar. |
| #14 | `ossf/scorecard-action` 2.4.0 -> 2.4.3 | action (patch) | **MERGED** nesta sessao (commit `b01f062`). |
| #15 | `actions/upload-pages-artifact` 4 -> 5 | action (major) | **HOLD**. Usado em `deploy-github-pages.yml`. Validar apos pagina ser publicada com v4. |
| #16 | `docker/login-action` 3.3.0 -> 4.1.0 | action (major) | **HOLD**. Usado em publish-pypi.yml para GHCR push. Validar apos primeiro push GHCR funcionar com v3. |
| #17 | `github/codeql-action` 3.35.2 -> 4.35.3 | action (major) | **HOLD**. Usado em multiplos workflows; v4 muda comportamento de upload-sarif e default queries. Aguardar repo virar publico (Fase 6) para que o CodeQL upload SARIF funcione, depois bumpar. |

## Princpios usados na decisao

1. **Bumps de dependencia que nao tocam release/supply-chain
   (pytest/pytest-cov/rich)**: validar localmente, mergear.
2. **Bumps de actions de CI que nao alteram contratos publicos
   (checkout, setup-python, upload-artifact)**: mergear apos
   confirmacao de que a API usada no codigo nao mudou.
3. **Bumps de actions de release/supply-chain (attest, release-please,
   docker/login, codeql, upload-pages)**: NAO mexer ate que a primeira
   release publica completa exista para servir de baseline. Mudar
   antes acumula risco sem ganho.
4. **Bumps majores de ferramentas de build/teste alternativas
   (mutmut)**: adiar ate uma janela dedicada, porque o workflow nao e
   bloqueante (roda semanalmente, schedule cron) e mutmut 3.x e uma
   reescrita.

## Acoes de follow-up

- Apos a primeira release publica de v1.1.0 funcionar com os pinos
  atuais, abrir uma nova rodada de triagem cobrindo #11, #12, #13,
  #15, #16, #17.
- Quando o repositorio virar publico (Fase 6 do plano), os checks
  vermelhos do Security CI/CD viram verdes automaticamente
  (`Resource not accessible by integration` desaparece). Validar isso
  reabrindo um PR sintetico ou rerodando o ultimo workflow.

## Conformidade com o plano

- Fase 8 do plano `plano-de-acao-publicacao-v1-1-0-2026-05-05.md` exige
  "Sem PR Dependabot aberta sem decisao". Cumprido: todas as PRs
  abertas no inicio da fase tem decisao registrada (mergear ou hold
  com justificativa).
- Nao foi feita acao destrutiva: nao houve `--force`, nao houve
  reescrita de historico, nao houve drop de tag.
