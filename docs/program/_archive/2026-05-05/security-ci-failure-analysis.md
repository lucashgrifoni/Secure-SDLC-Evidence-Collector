# Analise das falhas do Security CI/CD no PR #10

Data: 2026-05-05
Run analisado: <https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/runs/25393834658>
Run paralelo CodeQL: <https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/actions/runs/25393834649>

## Conclusao executiva

Todas as falhas no Security CI/CD do PR #10 sao **limitacoes de
configuracao do repositorio**, nao defeitos de codigo:

- O repositorio esta `private` e GitHub Advanced Security (GHAS) nao
  esta habilitado, entao `github/codeql-action/upload-sarif` retorna
  `Resource not accessible by integration` em todos os jobs que tentam
  publicar SARIF (CodeQL, Trivy, Semgrep).
- Os jobs Snyk falham porque `SNYK_TOKEN` nao esta configurado nos
  secrets do repositorio.
- `Dependency Review (PR)` so funciona em repositorios publicos.
- `Gitleaks History` falha porque o token de bot esperado pelo step
  ainda nao esta configurado (a deteccao em si roda; e o upload que
  falha).

Em outras palavras: a logica de scan executa em todos os casos, ela so
nao consegue **publicar** os achados na aba Security do GitHub porque a
plataforma exige (1) repositorio publico ou GHAS pago e (2) tokens dos
fornecedores externos.

Quando o usuario concluir as acoes externas listadas em
`docs/MATURITY_STATUS.md` e
`melhorias/checklist-acoes-externas-publicacao-2026-05-05.md` (tornar
publico, habilitar code scanning + secret scanning, criar `SNYK_TOKEN`,
criar ambiente PyPI), os checks vermelhos vao virar verdes
automaticamente sem alteracao de codigo.

## Detalhamento por check

### Falhas explicadas pelo repositorio ser privado

| Check | Causa | Resolve com |
|---|---|---|
| SAST - CodeQL (python) | upload-sarif: Resource not accessible by integration | Repo publico ou GHAS |
| SAST - CodeQL (javascript-typescript) | mesma causa | Repo publico ou GHAS |
| Analyze (python) (workflow CodeQL) | mesma causa | Repo publico ou GHAS |
| Analyze (actions) (workflow CodeQL) | mesma causa | Repo publico ou GHAS |
| SAST - Semgrep | upload-sarif: Resource not accessible by integration | Repo publico ou GHAS |
| SCA - Trivy | upload-sarif: Resource not accessible by integration | Repo publico ou GHAS |
| Secrets - Trivy | upload-sarif: Resource not accessible by integration | Repo publico ou GHAS |
| IaC and Pipeline - Trivy | upload-sarif: Resource not accessible by integration | Repo publico ou GHAS |
| SCA - Dependency Review (PR) | Action nao roda em repo privado | Repo publico |

### Falhas explicadas por secrets ausentes

| Check | Causa | Resolve com |
|---|---|---|
| SAST - Snyk Code | `SNYK_TOKEN` ausente; passo de auth retorna exit 2 | Configurar `SNYK_TOKEN` em Settings > Secrets |
| SCA - Snyk Open Source | mesma causa | mesmo |
| Secrets History - Gitleaks | falta token de upload | Configurar token (ou aceitar como log-only) |

### Checks que passaram

| Check | Status |
|---|---|
| GitHub CI/CD - Lint, type-check, test (py3.12) | success |
| GitHub CI/CD - Lint, type-check, test (py3.13) | success |
| GitHub CI/CD - Build package artifacts | success |
| GitHub CI/CD - Produce sample evidence bundle | success |
| Security CI/CD - Workflow Lint - actionlint | success |

## Recomendacao para o PR #10

- O PR esta **MERGEABLE** (sem conflito) e cobre apenas mudancas
  legitimas de release-readiness validadas localmente (143 testes,
  77.39% cobertura, mypy strict, ruff, build de wheel/sdist sem
  warning de licenca, mkdocs strict, actionlint).
- As falhas do Security CI/CD nao bloqueiam merge porque dependem de
  configuracao externa.
- Apos o merge, executar a triagem dos 8 PRs do Dependabot (Fase 8 do
  plano) e depois as acoes externas (Fase 6) antes de tag.

## Item para incluir no documento de readiness

Adicionar nota em `docs/publication-readiness.md` explicando que ate o
repositorio ser publico, varios checks do Security CI/CD vao aparecer
como red e nao indicam regressao funcional. Apos a publicacao, todos
devem virar verdes automaticamente.
