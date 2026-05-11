# Prompt Claude Code — Post-publication hardening pass (alvo: v1.1.1)

Data: 2026-05-10
Repositorio alvo:
`C:\Users\Lucas Grifoni\Downloads\My Projects - AppSec & DevSecOps\5.Projeto - Secure SDLC Evidence Collector`
Branch atual de origem esperada: `main`
Tag corrente: `v1.1.0` (ja existe; nao mover)
Branch a ser criada: `chore/post-publication-hardening-v1-1-1`

Cole o conteudo abaixo da linha `>>> INICIO DO PROMPT` ate o final em uma
unica execucao do Claude Code. O Claude Code deve executar as fases na
ordem indicada e nao pode comecar uma fase enquanto a anterior nao
estiver verde nos gates locais descritos.

---

>>> INICIO DO PROMPT

Voce esta no repositorio:
`C:\Users\Lucas Grifoni\Downloads\My Projects - AppSec & DevSecOps\5.Projeto - Secure SDLC Evidence Collector`

## Objetivo

Levar o projeto Secure SDLC Evidence Collector da versao `v1.1.0` ate
um estado release-ready para `v1.1.1`, aplicando um pacote de hardening
pos-publicacao que cobre seis frentes:

1. Reconciliacao documental dos numeros reais (testes, coverage) entre
   README, MATURITY_STATUS, release-readiness e CHANGELOG.
2. Subida do gate de coverage para condizer com a realidade observada.
3. Higienizacao da pasta `melhorias/` movendo o conteudo para
   `docs/program/` e preservando redirect.
4. Refator do `cli/main.py` (811 LOC, 11 comandos) em modulos por
   comando, sem mudar contrato externo.
5. Adicao do `step-security/harden-runner` em todos os jobs Linux dos
   workflows GitHub Actions que ainda nao o possuem.
6. Tres adicoes funcionais: comando `sdlc-evidence verify`, campo
   `classification` de primeira classe em evidencias SARIF, e snapshot
   test deterministico do bundle canonico.

Nao publicar nada (nao criar release, nao mover tag, nao push de tag).
A ultima etapa eh apenas commit + push da branch + PR para revisao
manual.

## Restricoes invioveis

- Nao mover, recriar ou apagar tags ja existentes (`v1.0.0`, `v1.0.1`,
  `v1.1.0`).
- Nao reescrever historico (`git rebase -i`, `--force`, etc.).
- Nao tornar o repositorio publico.
- Nao publicar no PyPI nem disparar `release.yml`.
- Nao introduzir dependencias novas alem das ja listadas em
  `pyproject.toml`.
- Manter retrocompatibilidade total da CLI: nome do entrypoint
  (`sdlc-evidence`), nomes de comandos, flags, codigos de saida e
  eventos NDJSON identicos ao estado atual de `main`.
- Nao mexer no esquema do `bundle.json` de forma quebradora. Novos
  campos sao OK desde que sejam opcionais (`Optional`/`| None = None`)
  e tenham comportamento backward-compatible.

## Como ler este documento

Cada fase eh uma unidade de trabalho. Execute as fases em ordem.
Antes de comecar uma fase, leia o "Estado esperado pos-fase". Antes de
encerrar, valide os "Criterios de aceite" daquela fase. Se algum
criterio falhar, pare e relate.

---

## Fase 0 — Audit inicial e preparo do worktree

Antes de tocar em qualquer arquivo, capture o estado atual em texto e
nao prossiga se houver bloqueio.

Acoes:

1. `git status --short` precisa estar limpo. Se houver alteracoes nao
   commitadas, pare e relate.
2. `git log -1 --oneline` deve apontar para o commit que carregou
   `v1.1.0` em `main`. Se nao for o caso, pare e relate.
3. `git switch -c chore/post-publication-hardening-v1-1-1`.
4. Confirme que existe ambiente Python >= 3.12 ativo (
   `python --version`). Se nao existir, instrua o usuario e pare.
5. Em um venv local (nao alterar o repo): instale `.[dev,api,logs]`
   apenas para validar a posterior execucao dos gates. Nao commitar
   nada relacionado a isso.

Criterio de aceite Fase 0:

- Branch nova criada e ativa.
- Worktree limpo.
- `pytest -q` no estado atual de `main` passa com `--cov-fail-under=70`
  ja configurado.

---

## Fase 1 — Reconciliacao documental dos numeros reais

Contexto: hoje o repo carrega tres "verdades" diferentes para a mesma
metrica. README badge mostra `tests-143` e `coverage-77%`; o bloco
`[Unreleased]` do CHANGELOG ja registra `211 testes / 86.38%`;
`docs/MATURITY_STATUS.md` e `docs/release-readiness.md` continuam em
`143 / 77.39%`.

Acoes:

1. Rodar localmente `pytest --cov=evidence_collector
   --cov-report=term-missing -q` para capturar os valores ATUAIS de
   tests/coverage. Considere esses valores como verdade.
2. Atualizar em commit unico:
   - `README.md`: badges `tests-<N>` e `coverage-<X>%`.
   - `docs/MATURITY_STATUS.md`:
     - linha "Last updated" para `2026-05-10`.
     - tabela Headline numbers: `Tests passing`, `Line + branch
       coverage` com os valores atuais. A nota da coverage deve
       mencionar que o floor sera elevado para `80 %` em
       `pyproject.toml` na Fase 2.
   - `docs/release-readiness.md`:
     - bloco "Last local validation pass" atualizado.
     - adicionar bloco "Re-validation required before tagging
       `v1.1.1`" listando as mudancas das Fases 2 a 8.
     - atualizar a linha `--cov-fail-under=` na lista "Quality gates"
       para `80`.
3. No CHANGELOG.md:
   - Subdividir `[Unreleased]` em dois sub-blocos por data:
     `#### 2026-05-10 — post-publication hardening pass` e
     `#### 2026-05-05 — maturity/higiene rodada`.
   - Os itens da Fase 2 ate 8 entram no sub-bloco `2026-05-10` nas
     secoes `Added`, `Changed` e `Documentation`. Voce vai preencher
     esses itens durante as fases; aqui apenas crie a estrutura vazia.
   - Os itens pre-existentes ficam no sub-bloco `2026-05-05`.

Criterio de aceite Fase 1:

- Os tres documentos (README, MATURITY_STATUS, release-readiness) e o
  CHANGELOG mostram exatamente o mesmo par `(tests, coverage)`.
- `git diff` so afeta arquivos `.md` e o README.

---

## Fase 2 — Subir cov-fail-under de 70 para 80

Acoes:

1. Em `pyproject.toml`, secao `[tool.pytest.ini_options].addopts`,
   trocar `--cov-fail-under=70` por `--cov-fail-under=80`.
2. Em `README.md`, ajustar a linha do Makefile-style help:
   `make test  # pytest with coverage gate (>=70%)` para `>=80%`.
3. Confirmar que `docs/release-readiness.md` ja foi ajustada na Fase 1.
4. Rodar `pytest` localmente para confirmar que o gate de 80% passa.

Criterio de aceite Fase 2:

- `pytest` verde com `--cov-fail-under=80`.
- Nenhuma outra mudanca de comportamento.

---

## Fase 3 — Higienizar `melhorias/` para `docs/program/`

Contexto: `melhorias/` carrega 13 documentos da rodada de publicacao
de 2026-05-05, misturando governance ativo (runbook, dependabot
triage, pinning inventory, validacao cruzada) com scratch operacional
(prompts, planos executados, mini-prompts, analise de falhas).

Estrutura alvo:

```
docs/program/
├── README.md                              # indice
├── release-runbook.md                     # do runbook-publicacao-v1-1-0
├── dependabot-triage.md                   # do dependabot-triagem
├── actions-pinning-inventory.md           # do pinning-actions
├── cross-validation-2026-05-05.md         # do validacao-cruzada-codex-claude
└── _archive/2026-05-05/
    ├── decision-ideia-do-projeto-md.md
    ├── external-actions-checklist.md
    ├── mini-prompt-publication.md
    ├── plan-maturity-hygiene.md
    ├── plan-publication.md
    ├── prompt-cursor.md
    ├── prompts-claude-code.md
    └── security-ci-failure-analysis.md
```

Acoes:

1. Criar a estrutura acima com `git mv` para preservar historico.
2. Reescrever `melhorias/README.md` como pointer com a tabela de
   redirecionamento `old -> new`. Esse arquivo eh o unico que sobra na
   pasta `melhorias/`.
3. Reescrever referencias internas que apontam para `melhorias/...` nos
   seguintes arquivos para apontar para o novo caminho:
   - `CHANGELOG.md`
   - `docs/MATURITY_STATUS.md`
   - `THREAT_MODEL.md`
   - cada arquivo dentro de `docs/program/` que cruza-referencia outro
     dentro de `docs/program/` (mantenha referencias historicas em
     `_archive/` apontando para caminhos de archive).
4. Em `docs/program/cross-validation-2026-05-05.md`, adicionar uma
   "Nota historica (2026-05-10)" no topo explicando que as mencoes
   internas a `melhorias/` retratam o estado de 2026-05-05.
5. Criar `docs/program/README.md` como indice da pasta, listando os
   quatro artefatos ativos e apontando para o `_archive/2026-05-05/`.

Criterio de aceite Fase 3:

- `melhorias/` contem apenas `README.md` (pointer).
- `grep -rn 'melhorias/' --include='*.md' --include='*.py'` retorna
  somente mencoes contextuais documentadas (CHANGELOG explicando a
  renomeacao, README/pointer, archive historico). Nenhuma referencia
  "viva" para arquivo dentro de `melhorias/...` que nao seja o
  pointer.
- `pytest` continua verde.

---

## Fase 4 — Refator do `cli/main.py`

Contexto: `src/evidence_collector/cli/main.py` tem 811 linhas com 11
comandos, helpers compartilhados, flag global `_LOG_JSON`, exceptions
sub-app, exit-code policy e UTF-8 stream reconfig. Vamos separar em
modulo por comando + auxiliares, preservando o contrato externo.

Layout alvo:

```
src/evidence_collector/cli/
├── __init__.py                # ja existe; nao mover
├── main.py                    # slim entrypoint: app, callback, main(), reexports
├── _state.py                  # _LOG_JSON, EVIDENCE_ADAPTER, Console, set_json_logs, is_json_logs
├── _logging.py                # configure_logging, emit_event
├── _render.py                 # render_summary, render_collection_errors
├── _exit_codes.py             # exit_code_for_status, fail_on_exit_code
├── _builders.py               # build_application, build_release
└── commands/
    ├── __init__.py            # register_all(app); ordered COMMAND_MODULES
    ├── run.py
    ├── collect.py
    ├── evaluate.py
    ├── bundle_cmd.py
    ├── controls.py
    ├── compare.py
    ├── oscal.py
    ├── plugins.py
    ├── schema.py
    ├── doctor.py
    ├── exceptions.py
    └── verify.py              # vazio nesta fase; preenchido na Fase 6
```

Regras de execucao:

1. Criar primeiro os modulos auxiliares (`_state`, `_logging`,
   `_render`, `_exit_codes`, `_builders`). Cada um expoe uma API
   estavel e nao depende de Typer.
2. Cada modulo em `commands/` expoe `register(app: typer.Typer) ->
   None` que registra o comando no app raiz. Nada mais.
3. `commands/__init__.py` define `COMMAND_MODULES: tuple[Callable[[
   typer.Typer], None], ...]` em ordem coerente com o help atual
   (`run`, `collect`, `evaluate`, `bundle`, `controls`, `compare`,
   `oscal`, `plugins`, `schema`, `doctor`, `verify`, `exceptions`).
   `register_all(app)` itera e chama cada `register`.
4. `commands/exceptions.py` deve criar o sub-Typer `exceptions_app`
   localmente dentro de `register(app)` e fazer `app.add_typer(
   exceptions_app)` la dentro.
5. `commands/bundle_cmd.py` chama a logica de `evaluate` exposta como
   funcao `evaluate(...)` no modulo `commands/evaluate.py`. Nao
   duplicar codigo.
6. `commands/doctor.py` expoe `doctor_checks()` como funcao pura, sem
   instanciar Typer. Esse simbolo eh reexportado de `cli/main.py`
   como `_doctor_checks` para manter compat dos testes.
7. `main.py` final deve:
   - Definir o `app = typer.Typer(...)` raiz.
   - Chamar `register_all(app)`.
   - Definir `@app.callback(invoke_without_command=True)
     main_callback(...)` com flags `--verbose`, `--json-logs`,
     `--version` que reaproveitam `set_json_logs(...)`,
     `configure_logging(...)`.
   - Manter `_force_utf8_std_streams` e `def main()`.
   - Reexportar `_doctor_checks` para preservar imports de teste.

Restricoes:

- Nenhum nome de comando muda. Nenhuma flag muda. Nenhum codigo de
  saida muda. Nenhum evento NDJSON muda.
- Testes existentes que fazem
  `from evidence_collector.cli.main import app` e
  `from evidence_collector.cli.main import _doctor_checks` precisam
  continuar funcionando sem alteracao.

Documentacao da decisao:

8. Criar `docs/adr/0006-cli-command-modularization.md` no formato
   compressed MADR usado pelas outras ADRs do projeto. Incluir
   Status, Context, Decision, Alternatives considered, Consequences,
   Validation.
9. Adicionar entry no `docs/adr/README.md` no indice.

Criterio de aceite Fase 4:

- `wc -l src/evidence_collector/cli/main.py` < 120 linhas.
- `wc -l src/evidence_collector/cli/commands/*.py` total no entorno
  de 900 linhas distribuidas entre os comandos.
- `pytest -q` verde, incluindo `tests/integration/test_cli.py`,
  `tests/integration/test_cli_more_commands.py`,
  `tests/unit/test_doctor.py`, `tests/unit/test_json_logs.py`.
- `ruff check src tests scripts` clean.
- `mypy --strict src tests` clean (lembrar de instalar
  `.[dev,api,logs]` no venv).

---

## Fase 5 — `step-security/harden-runner` em todos os jobs Linux faltantes

Contexto: rodar `grep -L harden-runner .github/workflows/*.yml` mostra
quais workflows ainda nao tem o step. Hoje faltam:

- `.github/workflows/github-ci-cd.yml` (4 jobs Linux: `quality`,
  `package`, `sample-bundle`, `cross-os-determinism`; o job
  `sample-bundle-windows` NAO recebe harden-runner — a action nao
  suporta Windows).
- `.github/workflows/deploy-github-pages.yml` (2 jobs: `build`,
  `deploy`).
- `.github/workflows/release.yml` (5 jobs Linux: `quality`, `build`,
  `release-bundle`, `sign-and-publish`, `publish-pypi`,
  `publish-container`; o job `provenance` chama um reusable workflow
  externo e NAO recebe harden-runner local).

Acoes:

1. Em cada job Linux listado, inserir como PRIMEIRO step (antes do
   `actions/checkout`):

   ```yaml
   - name: Harden runner
     uses: step-security/harden-runner@8d3c67de8e2fe68ef647c8db1e6a09f647780f40 # v2
     with:
       egress-policy: audit
   ```

   O SHA acima ja eh o pin usado pelos demais workflows do projeto
   (`codeql.yml`, `mutation.yml`, etc.). Mantenha o `# v2` como
   comentario.

2. Nao adicionar em jobs Windows.
3. Nao adicionar no job `provenance` do `release.yml`.

Criterio de aceite Fase 5:

- `python -c "import yaml,glob; [yaml.safe_load(open(f)) for f in
  glob.glob('.github/workflows/*.yml')]"` sem erro (YAML valido).
- `actionlint .github/workflows/*.yml` clean (se o binario
  estiver disponivel).
- `grep -L harden-runner .github/workflows/*.yml` retorna lista vazia
  exceto pelos casos documentados (Windows / reusable workflow
  externo).

---

## Fase 6 — Comando `sdlc-evidence verify`

Contexto: o projeto promete bundles `bundle.json` deterministicos
(modulo campos volateis documentados). Hoje o CI gate aplica essa
regra durante a CI, mas o consumidor downstream nao tem comando para
recomputar e validar.

Acoes:

1. Criar `src/evidence_collector/application/integrity.py` expondo:

   ```python
   VOLATILE_TOP = frozenset({"bundle_id", "generated_at"})
   VOLATILE_EVIDENCE = frozenset({"collected_at"})
   VOLATILE_CONTROL = frozenset({"evaluated_at"})

   def normalize_bundle(data: dict[str, object]) -> bytes: ...
   def structural_sha256(bundle_path: Path) -> str: ...
   ```

   O conjunto de chaves volateis deve bater EXATAMENTE com o snippet
   inline atual no `github-ci-cd.yml` job
   `Determinism gate (re-run, normalize, compare SHA-256)`.

2. Criar `src/evidence_collector/cli/commands/verify.py` com o
   comando `verify <bundle.json>` aceitando `--expected <SHA>`:
   - sem `--expected`: imprime o SHA e exit 0.
   - com `--expected`: exit 0 em match, exit 2 em drift.
   - arquivo invalido ou ilegivel: exit 3.
   - suporte ao modo NDJSON via `is_json_logs()`: emitir eventos
     `verify_computed`, `verify_result`, `verify_failed`.

3. Atualizar `cli/commands/__init__.py` para registrar o `verify` na
   ordem `... doctor, verify, exceptions`.

4. Criar `tests/unit/test_verify_command.py` cobrindo:
   - `normalize_bundle` strip exatamente os campos `VOLATILE_*`.
   - `structural_sha256` estavel a mudancas so de campos volateis.
   - `structural_sha256` muda quando um campo nao-volatil muda.
   - CLI: exit 0 com match (`--expected SHA correto`).
   - CLI: exit 2 com drift (`--expected 0*64`).
   - CLI: exit 3 com JSON quebrado.
   - CLI: imprime digest sem `--expected`.

Criterio de aceite Fase 6:

- `sdlc-evidence verify --help` lista o comando.
- Testes do `test_verify_command.py` passam.
- `pytest -q` verde.

---

## Fase 7 — Classification confidence como campo de primeira classe

Contexto: hoje a heuristica de classificacao SARIF (driver_match vs
fallback_sast) so aparece implicitamente no `evaluation.rationale`.
Vamos promover para campo de primeira classe na evidencia, mantendo
retrocompat (campo opcional).

Acoes:

1. Em `src/evidence_collector/domain/models.py`, adicionar:

   ```python
   class EvidenceClassification(_BaseModel):
       confidence: ConfidenceLevel
       reason: Annotated[str, Field(min_length=1, max_length=60)]
       driver_name: str | None = Field(default=None, max_length=120)
   ```

   E acrescentar a `NormalizedEvidence`:

   ```python
   classification: EvidenceClassification | None = Field(
       default=None,
       description=(
           "Optional classification provenance for the evidence_type. "
           "Populated by parsers that apply a heuristic (currently "
           "the SARIF normalizer); absent when the evidence type is "
           "self-evident from the format."
       ),
   )
   ```

2. Em `src/evidence_collector/normalizers/engine.py`:
   - Importar `EvidenceClassification`.
   - Criar `_classify_sarif_with_provenance(tool_name, override) ->
     tuple[EvidenceType, EvidenceClassification]`. Reasons:
     - `manual_override` -> override usado, MEDIUM confidence.
     - `driver_match` -> token bate, HIGH confidence.
     - `fallback_sast` -> nada bate, default SAST, LOW confidence.
   - Manter `_classify_sarif(tool_name, override) -> EvidenceType`
     como projecao do novo (chama o `_with_provenance` e retorna
     `[0]`). Isso preserva os 25+ testes existentes de
     `test_classification_calibration.py` e `test_classification_edges.py`
     que importam `_classify_sarif`.
   - Em `normalize_sarif`, usar `_classify_sarif_with_provenance`,
     popular `classification=...` no `NormalizedEvidence`, e quando
     `classification.reason == "fallback_sast"` rebaixar o
     `confidence` overall para `ConfidenceLevel.LOW`.

3. Nao alterar outros normalizers (`normalize_sbom`, `normalize_zap`,
   `normalize_junit`, `normalize_attestation`,
   `normalize_pr_metadata`, `normalize_workflow_run`). O campo
   `classification` fica como `None` para esses, e o docstring do
   campo ja documenta esse comportamento.

4. Criar `tests/unit/test_classification_provenance.py` com 6
   casos:
   - SAST driver conhecido -> `driver_match`, HIGH.
   - Secrets driver conhecido -> `driver_match`, HIGH.
   - SCA driver conhecido -> `driver_match`, HIGH.
   - Override explicito -> `manual_override`, MEDIUM.
   - Driver desconhecido -> `fallback_sast`, LOW.
   - `_classify_sarif` legado continua retornando so o `EvidenceType`.

5. Atualizar `docs/limitations.md §2` adicionando paragrafo que
   descreve o novo campo `classification`, valores possiveis de
   `reason` e que reasons sao um vocabulario controlado.

Criterio de aceite Fase 7:

- `pytest -q` verde, incluindo `test_classification_calibration.py`
  e `test_classification_edges.py` (que nao foram modificados).
- Bundle `examples/sample_release/output/bundle.json` regerado pelo
  `Makefile run-example` carrega `classification` em cada evidencia
  SARIF (verifique manualmente apos `make run-example`).
- `mypy --strict` clean.

---

## Fase 8 — Snapshot test deterministico do bundle canonico

Contexto: existe gate de determinismo same-runner e cross-OS em CI,
mas nao ha snapshot persistido em fixture que congele o SHA-256 do
bundle do `examples/sample_release` ao longo do tempo. Qualquer
mudanca em parser/normalizer/scoring/encoder vai quebrar esse
snapshot explicitamente.

Acoes:

1. Criar `tests/integration/test_bundle_snapshot.py` que:
   - Roda `run_pipeline` com os mesmos parametros do `make
     run-example`.
   - Recomputa o SHA-256 estrutural via
     `structural_sha256(bundle_path)`.
   - Le o SHA esperado de
     `tests/fixtures/sample_release_snapshot.sha256` (linhas
     comecando com `#` sao ignoradas).
   - Falha com mensagem clara se o fixture estiver vazio (instrui a
     popular).
   - Falha com diff explicit se o SHA real divergir do snapshot.

2. Criar `tests/fixtures/sample_release_snapshot.sha256` apenas com
   header comentado (sem digest). Na primeira execucao local o teste
   vai falhar e imprimir o digest atual.

3. Rodar `pytest tests/integration/test_bundle_snapshot.py` localmente
   uma vez. Copiar o digest impresso para o arquivo
   `sample_release_snapshot.sha256` (uma linha sem `#`). Rodar de
   novo: deve passar.

Criterio de aceite Fase 8:

- `pytest tests/integration/test_bundle_snapshot.py -q` verde.
- `tests/fixtures/sample_release_snapshot.sha256` contem exatamente
  uma linha de 64 caracteres hex.

---

## Fase 9 — Verificacao final consolidada

Acoes:

1. `ruff check src tests scripts` clean.
2. `ruff format --check src tests scripts` clean.
3. `mypy --strict src tests` clean.
4. `pytest -q` verde com `--cov-fail-under=80`.
5. `actionlint .github/workflows/*.yml` clean.
6. `gitleaks detect --source . --no-git --redact` clean.
7. `python -m pip_audit .` clean.
8. `python -m bandit -r src` clean.
9. `semgrep scan --config p/security-audit --config p/secrets` clean.
10. `make run-example` produz bundle `ready 13/13` em
    `examples/sample_release/output/`.
11. `sdlc-evidence verify examples/sample_release/output/bundle.json`
    imprime o mesmo SHA que `tests/fixtures/sample_release_snapshot.sha256`.

Atualize `docs/release-readiness.md` com os numeros REAIS observados
nesta passada, com data `2026-05-10` e commit hash do HEAD da branch.

## Fase 10 — Commit, push, abertura de PR (sem release)

Acoes:

1. Commits em ordem (um por fase), mensagens conventional-commit:
   - `docs: reconcile tests and coverage numbers across docs (fase 1)`
   - `build: raise pytest --cov-fail-under from 70 to 80 (fase 2)`
   - `chore: consolidate melhorias/ into docs/program/ (fase 3)`
   - `refactor(cli): split cli/main.py into per-command modules + ADR-0006 (fase 4)`
   - `ci: add step-security/harden-runner to remaining linux jobs (fase 5)`
   - `feat(cli): add sdlc-evidence verify and integrity helpers (fase 6)`
   - `feat(domain): promote classification confidence to first-class (fase 7)`
   - `test: add bundle.json structural SHA-256 snapshot gate (fase 8)`
   - `docs: refresh release-readiness with 2026-05-10 baseline (fase 9)`

2. `git push -u origin chore/post-publication-hardening-v1-1-1`.

3. Abrir Pull Request com titulo: `chore: post-publication hardening
   pass (alvo v1.1.1)` e corpo contendo:
   - resumo de cada fase em uma linha.
   - tabela `(before, after)` de tests/coverage.
   - lista das mudancas externas que ficam para outra rodada:
     repo publico, branch protection, PyPI trusted publisher,
     Discussions, harden-runner em block mode (atual: audit).

NAO criar tag. NAO publicar release. NAO mergear o PR
automaticamente. O merge fica para revisao manual.

---

## Reportagem final

Ao fim de cada fase, imprimir um bloco com:

```
== FASE N — <titulo> ==
arquivos tocados: <lista relativa>
gates locais: <quais rodaram e resultado>
proximo passo: <fase seguinte ou final>
```

Ao fim de tudo, imprimir:

```
== RESUMO FINAL ==
fases concluidas: 0..10
tests: <antes> -> <depois>
coverage: <antes>% -> <depois>%
cli/main.py LOC: <antes> -> <depois>
workflows com harden-runner: <antes>/<total> -> <depois>/<total>
proximo passo manual: revisar PR <URL> e decidir merge.
```

Se em qualquer fase algo falhar ou exigir decisao humana, PARE,
descreva o problema com evidencia (comando rodado + output) e
aguarde instrucao. Nao tente arrumar fora do escopo deste prompt.

<<< FIM DO PROMPT
