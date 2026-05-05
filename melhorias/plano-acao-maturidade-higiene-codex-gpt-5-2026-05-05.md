# Plano de acao de maturidade e higiene - Secure SDLC Evidence Collector

Data: 2026-05-05  
Executor: Codex GPT-5  
Repositorio: `C:\Users\Lucas Grifoni\Downloads\My Projects - AppSec & DevSecOps\5.Projeto - Secure SDLC Evidence Collector`

## 1. Objetivo

Fazer um raio-x tecnico do estado real do projeto, higienizar o que tinha evidencia clara de lixo, duplicidade ou legado fora do fluxo principal, e definir o proximo passo de amadurecimento sem inventar features, controles, profiles, schemas ou comandos novos.

Este plano adapta o prompt original do projeto `OSS Security Policy as Code Starter Kit` para este projeto. A mudanca mais importante de escopo e:

- O projeto atual nao possui `profiles`.
- O equivalente real de analise aqui e o catalogo de controles, os tipos de evidencia, os comandos CLI, os exemplos, os workflows e os documentos de release readiness.
- Portanto, qualquer instrucao sobre "profiles" deve ser traduzida para "controles existentes do catalogo e fluxos de evidencia existentes".
- Nao criar profile novo.
- Nao criar controle novo.
- Nao criar flag nova.
- Nao criar schema novo.
- Nao alterar a proposta do produto.

## 2. Decisao executiva

Decisao: `GO WITH CAVEATS`

Justificativa objetiva:

- O core do produto esta funcional: CLI executa, testes passam, catalogo carrega, sample release gera `ready`, cenario negativo sem attestations gera `not_ready`, schema exporta, plugins listam, OSCAL exporta e o catalogo tem cobertura coerente para o escopo declarado.
- A estrutura de camadas esta profissional e nao precisa de reorganizacao agressiva agora.
- A seguranca basica validada localmente esta boa: Gitleaks limpo, actionlint limpo, `pip-audit .` limpo para o projeto, Trivy secret/misconfig limpo apos correcao do Dockerfile.
- Ainda existem caveats que impedem chamar isso de release perfeita/profissional sem ressalvas: validacao local nao cobriu Semgrep/Bandit, Docker build nao rodou porque o daemon Docker nao estava ativo, conectores GitHub/GitLab nao foram testados contra API real por ausencia de tokens, algumas acoes de release dependem de configuracao externa, e ainda ha documentacao/traceability que precisa ser refrescada com a baseline atual.

Conclusao pratica:

- `GO WITH CAVEATS` para uso local, dogfood, hardening e continuidade do projeto.
- Para release publica profissional, resolver os caveats P0/P1 abaixo antes de taguear ou publicar.

## 3. Evidencias coletadas nesta rodada

### 3.1 Estado Git inicial

Comando:

```powershell
git status --short --branch
```

Resultado observado:

```text
## main...origin/main
```

Estado inicial limpo, antes das alteracoes desta rodada.

### 3.2 Contrato real da CLI

Comandos executados:

```powershell
python -m evidence_collector.cli.main --version
python -m evidence_collector.cli.main --help
python -m evidence_collector.cli.main controls
python -m evidence_collector.cli.main doctor --json
python -m evidence_collector.cli.main plugins
python -m evidence_collector.cli.main schema --output output\schema-check.json
python -m evidence_collector.cli.main oscal --output output\raiox-oscal\catalog.json
```

Resultados observados:

- Versao: `1.0.1`.
- Comandos reais: `run`, `collect`, `evaluate`, `bundle`, `controls`, `compare`, `oscal`, `plugins`, `schema`, `doctor`, `exceptions`.
- `doctor --json`: zero checks obrigatorios falhando.
- `GITHUB_TOKEN` e `GITLAB_TOKEN`: ausentes, reportados como opcionais.
- `cosign`: ausente localmente, reportado como opcional.
- `schema`: exportacao OK.
- `plugins`: parsers `attestation`, `exception`, `junit`, `sarif`, `sbom`, `zap`; collectors `github`, `gitlab`, `local`.
- `controls`: catalogo carregou e exibiu 13 controles.

### 3.3 Testes e qualidade

Comandos executados:

```powershell
python -m pytest -q
python -m ruff check .
python -m mypy src tests
actionlint .github\workflows\*.yml
```

Resultados observados:

- `pytest`: `143 passed`, cobertura total `77.39%`, piso configurado `70%`.
- `ruff check .`: inicialmente falhou em `scripts/scrub_lab_artifacts.py` com `SIM102`; corrigido nesta rodada.
- `ruff check .` apos correcao: `All checks passed!`.
- `mypy src tests`: `Success: no issues found in 61 source files`.
- `actionlint`: limpo apos chamada com expansao PowerShell correta.

### 3.4 Validacao operacional de CLI

Comandos executados:

```powershell
python -m evidence_collector.cli.main run --application secure-sdlc-evidence-collector --repository LucasGrifoni/secure-sdlc-evidence-collector --release-id 1.0.1-smoke --commit-sha abcdef1234567890 --artifacts-dir examples\sample_release\artifacts --attestations-dir examples\sample_release\attestations --output-dir output\raiox-run --artifact-root .

python -m evidence_collector.cli.main collect --release-id 1.0.1-smoke --commit-sha abcdef1234567890 --artifacts-dir examples\sample_release\artifacts --attestations-dir examples\sample_release\attestations --output output\raiox-collect\evidence.json

python -m evidence_collector.cli.main evaluate --evidence output\raiox-collect\evidence.json --application secure-sdlc-evidence-collector --repository LucasGrifoni/secure-sdlc-evidence-collector --release-id 1.0.1-smoke --commit-sha abcdef1234567890 --output-dir output\raiox-evaluate

python -m evidence_collector.cli.main compare examples\sample_release\output\bundle.json output\raiox-run\bundle.json --format json

python -m evidence_collector.cli.main run --application no-attestations-check --repository local/no-attestations --release-id no-att --commit-sha abcdef1234567890 --artifacts-dir examples\sample_release\artifacts --output-dir output\raiox-no-attestations
```

Resultados observados:

- `run` com sample completo: `release_status=ready`, coverage `100`, confidence `59`, controles `met=13`, `missing=0`, evidencia `13`.
- `collect`: coletou 13 evidencias.
- `evaluate`: gerou bundle `ready` com 13 evidencias.
- `compare`: `ready -> ready`, deltas de coverage/confidence `0`, 13 controles unchanged.
- `run` sem attestations: `release_status=not_ready`, coverage `47`, confidence `100`, controles `met=5`, `partial=2`, `missing=6`; missing critical inclui code review, release approval, rollback plan e artifact signature. O exit code nao-zero e esperado por design do gate.

### 3.5 Seguranca local

Comandos executados:

```powershell
gitleaks detect --source . --no-git --redact --exit-code 1
python -m pip_audit .
trivy fs --scanners secret,misconfig --skip-dirs .git --skip-dirs output --skip-dirs build --skip-dirs .mypy_cache --skip-dirs .pytest_cache --skip-dirs .ruff_cache --skip-dirs .hypothesis --quiet .
```

Resultados observados:

- Gitleaks: `no leaks found`.
- `python -m pip_audit .`: `No known vulnerabilities found`.
- `python -m pip_audit` sem escopo de projeto encontrou vulnerabilidades no ambiente Python global, mas isso inclui pacotes fora do projeto; nao deve ser usado como evidencia direta contra este repositorio.
- Trivy inicialmente encontrou `AVD-DS-0026 LOW` por Dockerfile sem `HEALTHCHECK`.
- Dockerfile recebeu `HEALTHCHECK` usando `sdlc-evidence --version`.
- Trivy apos correcao: Dockerfile com `0` misconfigurations.

### 3.6 Docker

Comando tentado:

```powershell
docker build -t sdlc-evidence:raiox .
```

Resultado observado:

```text
failed to connect to the docker API at npipe:////./pipe/dockerDesktopLinuxEngine
```

Interpretacao:

- Docker CLI existe.
- Docker daemon / Docker Desktop Linux Engine nao estava ativo.
- Build da imagem nao foi validado nesta rodada.
- Deve permanecer como caveat de release ate ser executado em ambiente com daemon ativo.

## 4. Inventario atual do projeto

### 4.1 Estrutura principal

Camadas em `src/evidence_collector/`:

- `domain`: modelos Pydantic, enums e invariantes.
- `application`: orquestracao e comparacao de bundles.
- `collectors`: coleta local, GitHub e GitLab.
- `parsers`: SARIF, SBOM, JUnit, ZAP, attestations e exceptions.
- `normalizers`: conversao de artefatos parseados para evidencia canonica.
- `controls`: catalogo e motor de avaliacao.
- `scoring`: coverage, confidence e release status.
- `exporters`: JSON, Markdown, HTML e OSCAL.
- `cli`: interface Typer.
- `api`: superficie FastAPI opcional e read-only.

Conclusao:

- A organizacao por responsabilidade ja esta boa.
- Nao ha ganho real em reestruturar pastas agora.
- Reorganizacao cosmetica aumentaria risco sem melhorar maturidade.

### 4.2 Numeros reais observados

- Arquivos versionados: 220 antes da adicao desta rodada.
- Test files `test_*.py`: 20.
- Markdown files em `docs/`: 15.
- Workflows GitHub Actions: 10.
- Controles no catalogo: 13.
- Framework mix: 6 `NIST_SSDF`, 4 `ORG_INTERNAL`, 3 `OWASP_SAMM`.
- Criticality mix: 5 `critical`, 6 `high`, 2 `medium`.
- Required evidence types unicos: `artifact_signature`, `code_review`, `release_approval`, `rollback_plan`, `sast_scan`, `sbom`, `sca_scan`, `secrets_scan`, `test_result`, `threat_model`.
- Recommended evidence types unicos: `artifact_attestation`, `artifact_signature`, `dast_scan`, `pr_metadata`, `sca_scan`.

## 5. Higienizacao executada

### 5.1 Arquivos/diretorios removidos

Removidos por serem caches, build output, output de teste, metadata de build/editable install, scratch local ou documento legado sem uso operacional:

- `.coverage`
- `.cursorrules`
- `.hypothesis/`
- `.mypy_cache/`
- `.pytest_cache/`
- `.ruff_cache/`
- `.vscode/`
- `build/`
- `output/`
- `src/secure_sdlc_evidence_collector.egg-info/`
- `gitpage/CURSOR_PROMPT_GITPAGE.md`
- `seção do gitpage do meu perfil.txt`
- todos os `__pycache__/` sob `src/` e `tests/`
- `examples/labs/*/output/`
- `Plano de acao e execucao - Claude.md`

Todos os deletes recursivos foram feitos apos resolver e validar os caminhos absolutos dentro da raiz do workspace.

### 5.2 Arquivos mantidos de forma intencional

`Ideia do projeto.md` foi mantido.

Motivo:

- Ainda e referenciado por `examples/self_release/attestations/threat_model.yaml`.
- Aparece em bundle dogfood versionado.
- Tambem e citado em `gitpage/README.md`.
- Apagar sem migrar referencias quebraria rastreabilidade de evidencia historica.

Acao recomendada futura:

- Migrar a referencia de threat model para `THREAT_MODEL.md` ou para uma pagina oficial em `docs/`, regenerar os bundles afetados e so depois remover ou arquivar `Ideia do projeto.md`.
- Nao fazer isso como delete cego.

### 5.3 Correcoes de higiene aplicadas

- Corrigido `SIM102` em `scripts/scrub_lab_artifacts.py`.
- `Makefile` agora tem `RUFF_TARGETS ?= src tests scripts`.
- CI `github-ci-cd.yml` agora roda Ruff tambem em `scripts`.
- README badges atualizados para 143 testes e coverage 77%.
- README CLI atualizada para incluir `oscal`, `plugins` e `doctor`.
- `docs/release-readiness.md` atualizado com a validacao local real de 2026-05-05.
- `docs/index.md` deixou de afirmar PyPI publicado como fato; agora aponta que publicacao depende da configuracao externa de Trusted Publisher.
- `gitpage/README.md` deixou de listar o scratch `CURSOR_PROMPT_GITPAGE.md`.
- `.dockerignore` removeu entradas do plano legado apagado.
- Dockerfile recebeu `HEALTHCHECK`.
- CHANGELOG recebeu secao `[Unreleased]` com a higiene e ajustes desta rodada.

## 6. Pontos positivos

1. Arquitetura por camadas esta clara e coesa.
2. CLI principal esta fina o suficiente e delega para application/orchestrator.
3. Modelagem com Pydantic v2 e `extra='forbid'` aumenta previsibilidade de bundle.
4. Catalogo pequeno e objetivo, alinhado com a proposta evidence-first.
5. Test suite e ampla o suficiente para sustentar evolucao incremental.
6. Property-based tests e determinism tests elevam o nivel acima de um MVP comum.
7. `doctor`, `schema`, `compare`, `oscal` e `plugins` aumentam operabilidade real.
8. `docs/limitations.md` e honesto sobre presenca vs qualidade da evidencia.
9. Workflows cobrem CI, security CI, CodeQL, Scorecard, release, Pages, mutation e stale.
10. Gitleaks, Trivy e project-scoped pip-audit ficaram limpos localmente.
11. `sample_release` positivo e cenario sem attestations negativo validam bem o modelo de release gate.
12. `docs/MATURITY_STATUS.md` diferencia itens internos de acoes externas ainda pendentes.

## 7. Pontos negativos e riscos

### R1 - Release profissional ainda depende de evidencias externas

Itens como PyPI project, Trusted Publisher, branch protection e GitHub Discussions dependem de configuracao fora do repo. Enquanto isso nao estiver feito, a narrativa de release/publicacao precisa continuar com caveat.

Prioridade: P0  
Risco: release/provenance/governanca

### R2 - Validacao local nao cobriu tudo que o checklist exige

Semgrep e Bandit nao foram executados localmente nesta rodada. Docker build tambem nao rodou porque o daemon nao estava ativo.

Prioridade: P0  
Risco: release/security

### R3 - Documentacao historica ainda precisa refresh amplo

`docs/traceability.md` ainda declara last refreshed em 2026-04-24. Isso nao invalida o codigo, mas enfraquece a rastreabilidade se usado como evidencia de release atual.

Prioridade: P1  
Risco: auditoria/documentacao

### R4 - `Ideia do projeto.md` ainda funciona como referencia de evidencia

O arquivo parece legado, mas nao pode ser removido sem migrar referencias. Isso e uma pequena fragilidade de governanca documental.

Prioridade: P1  
Risco: rastreabilidade/documentacao

### R5 - Exceptions existem na CLI, mas faltam fixtures de excecao validas visiveis

`exceptions list` funciona, mas ao rodar em `attestations` gera muitos "invalid". Isso e correto tecnicamente, mas pode confundir usuario final. Falta um exemplo claro de `exceptions/` separado.

Prioridade: P1  
Risco: UX operacional/documentacao/testabilidade

### R6 - Assinatura de artefato e evidence-presence, nao verificacao criptografica

O projeto documenta essa limitacao, o que e positivo. Ainda assim, em situacoes extremas, o controle de assinatura nao deve ser tratado como prova criptografica completa sem verificacao upstream/consumer.

Prioridade: P1  
Risco: interpretacao indevida/security assurance

### R7 - Conectores SCM nao foram testados contra APIs reais nesta rodada

Sem `GITHUB_TOKEN`/`GITLAB_TOKEN`, o teste foi de contrato, import e estrutura. A coleta real de PR/workflow precisa de validacao controlada antes de afirmar maturidade operacional extrema.

Prioridade: P1  
Risco: integracao/operacao

### R8 - Workflow action pinning tem excecoes por tags

Ha uso forte de SHA pinning, mas tambem ha actions por tag em pontos de release/deploy. Isso pode ser aceitavel se justificado, mas nao deve ser descrito como "tudo pinado por SHA" sem ressalva.

Prioridade: P2  
Risco: supply chain/governanca

### R9 - Cobertura esta acima do piso, mas abaixo da meta de maturidade

Coverage atual `77.39%` passa o piso de `70%`, mas fica abaixo da meta de `85%` registrada em maturidade.

Prioridade: P2  
Risco: manutencao/regressao

## 8. Maturidade dos controles existentes

Nao ha profiles neste projeto. A lista abaixo analisa os 13 controles existentes sem inventar novos controles.

Legenda:

- Diario: adequado para uso operacional normal como gate de evidencia.
- Extremo: adequado para incidentes, auditoria pesada, release critica ou ambiente regulado sem depender apenas de interpretacao humana.
- Caveat: limitacao que precisa ser entendida pelo usuario.

| Controle | Estado para uso diario | Estado para uso extremo | Caveat principal |
|---|---|---|---|
| `SSDF-PW.7` SAST | Pronto | Parcial | Presenca de SARIF nao mede qualidade de regras/severidade/coverage real do scan. |
| `SSDF-PW.4` SCA | Pronto | Parcial | Presenca de SCA/SBOM nao prova que vulnerabilidades foram remediadas. |
| `ORG-SECRETS-SCAN` | Pronto | Parcial | Depende de ferramenta upstream e escopo do scan; historico Git precisa de Gitleaks/Trivy adequados. |
| `SSDF-PS.3` SBOM | Pronto | Parcial | SBOM presente nao prova completude ou atualizacao contra artefato final. |
| `SSDF-PW.8` Tests | Pronto | Parcial | JUnit presente nao prova qualidade dos testes ou cobertura funcional. |
| `ORG-CODE-REVIEW` | Pronto com evidencia local/API | Parcial | API real GitHub/GitLab precisa token e validacao; attestation manual pode ser aceita de boa fe. |
| `SSDF-PW.1` Threat model | Pronto | Parcial | Controle de presenca; conteudo do threat model requer review humano. |
| `ORG-RELEASE-APPROVAL` | Pronto | Parcial | Atende governanca de evidencia, nao valida autoridade real do aprovador sem processo externo. |
| `ORG-REL-ROLLBACK` | Pronto | Parcial | Plano existe, mas o tool nao executa ensaio de rollback. |
| `SSDF-PS.2` Artifact signing | Pronto como evidencia | Parcial | O collector registra assinatura; nao verifica criptograficamente a identidade/assinatura. |
| `SAMM-DESIGN-TA-1` | Pronto | Parcial | Mesma limitacao de conteudo do threat model. |
| `SAMM-IMPL-SB-2` | Pronto | Parcial | Assinatura/attestation sao recommended; qualidade depende do upstream. |
| `SAMM-VERIF-ST-1` | Pronto | Parcial | DAST e recommended; cobertura real de security testing depende do conjunto de scanners. |

Conclusao sobre "perfeito/pronto":

- Nenhum controle deve ser chamado de "perfeito" em sentido absoluto para situacoes extremas.
- Todos os 13 controles estao prontos para uso diario como checklist de evidencia, dentro das limitacoes documentadas.
- Para situacoes extremas, todos precisam de apoio de evidencia operacional forte e revisao humana. Isso e coerente com a proposta do projeto: o produto prova presenca e rastreabilidade de evidencia, nao substitui decisao de compliance ou AppSec.

## 9. Plano de acao priorizado

### P0-01 - Fechar baseline de release local reproduzivel

Impacto: alto  
Risco reduzido: release, regressao, confianca  
Urgencia: alta

Acao:

- Rodar em ambiente limpo:
  - `python -m pip install -e ".[dev,api,docs]"`
  - `python -m ruff check src tests scripts`
  - `python -m ruff format --check src tests scripts`
  - `python -m mypy src tests`
  - `python -m pytest -q`
  - `python -m evidence_collector.cli.main doctor --json`
  - `python -m evidence_collector.cli.main run ...sample_release...`
  - `python -m evidence_collector.cli.main run ...sem attestations...`
  - `python -m pip_audit .`
  - `gitleaks detect --source . --no-git --redact`
  - `trivy fs --scanners secret,misconfig .`
- Se Docker daemon estiver ativo:
  - `docker build -t sdlc-evidence:check .`
  - `docker run --rm sdlc-evidence:check --version`

Aceite:

- Todos os comandos obrigatorios passam.
- Qualquer comando nao executado fica documentado com motivo objetivo.
- Nao atualizar docs dizendo que passou algo que nao passou.

Trade-off:

- Pode aumentar tempo local, mas reduz release por otimismo.

### P0-02 - Resolver acoes externas de release

Impacto: alto  
Risco reduzido: publicacao, provenance, Scorecard  
Urgencia: alta se houver release publica

Acao:

- Criar projeto no PyPI.
- Configurar PyPI Trusted Publisher para owner/repo/workflow/env corretos.
- Ativar branch protection em `main`.
- Ativar GitHub Discussions se mantido como meta Tier 4.
- Rodar workflows em `main` e registrar resultado real.

Aceite:

- `docs/MATURITY_STATUS.md` deixa de listar essas acoes como pendentes quando forem feitas.
- Docs publicas nao afirmam publicacao antes de haver evidencia.

Trade-off:

- Depende de UI/terceiros; nao e resolvido apenas por commit.

### P1-01 - Refresh de traceability e release-readiness com a baseline atual

Impacto: alto  
Risco reduzido: auditoria/documentacao  
Urgencia: media-alta

Acao:

- Atualizar `docs/traceability.md` com data atual e resultados atuais.
- Revalidar os cenarios citados, inclusive labs se houver os artefatos.
- Registrar exatamente o que foi rodado e o que nao foi.
- Garantir consistencia entre README, CHANGELOG, MATURITY_STATUS, release-readiness e traceability.

Aceite:

- Nao existem numeros conflitantes de testes/cobertura em docs publicas.
- Cada promessa publica tem uma evidencia, teste ou limitacao associada.

Trade-off:

- Trabalho documental chato, mas essencial para produto de evidencia.

### P1-02 - Migrar referencia legada de `Ideia do projeto.md`

Impacto: medio-alto  
Risco reduzido: governanca documental  
Urgencia: media

Acao:

- Decidir se `Ideia do projeto.md` vira documento oficial em `docs/` ou se sera removido.
- Se remover:
  - atualizar `examples/self_release/attestations/threat_model.yaml` para apontar para `THREAT_MODEL.md` ou documento oficial;
  - regenerar `examples/self_release/output/bundle.json`;
  - atualizar qualquer README que mencione o arquivo;
  - validar testes e determinismo.

Aceite:

- Nenhum bundle ou attestation versionado aponta para arquivo removido.
- A rastreabilidade do threat model continua clara.

Trade-off:

- Regenerar bundles pode causar diffs grandes; precisa ser feito numa rodada controlada.

### P1-03 - Criar fixture/documentacao honesta para `exceptions`

Impacto: medio  
Risco reduzido: UX operacional  
Urgencia: media

Acao:

- Usar o schema existente de exceptions.
- Criar exemplo simples em `examples/sample_release/exceptions/` ou docs, sem mudar schema.
- Adicionar teste/validacao que `exceptions list` em pasta correta mostra pelo menos um item valido.
- Documentar claramente diferenca entre `attestations/` e `exceptions/`.

Aceite:

- Usuario final nao precisa inferir o formato de exception.
- `exceptions list examples/.../exceptions` gera saida util.
- Nao criar novo tipo de evidencia, schema ou controle.

Trade-off:

- Pode alterar o status de um bundle se a exception for incluida em pipeline; por isso o exemplo deve ser controlado e documentado.

### P1-04 - Validar conectores GitHub/GitLab com repositorio controlado

Impacto: medio-alto  
Risco reduzido: integracao real  
Urgencia: media

Acao:

- Usar repo/lab controlado, sem segredos em logs.
- Rodar PR/workflow collection real com token de baixa permissao.
- Confirmar comportamento de approval apos ultimo commit e workflow run.
- Registrar limitacoes sem publicar token ou dados sensiveis.

Aceite:

- Ha evidencia reproduzivel de coletor SCM real.
- Falhas sao documentadas com escopo e causa.

Trade-off:

- Exige cuidado operacional com credenciais e dados de terceiros.

### P2-01 - Revisar pinning de GitHub Actions

Impacto: medio  
Risco reduzido: supply chain  
Urgencia: media-baixa

Acao:

- Listar todas as `uses:`.
- Classificar SHA pinned, tag pinned por necessidade, tag pinned sem justificativa.
- Onde for viavel, trocar tag por SHA com comentario de versao.
- Onde nao for viavel, documentar excecao.

Aceite:

- README/docs nao afirmam pinning absoluto se houver excecoes.
- `actionlint` continua limpo.

Trade-off:

- SHA pinning aumenta seguranca, mas aumenta manutencao de atualizacoes.

### P2-02 - Subir coverage rumo a 85% com foco em gaps reais

Impacto: medio  
Risco reduzido: regressao/manutencao  
Urgencia: media-baixa

Acao:

- Priorizar modulos com cobertura baixa e alto risco:
  - `cli/main.py`
  - `application/compare.py`
  - `collectors/gitlab.py`
  - `exporters/_jinja.py`
- Adicionar testes de comportamento, nao snapshots frageis.

Aceite:

- Coverage sobe sem testar detalhes irrelevantes.
- Testes capturam edge cases ou contratos de usuario.

Trade-off:

- Mais testes podem aumentar manutencao se forem acoplados a output Rich. Preferir JSON/eventos e funcoes puras.

## 10. O que nao fazer

Nao fazer nesta proxima rodada:

- Criar novos controles.
- Criar profiles.
- Criar flags novas obrigatorias.
- Criar schema novo.
- Transformar limitacoes documentadas em promessas falsas.
- Reorganizar pastas de `src/` so por estetica.
- Apagar `Ideia do projeto.md` sem migrar referencias e regenerar outputs.
- Atualizar docs dizendo que Semgrep/Bandit/Docker build passaram se nao passaram.
- Mexer em release/tag/push sem uma validacao completa.

## 11. Proximo passo recomendado

Executar uma rodada fechada de "release evidence sync", com foco em:

1. Validar tudo em ambiente limpo.
2. Rodar Docker build com daemon ativo.
3. Atualizar `docs/traceability.md` e `docs/release-readiness.md` com evidencia atual.
4. Resolver ou documentar external actions de PyPI/branch protection/Discussions.
5. Criar fixture honesta de `exceptions`.
6. Decidir e executar migracao segura de `Ideia do projeto.md`.

Esse e o caminho mais maduro porque fortalece o que ja existe em vez de inventar mais produto.
