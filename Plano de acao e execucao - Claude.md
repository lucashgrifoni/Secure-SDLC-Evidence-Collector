# Plano de acao e execucao para o Claude

## 1. Objetivo do handoff

Implementar um **MVP funcional, auditavel e demonstravel** do **Secure SDLC Evidence Collector**, priorizando:

- modelo de evidencia bem definido
- coleta automatizada de evidencias essenciais
- correlacao por release
- score de cobertura e status de release
- geracao de bundle e relatorio

O Claude deve tratar este projeto como um produto **CLI-first**, orientado a pipeline e focado em **release readiness por evidencias**, nao como uma plataforma de dashboard completa.

---

## 2. Resultado esperado ao final do MVP

Ao final da execucao, o projeto deve conseguir:

1. Receber contexto de uma release.
2. Coletar evidencias de arquivos locais e GitHub/GitHub Actions.
3. Normalizar essas evidencias para um schema canonico.
4. Avaliar um conjunto inicial de controles.
5. Calcular score de cobertura e classificar a release.
6. Gerar `bundle.json`, `report.md` e `summary.html`.
7. Rodar localmente e em pipeline.

---

## 3. Premissas de implementacao

- O repositorio esta praticamente vazio; Claude deve estruturar o projeto desde o inicio.
- O MVP deve minimizar UI e maximizar demonstracao tecnica e valor AppSec.
- O primeiro alvo de integracao deve ser **GitHub + GitHub Actions**.
- O stack recomendado deve priorizar velocidade, qualidade de modelagem e testabilidade.
- O bundle final deve ser deterministico e auditavel.

---

## 4. Escopo obrigatorio do MVP

### Entradas obrigatorias

- contexto de release: `application`, `release_id`, `commit_sha`
- artefatos locais
- resultado de SAST
- resultado de SCA
- SBOM
- test result
- metadata de PR/review
- attestation manual para threat model
- attestation manual para release approval
- attestation manual para rollback plan
- attestation de assinatura ou integridade de artefato

### Saidas obrigatorias

- `bundle.json`
- `report.md`
- `summary.html`
- `release_status`
- lista de gaps
- score de cobertura

### Fora do escopo do MVP

- multi-tenancy
- interface web rica
- analytics historicos avancados
- excecoes complexas com workflow humano completo
- suporte amplo a multiplos SCM/CI

---

## 5. Stack recomendada

### Linguagem e base

- **Python 3.12**
- **FastAPI** para API opcional e futura extensibilidade
- **Typer** para CLI principal
- **Pydantic v2** para schemas
- **SQLAlchemy** ou **SQLModel** apenas se houver necessidade de persistencia local alem de arquivos

### Qualidade e testes

- **pytest**
- **ruff**
- **mypy**
- **pre-commit**

### Relatorios

- **Jinja2** para Markdown/HTML templating

### Formatos suportados no MVP

- JSON
- SARIF
- JUnit XML
- CycloneDX JSON
- SPDX JSON
- YAML/JSON para attestations manuais

### Persistencia recomendada

Comecar com:

- armazenamento local em `artifacts/`, `examples/` e `output/`
- bundle final em arquivo JSON
- opcionalmente um pequeno SQLite para catalogar execucoes

Se a persistencia nao for necessaria no MVP, evitar banco inicialmente.

---

## 6. Estrutura recomendada do repositorio

```text
secure-sdlc-evidence-collector/
  src/evidence_collector/
    domain/
    application/
    collectors/
    parsers/
    normalizers/
    controls/
    scoring/
    exporters/
    cli/
    api/
  tests/
    unit/
    integration/
    fixtures/
  examples/
    sample_release/
  docs/
  output/
  pyproject.toml
  README.md
```

### Responsabilidade por camada

- `domain/`: entidades, enums, schemas, regras nucleares
- `application/`: orchestrators e casos de uso
- `collectors/`: integracoes e ingestion adapters
- `parsers/`: leitura de formatos brutos
- `normalizers/`: conversao para evidencia canonica
- `controls/`: definicoes e avaliacoes de controles
- `scoring/`: calculo de score e status
- `exporters/`: JSON/Markdown/HTML bundle e relatorios
- `cli/`: ponto principal de execucao do MVP
- `api/`: opcional, so depois da CLI funcionar bem

---

## 7. Modelo minimo que Claude deve implementar primeiro

Claude nao deve comecar por collectors ou UI. O primeiro trabalho deve ser estabilizar o modelo.

### Entidades minimas

- `Application`
- `ReleaseContext`
- `EvidenceSource`
- `RawEvidenceRef`
- `NormalizedEvidence`
- `ControlDefinition`
- `ControlEvaluation`
- `Gap`
- `EvidenceBundle`

### Enums minimos

- `EvidenceType`
- `EvidenceStatus`
- `ConfidenceLevel`
- `ReleaseStatus`
- `ControlEvaluationStatus`

### Regras minimas

- diferenciar evidence bruta de evidence normalizada
- cada avaliacao de controle precisa apontar para `evidence_refs`
- ausencia de evidencia critica deve afetar `release_status`
- evidencias manuais devem possuir `confidence` inferior por padrao

---

## 8. Backlog prioritario por epico

### Epico 1: Fundacao do projeto

**Objetivo**
Criar a base limpa do repositorio, stack, qualidade e estrutura.

**Tarefas**

- inicializar projeto Python
- configurar `pyproject.toml`
- configurar ruff, mypy e pytest
- criar estrutura `src/` e `tests/`
- escrever README inicial

**Sinal de conclusao**

- projeto instala
- lint roda
- type-check roda
- testes vazios passam

### Epico 2: Modelo de dominio e schema canonico

**Objetivo**
Definir o contrato central do produto antes de qualquer integracao.

**Tarefas**

- criar entidades e enums principais
- definir schema de bundle
- criar fixtures de exemplo
- validar serializacao/deserializacao

**Sinal de conclusao**

- bundle JSON valido
- testes de schema passando

### Epico 3: Ingestao local e parsers

**Objetivo**
Permitir que o sistema leia artefatos locais e converta formatos basicos.

**Tarefas**

- parser SARIF
- parser CycloneDX/SPDX
- parser JUnit
- parser YAML/JSON de attestation

**Sinal de conclusao**

- fixtures reais geram evidencias normalizadas

### Epico 4: Collectors GitHub e GitHub Actions

**Objetivo**
Trazer dados reais de PR, approvals e pipeline.

**Tarefas**

- coletor de PR metadata
- coletor de reviewers e approvals
- coletor de run metadata
- associacao com release context

**Sinal de conclusao**

- uma release com dados do GitHub gera evidencias correlacionadas

### Epico 5: Motor de controles e scoring

**Objetivo**
Transformar evidencias em avaliacao explicavel.

**Tarefas**

- definir controles iniciais
- implementar regras de satisfacao
- identificar gaps obrigatorios
- calcular score de cobertura
- calcular `release_status`

**Sinal de conclusao**

- mesmo conjunto de entradas produz score e status consistentes

### Epico 6: Exporters e bundle final

**Objetivo**
Entregar artefatos consumiveis por humanos e automacao.

**Tarefas**

- exporter JSON
- exporter Markdown
- exporter HTML
- resumo executivo do bundle

**Sinal de conclusao**

- uma execucao gera os tres arquivos esperados

### Epico 7: CLI operacional

**Objetivo**
Criar a interface principal de uso do MVP.

**Tarefas**

- comando `collect`
- comando `evaluate`
- comando `bundle`
- comando `run` de ponta a ponta

**Sinal de conclusao**

- comando unico executa o fluxo completo da release

### Epico 8: Testes, exemplos e pipeline

**Objetivo**
Fechar o MVP com verificacao e demonstrabilidade.

**Tarefas**

- testes unitarios
- testes de integracao com fixtures
- exemplo de release realista
- pipeline GitHub Actions com lint, mypy e pytest

**Sinal de conclusao**

- repositorio pode ser clonado e demonstrado sem trabalho manual extra

---

## 9. Ordem exata de execucao para Claude

Claude deve seguir esta ordem e nao pular etapas:

1. Estruturar o repositorio e a base Python.
2. Implementar o modelo de dominio e schemas.
3. Criar fixtures de exemplo e testes de schema.
4. Implementar parsers locais.
5. Implementar normalizers.
6. Implementar regras de controles e scoring.
7. Implementar geracao de bundle e relatorios.
8. Implementar CLI ponta a ponta.
9. Integrar GitHub/GitHub Actions.
10. Fechar com testes, README e pipeline CI.

### Regra importante

Se Claude inverter a ordem e comecar por API, dashboard ou integracoes demais, o projeto perde foco. O modelo de evidencia e a cadeia de avaliacao sao a parte mais valiosa do produto.

---

## 10. Fases detalhadas de execucao

## Fase 1 - Bootstrap tecnico

**Objetivo**
Criar um esqueleto profissional e verificavel.

**Entregaveis**

- `pyproject.toml`
- estrutura `src/` e `tests/`
- `README.md`
- configuracoes de qualidade

**Criterios de aceite**

- `ruff check` passa
- `mypy` passa
- `pytest` passa

## Fase 2 - Schema e dominio

**Objetivo**
Modelar o produto de forma correta antes das integracoes.

**Entregaveis**

- entidades Pydantic
- enums
- schema de bundle
- exemplos serializados

**Criterios de aceite**

- bundle de exemplo valida
- erros de schema sao claros

## Fase 3 - Ingestao local

**Objetivo**
Dar vida ao MVP sem depender de APIs externas primeiro.

**Entregaveis**

- leitores de SARIF, SBOM, JUnit e attestation
- normalizacao para `NormalizedEvidence`

**Criterios de aceite**

- fixtures de exemplo geram evidencias validas

## Fase 4 - Avaliacao e status

**Objetivo**
Responder as perguntas centrais do produto.

**Entregaveis**

- definicao de controles iniciais
- engine de avaliacao
- engine de score
- gaps e release status

**Criterios de aceite**

- bundle final informa claramente por que a release esta pronta ou nao

## Fase 5 - Exportacao

**Objetivo**
Produzir saidas reutilizaveis.

**Entregaveis**

- JSON bundle
- Markdown report
- HTML summary

**Criterios de aceite**

- outputs sao legiveis, rastreaveis e consistentes

## Fase 6 - CLI ponta a ponta

**Objetivo**
Executar o produto como ferramenta real.

**Entregaveis**

- comando unico `run`
- parametros de entrada documentados
- output previsivel

**Criterios de aceite**

- um comando gera todo o pacote final

## Fase 7 - Integracao GitHub

**Objetivo**
Conectar o MVP ao ambiente mais relevante para demonstracao.

**Entregaveis**

- coletor de PR e approvals
- coletor de metadata de workflow
- associacao correta com release context

**Criterios de aceite**

- uma release baseada em GitHub Actions pode ser avaliada

## Fase 8 - Fechamento de qualidade

**Objetivo**
Deixar o repositorio pronto para demonstracao e evolucao.

**Entregaveis**

- testes finais
- README completo
- exemplos de execucao
- GitHub Actions CI

**Criterios de aceite**

- projeto demonstra qualidade basica de engenharia e AppSec

---

## 11. Controles iniciais que Claude deve suportar

Para o MVP, Claude nao deve tentar cobrir o SSDF inteiro. Deve implementar um conjunto pequeno e forte:

- evidencia de SAST executado
- evidencia de SCA executado
- evidencia de secrets scan executado
- evidencia de SBOM gerada
- evidencia de testes executados
- evidencia de code review/aprovacao
- evidencia de threat model ou justificativa
- evidencia de release approval
- evidencia de rollback plan
- evidencia de assinatura/integridade de artefato

Cada controle deve ter:

- `control_id`
- descricao
- criticidade
- evidencias aceitas
- regra de satisfacao
- regra de impacto no `release_status`

---

## 12. Regras de decisao recomendadas

Claude deve implementar regras simples, explicaveis e seguras:

- se faltar evidencia critica, `release_status = not_ready`
- se faltar apenas evidencia recomendada, `release_status = conditional`
- se tudo obrigatorio existir, `release_status = ready`
- evidencias manuais devem registrar menor confianca
- excecoes, se existirem, precisam de aprovador, justificativa e expiracao

---

## 13. Testes obrigatorios

Claude deve escrever testes desde o inicio.

### Unitarios

- serializacao do schema
- parsers
- normalizers
- scoring
- regras de controle

### Integracao

- fluxo de uma release completa com fixtures
- geracao dos tres outputs finais
- cenario com release aprovada
- cenario com release bloqueada por gap critico

### Regressao

- bundles com campos obrigatorios ausentes
- evidencias duplicadas
- artefatos invalidos ou corrompidos

---

## 14. Qualidade minima exigida

Claude nao deve declarar o MVP pronto sem:

- `ruff check`
- `mypy`
- `pytest`
- README atualizado
- exemplo de execucao documentado
- exemplo de output gerado

Se houver pipeline GitHub Actions, ela deve reproduzir pelo menos:

- lint
- type-check
- testes

---

## 15. Riscos que Claude deve controlar

### Risco 1: escopo explodir

Mitigacao:
manter foco em CLI-first, GitHub-first e poucos tipos de evidencia.

### Risco 2: schema fraco

Mitigacao:
estabilizar o modelo antes de integracoes.

### Risco 3: score virar marketing

Mitigacao:
sempre explicar score, gaps e racional.

### Risco 4: integracoes quebrarem o MVP

Mitigacao:
usar fixtures locais e adapters simples primeiro.

### Risco 5: auditoria sem lineage

Mitigacao:
todo controle avaliado deve apontar para evidencias concretas.

---

## 16. Decisoes arquiteturais recomendadas

- priorizar interfaces pequenas e plugaveis para collectors
- manter o dominio puro, sem dependencia direta de framework
- separar parser, normalizer e evaluator
- tratar bundle como artefato principal do sistema
- evitar banco se arquivo resolver o MVP
- adicionar API apenas depois que a CLI estiver madura

---

## 17. Definition of Done do MVP

O MVP so esta pronto quando:

1. Existe comando de execucao ponta a ponta.
2. O comando recebe uma release e gera bundle, relatorio e status.
3. Pelo menos cinco tipos de evidencia funcionam de verdade.
4. GitHub/GitHub Actions estao integrados em nivel basico.
5. O output explica claramente gaps e controles avaliados.
6. Testes automatizados cobrem schema, parsers, scoring e fluxo principal.
7. README explica setup, uso e estrutura.

---

## 18. Prompt sugerido para iniciar o Claude

```text
Implemente o MVP do projeto "Secure SDLC Evidence Collector" neste repositorio.

Objetivo:
Construir uma ferramenta CLI-first em Python que colete, normalize e avalie evidencias de Secure SDLC por release, gerando bundle.json, report.md e summary.html.

Documentos de referencia obrigatorios:
- Ideia do projeto.md
- Plano de acao e execucao - Claude.md

Regras de execucao:
- siga a ordem de implementacao descrita no plano
- nao comece por UI rica
- estabilize primeiro o modelo de dominio e o schema de evidencias
- implemente testes desde o inicio
- mantenha o dominio desacoplado dos adapters
- priorize GitHub e GitHub Actions como primeira integracao
- use Python 3.12, Typer, Pydantic, pytest, ruff e mypy

Escopo obrigatorio do MVP:
- ingestao local de SARIF, SBOM, JUnit e attestations JSON/YAML
- coleta basica de PR approvals e workflow metadata do GitHub
- mapeamento inicial de controles
- score de cobertura
- release_status ready/conditional/not_ready
- exporters JSON, Markdown e HTML

Criterios de conclusao:
- ruff, mypy e pytest passando
- README atualizado
- exemplo executavel com fixtures
- pacote final gerado com sucesso
```

---

## 19. Primeira entrega recomendada

Se o trabalho for dividido em iteracoes, a **primeira entrega ideal** deve conter:

- bootstrap do projeto
- schema do bundle
- enums e entidades principais
- um fluxo minimo com fixtures locais
- bundle JSON gerado
- testes iniciais

Essa primeira entrega ja cria a base correta para o restante do projeto.
