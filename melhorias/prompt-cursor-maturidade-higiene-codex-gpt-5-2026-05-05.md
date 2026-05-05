# Prompt para Cursor - maturidade e higiene sem inventar escopo

Repositorio alvo:

`C:\Users\Lucas Grifoni\Downloads\My Projects - AppSec & DevSecOps\5.Projeto - Secure SDLC Evidence Collector`

Documento base:

`melhorias/plano-acao-maturidade-higiene-codex-gpt-5-2026-05-05.md`

## Objetivo

Executar a proxima rodada de maturidade do Secure SDLC Evidence Collector focando apenas no que ja existe: CLI, catalogo de 13 controles, evidence bundle, docs, exemplos, workflows, Dockerfile, testes, fixtures e release readiness.

Nao inventar produto novo. Nao criar controles, profiles, schemas, flags ou features novas.

## Regras obrigatorias

1. Trabalhe sempre ancorado no estado real do repositorio.
2. Antes de alterar qualquer coisa, rode `git status --short --branch`.
3. Nao assuma que um gate passou sem rodar o comando.
4. Nao atualize documento dizendo que algo foi validado se o comando nao foi executado.
5. Nao criar `profiles`; este projeto nao possui esse conceito.
6. Nao criar controle novo no catalogo.
7. Nao alterar `schema_version` ou estrutura do bundle.
8. Nao criar flag nova na CLI.
9. Nao criar comando novo.
10. Nao mexer na proposta do produto.
11. Nao apagar `Ideia do projeto.md` sem migrar referencias e regenerar bundles afetados.
12. Nao reestruturar `src/evidence_collector/` se nao houver ganho real. A organizacao atual por camada ja esta adequada.
13. Toda recomendacao deve vir de evidencia: comando, codigo, documento ou output real.
14. Diferenciar claramente `implementado`, `parcial`, `documentado`, `pendente externo` e `nao validado`.
15. Se algo depende de GitHub UI, PyPI UI, token real ou Docker daemon, registrar como dependencia externa ou limitacao da rodada.

## Escopo permitido

Voce pode:

- Corrigir inconsistencias documentais.
- Atualizar badges/numeros com base em comandos rodados.
- Atualizar `docs/traceability.md`, `docs/release-readiness.md`, `docs/MATURITY_STATUS.md`, `docs/index.md`, `README.md` e `CHANGELOG.md` para refletirem o estado real.
- Melhorar exemplos/fixtures que usam estruturas ja existentes.
- Criar fixture de `exceptions` usando o schema existente.
- Adicionar testes para comandos e fluxos ja existentes.
- Rodar e documentar gates de qualidade e seguranca.
- Regenerar bundles versionados apenas se a alteracao de referencia/evidencia exigir isso.
- Ajustar scripts, Makefile ou workflow quando o ajuste for para cobrir o que ja existe.
- Corrigir achados objetivos de lint/security hygiene, sem ampliar escopo funcional.

Voce nao pode:

- Criar controle novo.
- Criar profile novo.
- Criar evidence type novo.
- Criar schema novo.
- Criar flag nova.
- Criar comando novo.
- Criar dashboard novo.
- Criar API endpoint novo.
- Criar collector novo.
- Mudar semantica do release status.
- Alterar `controls:` do catalogo salvo se for uma correcao comprovada de bug e autorizada explicitamente.

## Baseline obrigatoria

Rode e registre:

```powershell
git status --short --branch
python -m evidence_collector.cli.main --version
python -m evidence_collector.cli.main --help
python -m evidence_collector.cli.main controls
python -m evidence_collector.cli.main doctor --json
python -m evidence_collector.cli.main plugins
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src tests
python -m pytest -q
actionlint .github\workflows\*.yml
python -m pip_audit .
gitleaks detect --source . --no-git --redact --exit-code 1
trivy fs --scanners secret,misconfig --skip-dirs .git --skip-dirs output --skip-dirs build --skip-dirs .mypy_cache --skip-dirs .pytest_cache --skip-dirs .ruff_cache --skip-dirs .hypothesis --quiet .
```

Observacao para `actionlint` no PowerShell:

Se wildcard direto falhar, use:

```powershell
Get-ChildItem .github\workflows\*.yml | ForEach-Object { actionlint $_.FullName }
```

Se Semgrep ou Bandit estiverem disponiveis, rode tambem:

```powershell
semgrep scan --config p/security-audit --config p/secrets --error --metrics=off .
bandit -r src
```

Se nao estiverem disponiveis, nao instale nada sem necessidade. Registre como "nao executado localmente".

## Validacao operacional obrigatoria

Rode:

```powershell
python -m evidence_collector.cli.main run `
  --application secure-sdlc-evidence-collector `
  --repository LucasGrifoni/secure-sdlc-evidence-collector `
  --release-id validation-current `
  --commit-sha abcdef1234567890 `
  --artifacts-dir examples\sample_release\artifacts `
  --attestations-dir examples\sample_release\attestations `
  --output-dir output\cursor-validation-run `
  --artifact-root .

python -m evidence_collector.cli.main collect `
  --release-id validation-current `
  --commit-sha abcdef1234567890 `
  --artifacts-dir examples\sample_release\artifacts `
  --attestations-dir examples\sample_release\attestations `
  --output output\cursor-validation-collect\evidence.json

python -m evidence_collector.cli.main evaluate `
  --evidence output\cursor-validation-collect\evidence.json `
  --application secure-sdlc-evidence-collector `
  --repository LucasGrifoni/secure-sdlc-evidence-collector `
  --release-id validation-current `
  --commit-sha abcdef1234567890 `
  --output-dir output\cursor-validation-evaluate

python -m evidence_collector.cli.main compare `
  examples\sample_release\output\bundle.json `
  output\cursor-validation-run\bundle.json `
  --format json

python -m evidence_collector.cli.main oscal --output output\cursor-validation-oscal\catalog.json
python -m evidence_collector.cli.main schema --output output\cursor-validation-schema\bundle.schema.json
```

Rode tambem o cenario negativo:

```powershell
python -m evidence_collector.cli.main run `
  --application no-attestations-check `
  --repository local/no-attestations `
  --release-id no-attestations `
  --commit-sha abcdef1234567890 `
  --artifacts-dir examples\sample_release\artifacts `
  --output-dir output\cursor-validation-no-attestations
```

Esse comando deve retornar `not_ready` e pode sair com exit code nao-zero por design. Nao trate isso como falha se o output for coerente.

## Tarefas de execucao

### Tarefa 1 - Sincronizar documentacao com o estado real

Revise:

- `README.md`
- `CHANGELOG.md`
- `docs/index.md`
- `docs/release-readiness.md`
- `docs/traceability.md`
- `docs/MATURITY_STATUS.md`
- `docs/limitations.md`
- `gitpage/README.md`

Corrija apenas afirmacoes inconsistentes com a evidencia atual.

Pontos especificos a validar:

- Quantidade de testes.
- Coverage real.
- Lista real de comandos CLI.
- Estado real de PyPI publishing.
- Estado real de Docker build.
- Estado real de Semgrep/Bandit se nao rodaram.
- Last refreshed/last validation dates.
- Se os workflows realmente usam SHA pinning em todos os pontos ou se ha excecoes por tag.

Aceite:

- Nao existem badges ou frases com numeros antigos conflitantes.
- Docs nao dizem "publicado" quando a publicacao depende de setup externo.
- Docs nao dizem "clean" para scanner nao executado.

### Tarefa 2 - Resolver ou registrar dependencia externa de release

Nao tente resolver via codigo o que depende de UI externa.

Verifique e registre em `docs/MATURITY_STATUS.md`:

- PyPI project criado ou pendente.
- PyPI Trusted Publisher configurado ou pendente.
- Branch protection em `main` configurado ou pendente.
- GitHub Discussions habilitado ou pendente.
- OpenSSF Scorecard ja executado e com score real ou ainda pendente.

Aceite:

- Cada dependencia externa tem status honesto.
- Se estiver pendente, a documentacao nao representa como concluido.

### Tarefa 3 - Criar exemplo honesto de exceptions usando schema existente

Objetivo:

Demonstrar `sdlc-evidence exceptions validate` e `exceptions list` em pasta correta.

Regras:

- Usar schema existente.
- Nao criar evidence type.
- Nao alterar catalogo.
- Nao alterar semantica de waivers.

Possivel caminho:

- Criar `examples/sample_release/exceptions/README.md`.
- Criar uma exception YAML minima e valida apenas se ela nao quebrar o sample positive fixture.
- Se uma exception alterar o bundle esperado, mantenha fixture separada e documente que e para validar a CLI de exceptions, nao o sample release `ready`.

Comandos de aceite:

```powershell
python -m evidence_collector.cli.main exceptions validate <arquivo-da-exception>
python -m evidence_collector.cli.main exceptions list <pasta-de-exceptions>
python -m pytest -q
```

### Tarefa 4 - Migrar ou manter `Ideia do projeto.md` com decisao explicita

Estado atual:

- `Ideia do projeto.md` ainda e referenciado por `examples/self_release/attestations/threat_model.yaml`.
- Tambem aparece em bundle dogfood e docs do GitPage.

Escolha uma das duas opcoes:

Opcao A - manter:

- Registrar no plano/documento que ele continua como fonte historica/produto.
- Nao apagar.

Opcao B - migrar:

- Mover conteudo essencial para `docs/` ou apontar para `THREAT_MODEL.md`.
- Atualizar `examples/self_release/attestations/threat_model.yaml`.
- Regenerar `examples/self_release/output/bundle.json`.
- Atualizar referencias em `gitpage/README.md`.
- Rodar testes e determinism checks.

Nao executar delete sem completar a migracao.

### Tarefa 5 - Refresh de traceability

Atualize `docs/traceability.md` com resultados atuais.

Nao invente resultados de labs. Se nao rodar todos os labs, declare:

- "nao revalidado nesta rodada"
- motivo
- comando esperado para proxima rodada

Se rodar labs, use scripts existentes:

```powershell
bash scripts/scan_all_labs.sh
```

Se estiver no Windows sem Bash funcional, nao reescreva scripts; registre limitacao ou rode comandos equivalentes de CLI sem alterar produto.

### Tarefa 6 - Revisar pinning de GitHub Actions

Liste todas as linhas `uses:`.

Classifique:

- SHA pinned.
- Tag pinned justificado.
- Tag pinned sem justificativa.

Nao altere tudo mecanicamente se isso aumentar risco.

Se alterar:

- Use SHA com comentario de versao.
- Rode `actionlint`.
- Atualize docs para nao prometer pinning absoluto se ainda houver excecoes.

### Tarefa 7 - Coverage focada, se houver tempo

Nao aumente coverage por cobertura cosmetica.

Priorize:

- `cli/main.py`
- `application/compare.py`
- `collectors/gitlab.py`
- `exporters/_jinja.py`

Regras:

- Testar comportamento observavel.
- Evitar snapshots frageis de tabela Rich.
- Preferir JSON, funcoes puras e erros de contrato.
- Nao criar API nova para facilitar teste.

Aceite:

```powershell
python -m pytest -q
```

Coverage deve subir ou, se nao subir, os testes devem cobrir risco real documentado.

## Higiene final obrigatoria

Antes de encerrar:

1. Remova caches e outputs gerados usando validacao de caminho:

```powershell
$root = (Resolve-Path -LiteralPath .).Path
$targets = New-Object System.Collections.Generic.List[string]
foreach ($rel in @('.coverage', '.pytest_cache', '.mypy_cache', '.ruff_cache', '.hypothesis', 'output', 'build')) {
  $candidate = Join-Path $root $rel
  if (Test-Path -LiteralPath $candidate) {
    $targets.Add((Resolve-Path -LiteralPath $candidate).Path)
  }
}
Get-ChildItem -Path $root -Recurse -Directory -Force -Filter '__pycache__' | ForEach-Object {
  $targets.Add($_.FullName)
}
$prefix = $root.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$targets | Sort-Object -Unique | ForEach-Object {
  if ($_ -eq $root -or -not $_.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to remove outside workspace: $_"
  }
  Remove-Item -LiteralPath $_ -Recurse -Force
}
```

2. Nunca execute delete recursivo sobre caminho calculado sem a validacao acima.
3. Rode:

```powershell
git status --short --branch
git status --ignored --short
```

4. Nao deixe `output/`, `build/`, `__pycache__/`, `.coverage`, `.pytest_cache/`, `.mypy_cache/`, `.ruff_cache/` ou `.hypothesis/` no working tree.

## Formato obrigatorio da resposta final

Responder com:

1. Objetivo executado.
2. Estado inicial encontrado.
3. Arquivos alterados/criados/removidos.
4. Comandos executados e resultados.
5. Principais achados.
6. Decisao final: `GO`, `GO WITH CAVEATS` ou `NO-GO`.
7. Limitacoes conhecidas.
8. Proximo passo recomendado.

## Criterio de sucesso

A rodada so esta concluida se:

- O repositório estiver mais limpo.
- As docs estiverem mais verdadeiras.
- Os gates principais tiverem evidencia real.
- Nenhum controle/profile/schema/flag novo tiver sido criado.
- As pendencias externas estiverem claramente separadas de pendencias de codigo.
- A decisao final nao inflar a maturidade do projeto.
