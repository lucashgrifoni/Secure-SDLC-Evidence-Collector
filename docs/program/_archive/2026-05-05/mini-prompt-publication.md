# Mini prompt para Claude Code

```text
Voce esta no repositorio:
C:\Users\Lucas Grifoni\Downloads\My Projects - AppSec & DevSecOps\5.Projeto - Secure SDLC Evidence Collector

Objetivo: executar o plano de melhorias ate deixar o projeto release-ready para v1.1.0, sem publicar nada antes dos gates e das acoes externas obrigatorias.

Leia primeiro, nesta ordem:
1. melhorias/README.md
2. melhorias/validacao-cruzada-codex-claude-2026-05-05.md
3. melhorias/plano-de-acao-publicacao-v1-1-0-2026-05-05.md
4. melhorias/checklist-acoes-externas-publicacao-2026-05-05.md
5. melhorias/prompts-claude-code-publicacao-v1-1-0-2026-05-05.md

Regras obrigatorias:
- Comece com `git status --short --branch`, `git diff --name-status` e `git diff --stat`.
- Nao reverta nem apague mudancas do usuario sem autorizacao explicita.
- Preserve todos os arquivos existentes em `melhorias/`.
- Nao mover tags existentes.
- Nao criar tag, release, push de release ou publish PyPI/GHCR ate todos os gates passarem.
- Nao criar comando, flag, schema, evidence type, controle, collector ou feature nova.
- Nao afirmar que CI, Semgrep, Bandit, Docker, cosign, SLSA, PyPI ou GHCR passaram sem rodar e registrar evidencia.
- Quando algo depender de GitHub UI, PyPI UI, token real ou Docker daemon, pare e liste exatamente a acao externa necessaria.

Execute por fases:
1. Rode o Prompt 0 do arquivo `prompts-claude-code-publicacao-v1-1-0-2026-05-05.md` e confirme o estado inicial.
2. Execute os Prompts 1 a 5 para higiene local, links/metadados, licenca, docs e versionamento v1.1.0.
3. Rode os gates locais obrigatorios:
   - `python -m ruff check src tests scripts`
   - `python -m ruff format --check src tests scripts`
   - `python -m mypy src tests`
   - `python -m pytest`
   - `python -m pip_audit .`
   - `gitleaks detect --source . --redact --verbose`
   - `actionlint` nos workflows
4. Execute o Prompt 6 para validar ou diagnosticar GitHub Actions remoto.
5. Pare antes dos Prompts 7 a 10 se faltar qualquer acao externa de GitHub/PyPI.

Entrega final:
- arquivos alterados;
- comandos executados e resultados;
- pendencias externas;
- decisao `GO`, `GO WITH CAVEATS` ou `NO-GO`;
- proximo passo exato.
```
