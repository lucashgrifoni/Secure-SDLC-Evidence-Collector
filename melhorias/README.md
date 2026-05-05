# Melhorias - indice operacional

Data base: 2026-05-05

Esta pasta concentra planos, validacoes e prompts para amadurecer o Secure
SDLC Evidence Collector ate um estado publicavel. Ela nao e codigo de produto.

## Arquivos desta rodada

- `validacao-cruzada-codex-claude-2026-05-05.md`: reconciliacao entre o raio-x do Codex e o raio-x do Claude Code, com o que foi validado, corrigido ou ficou incerto.
- `plano-de-acao-publicacao-v1-1-0-2026-05-05.md`: plano de execucao priorizado para sair do estado atual ate publicacao.
- `prompts-claude-code-publicacao-v1-1-0-2026-05-05.md`: prompts prontos para colar no Claude Code, separados por fase.
- `checklist-acoes-externas-publicacao-2026-05-05.md`: checklist de acoes que dependem de GitHub/PyPI/UI e nao sao resolvidas apenas por commit.
- `../docs/publication-readiness.md`: gate oficial de aceite para tornar o repositorio publico em 2026-06-05.

## Arquivos ja existentes

- `plano-acao-maturidade-higiene-codex-gpt-5-2026-05-05.md`
- `prompt-cursor-maturidade-higiene-codex-gpt-5-2026-05-05.md`

Esses arquivos foram preservados. A validacao cruzada desta rodada deve ser
usada como camada mais recente de decisao, porque ela revalidou o estado remoto,
o estado local e as divergencias entre relatorios.

## Decisao atual

Status: `NO-GO` para publicacao publica imediata.

Motivo: o core local esta funcional, mas o repo nao esta release-clean: ha
worktree sujo, versao/tag/release desalinhadas, repo privado, PyPI inexistente,
Actions sem runs confirmados, branch protection ausente, code/secret scanning
desabilitados, PRs Dependabot abertos e metadados/links antigos.
