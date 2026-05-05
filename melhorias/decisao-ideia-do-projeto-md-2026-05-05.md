# Decisao - manter `Ideia do projeto.md` (Opcao A)

Data: 2026-05-05
Origem: Tarefa 4 do prompt
`melhorias/prompt-cursor-maturidade-higiene-codex-gpt-5-2026-05-05.md`
("Migrar ou manter `Ideia do projeto.md` com decisao explicita") e
P1-02 do plano
`melhorias/plano-acao-maturidade-higiene-codex-gpt-5-2026-05-05.md`.

## Decisao

**Opcao A — manter** o arquivo `Ideia do projeto.md` na raiz do
repositorio, sem migracao e sem regeneracao do bundle dogfood.

## Estado real de referencias verificado nesta rodada

```bash
grep -RIn "Ideia do projeto" .
```

Referencias ativas (4):

| Local | Tipo de referencia |
|---|---|
| `.dockerignore:24` | exclusao do build context Docker. Nao quebra com a permanencia do arquivo. |
| `gitpage/README.md:112` | nota editorial: "bundle de exemplo aderente ao modelo descrito em `Ideia do projeto.md`". E uma referencia narrativa, nao um link consumido por codigo. |
| `examples/self_release/attestations/threat_model.yaml:14` | atestacao com `link: "Ideia do projeto.md"` apontando para o threat model historico. |
| `examples/self_release/output/bundle.json:660` | bundle dogfood versionado contem o mesmo `"link": "Ideia do projeto.md"` derivado da atestacao acima. Esse bundle e a self-evidencia que o projeto entrega, regenerada por `deploy-github-pages.yml` e `release.yml`. |

Referencias historicas (em `melhorias/`, imutaveis):

- `plano-acao-maturidade-higiene-codex-gpt-5-2026-05-05.md` cita o
  arquivo como evidencia historica. Nao precisa ser migrado.
- `prompt-cursor-maturidade-higiene-codex-gpt-5-2026-05-05.md`
  atribui a esta rodada justamente a tarefa de decidir.

## Justificativa

1. **O arquivo e fonte da visao do produto.** Diferente de
   `Plano de acao e execucao - Claude.md` (que era um plano de
   execucao mantido como rascunho de trabalho e foi removido em
   `release(1.1.0)` — commit `17dede2`), `Ideia do projeto.md` e a
   declaracao do produto: visao, personas, modelo de evidencia,
   value proposition. Equivale ao "produto pensado em portugues"
   antes da localizacao para README/docs em ingles.
2. **Bundle dogfood versionado depende dele.**
   `examples/self_release/output/bundle.json` contem hash + link
   apontando para esse arquivo como evidencia de threat model. Migrar
   exigiria:
   - reescrever `examples/self_release/attestations/threat_model.yaml`
     para outro alvo (`THREAT_MODEL.md` ou um doc oficial em `docs/`);
   - regenerar `bundle.json`, `report.md`, `summary.html`;
   - atualizar `gitpage/README.md`;
   - revalidar determinismo via `compare`.
   Isso nao e um migrate cosmetico — e uma rodada inteira de
   regeneracao com diff grande e teste extenso. O ganho e zero
   enquanto o arquivo continua valido como referencia.
3. **`THREAT_MODEL.md` ja existe** na raiz com STRIDE por componente
   e cobertura tecnica; ele complementa, nao substitui,
   `Ideia do projeto.md`. O primeiro responde "quais ameacas
   tecnicas o tooling enfrenta"; o segundo responde "qual e o produto
   que estamos construindo e por que".
4. **A regra de manter o arquivo ja foi tomada na rodada anterior**
   pelo `plano-acao-maturidade-higiene-codex-gpt-5-2026-05-05.md`
   secao 5.2 ("Arquivos mantidos de forma intencional"). Esta rodada
   confirma a mesma decisao com a mesma justificativa, sem novidade.

## Acoes nesta rodada

Nenhuma alteracao no arquivo, no bundle dogfood ou nas atestacoes.
Apenas o registro desta decisao.

## Acoes futuras (nao agora)

Migrar so faz sentido se uma das tres condicoes ocorrer:

- O conteudo do produto for re-escrito em ingles oficial dentro de
  `docs/` e a `Ideia do projeto.md` virar redundante.
- A self-release dogfood for redesenhada (novo bundle base, nova
  evidencia de threat model) por outro motivo, abrindo a janela
  natural para reapontar `link:`.
- Uma decisao editorial passar a tratar `Ideia do projeto.md` como
  conteudo legado de portfolio (em vez de fonte do produto).

Em qualquer um desses cenarios, a migracao deve seguir P1-02 do
plano: atualizar `threat_model.yaml`, regenerar
`examples/self_release/output/bundle.json`, `report.md` e
`summary.html`, atualizar `gitpage/README.md`, e validar via
`compare` que somente os campos volateis documentados mudaram.
