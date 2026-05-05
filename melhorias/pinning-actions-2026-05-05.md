# Inventario de pinning de GitHub Actions

Data: 2026-05-05
Origem: Tarefa 6 do prompt
`melhorias/prompt-cursor-maturidade-higiene-codex-gpt-5-2026-05-05.md`
e P2-01 do plano
`melhorias/plano-acao-maturidade-higiene-codex-gpt-5-2026-05-05.md`.

Comando usado:

```powershell
Select-String -Path .\.github\workflows\*.yml -Pattern '^\s*uses:\s*'
```

ou equivalente via Grep.

## Resumo executivo

A maioria das `uses:` esta pinada por SHA com comentario de versao.
Permanecem **8 referencias por tag**, das quais 2 sao excecoes
estruturais (reusable workflow / publisher oficial) e 6 sao
candidatas a conversao em uma rodada separada de hardening
sincronizada com a primeira release publica real. Nao foi feita
conversao em massa nesta rodada porque todas as 6 candidatas tocam
o caminho de release/Pages que ainda nao foi exercitado de ponta
a ponta.

## Inventario completo de `uses:`

### SHA-pinned com comentario de versao (preferido)

| Action | Pin |
|---|---|
| `actions/checkout` | `de0fac2e4500dabe0009e67214ff5f5447ce83dd # v6` (alguns lugares com `# v6.0.2`) |
| `actions/setup-python` | `a309ff8b426b58ec0e2a45f0f869d46889d02405 # v6` (alguns com `# v6.2.0`) |
| `actions/setup-node` | `48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e # v6` |
| `actions/upload-artifact` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1` |
| `actions/stale` | `28ca1036281a5e5922ead5184a1bbf96e5fc984e # v9.0.0` |
| `actions/dependency-review-action` | `2031cfc080254a8a887f58cffee85186f0e49e48 # v4` |
| `aquasecurity/trivy-action` | `ed142fd0673e97e23eac54620cfb913e5ce36c25 # 0.36.0` |
| `step-security/harden-runner` | `8d3c67de8e2fe68ef647c8db1e6a09f647780f40 # v2` |
| `devops-actions/actionlint` | `9fb9c192862f19e684586ca84b500461bcd8a541 # pinned` |
| `anchore/sbom-action/download-syft` | `e11c554f704a0b820cbf8c51673f6945e0731532 # v0.20.0` |
| `docker/build-push-action` | `4f58ea79222b3b9dc2c8bbdd6debcef730109a75 # v6.9.0` |
| `docker/login-action` | `9780b0c442fbb1117ed29e0efdff1e18412f7567 # v3.3.0` |
| `docker/metadata-action` | `906ecf0fc0a80f9110f79d9e6c04b1080f4a2621 # v5.6.1` |
| `docker/setup-buildx-action` | `c47758b77c9736f4b2ef4073d4d51994fabfe349 # v3.7.1` |
| `docker/setup-qemu-action` | `49b3bc8e6bdd4a60e6116a5414239cba5943d3cf # v3.2.0` |
| `github/codeql-action/{analyze,autobuild,init,upload-sarif}` | `ce64ddcb0d8d890d2df4a9d1c04ff297367dea2a # v3` |
| `gitleaks/gitleaks-action` | `ff98106e4c7b2bc287b24eaf42907196329070c7 # v2` |
| `googleapis/release-please-action` | `a02a34c4d625f9be7cb89156071d8567266a2445 # v4.1.3` |
| `micnncim/action-label-syncer` | `3abd5ab72fda571e69fffd97bd4e0033dd5f495c # v1.3.0` |
| `ossf/scorecard-action` | `4eaacf0543bb3f2c246792bd56e8cdeffafb205a # v2.4.3` |

### Tag-pinned, excecao estrutural

| Action | Pin atual | Justificativa |
|---|---|---|
| `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml` | `v2.0.0` | E **reusable workflow**, nao action. A propria documentacao do SLSA generator [exige pin por tag major versao](https://github.com/slsa-framework/slsa-github-generator/blob/main/RELEASE.md) por causa do contrato de OIDC + trusted-builder. Pinar por SHA quebra a verificacao de provenance. |
| `pypa/gh-action-pypi-publish` | `release/v1` | Padrao oficial do PyPA para Trusted Publisher OIDC. O ref `release/v1` e atualizado pela equipe PyPA com correcoes de seguranca dentro da major v1. OpenSSF Scorecard reconhece este pin como aceitavel. Trocar por SHA quebra a continuidade de Trusted Publisher se a maintainer da action mover o ponteiro. |

### Tag-pinned, candidatas a conversao em rodada de hardening

Todas as seis abaixo ainda nao foram exercitadas em release publica
(Pages deploy nunca rodou no ambiente publico, primeiro release nao
existe). Convertelas agora antes da primeira release real adiciona
risco sem ganho. Devem ser convertidas na rodada de hardening
imediatamente apos a primeira release `v1.1.0` ser publicada e
verificada de ponta a ponta.

| Action | Pin atual | Workflow afetado | Acao recomendada |
|---|---|---|---|
| `actions/attest-build-provenance` | `@v1` | `release.yml` | converter para SHA + `# v1.x.y` apos primeira release validar provenance |
| `actions/deploy-pages` | `@v4` | `deploy-github-pages.yml` | converter para SHA + `# v4.x.y` apos primeiro deploy publico |
| `actions/download-artifact` | `@v4` | `release.yml` | converter junto com upload-artifact (que ja esta em v7) na proxima sincronizacao |
| `actions/upload-pages-artifact` | `@v4` | `deploy-github-pages.yml` | converter junto com `deploy-pages` |
| `sigstore/cosign-installer` | `@v3` | `release.yml` | converter para SHA apos primeira execucao do cosign keyless real |
| `softprops/action-gh-release` | `@v2` | `release.yml` | converter para SHA apos primeira GitHub Release ser criada |

## Acoes nesta rodada

- Inventario produzido neste documento.
- `docs/MATURITY_STATUS.md` atualizado:
  linha "Workflows pinned by SHA" virou
  "Workflows pinned (third-party): mostly SHA / target full SHA",
  com pointer para este arquivo via texto da nota.
- `docs/release-readiness.md` ja inclui o item
  "All GitHub workflows use ... SHA-pinned third-party actions
  (or explicit tag pins where SHA is not available)" no bloco de
  Security gates — esse texto continua honesto: as 8 excecoes
  acima sao tag pins **explicitos**, sem ambiguidade.
- `actionlint` continua limpo apos a inspecao manual desta rodada.

## Acoes futuras (rodada de hardening pos-release)

1. Apos a primeira `v1.1.0` publica ser tagueada e validada com
   cosign + SLSA, abrir uma rodada focada em converter as 6
   candidatas (`attest-build-provenance`, `deploy-pages`,
   `download-artifact`, `upload-pages-artifact`, `cosign-installer`,
   `action-gh-release`) por SHA.
2. Manter `slsa-github-generator/.../v2.0.0` e
   `pypa/gh-action-pypi-publish@release/v1` documentados como
   excecao estrutural, **nao** convertidos.
3. Configurar Dependabot para abrir PRs por SHA quando essas 6
   actions tiverem novas versoes (Dependabot ja faz isso por
   default quando o pin atual e SHA).
