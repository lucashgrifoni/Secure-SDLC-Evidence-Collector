# Inventario de pinning de GitHub Actions

Data: 2026-05-05
Origem: Tarefa 6 do prompt
`docs/program/_archive/2026-05-05/prompt-cursor.md`
e P2-01 do plano
`docs/program/_archive/2026-05-05/plan-maturity-hygiene.md`.

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

### Tag-pinned convertidas para SHA na rodada de 2026-05-05 (atualizacao)

As seis candidatas inicialmente listadas para "rodada de hardening
pos-release" foram convertidas para SHA + comentario de versao na
mesma sessao do dia 2026-05-05, depois que o usuario pediu para
executar todos os pontos de melhoria que dependem apenas de codigo.
A conversao foi mecanica e validada com `actionlint` clean. SHAs
obtidos via `gh api repos/<owner>/<repo>/commits/<tag>` e a versao
exata identificada via `gh api repos/<owner>/<repo>/tags?per_page=100`
filtrando pelo SHA. Atualizacao de log:

| Action | Pin novo | Workflow afetado | Status |
|---|---|---|---|
| `actions/attest-build-provenance` | `@ef244123eb79f2f7a7e75d99086184180e6d0018 # v1.4.4` | `publish-pypi.yml` | convertido |
| `actions/deploy-pages` | `@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e # v4.0.5` | `deploy-github-pages.yml` | convertido |
| `actions/download-artifact` | `@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0` | `publish-pypi.yml` (3 ocorrencias) | convertido |
| `actions/upload-pages-artifact` | `@7b1f4a764d45c48632c6b24a0339c27f5614fb0b # v4.0.0` | `deploy-github-pages.yml` | convertido |
| `sigstore/cosign-installer` | `@398d4b0eeef1380460a10c8013a76f728fb906ac # v3.9.1` | `publish-pypi.yml` (2 ocorrencias) | convertido |
| `softprops/action-gh-release` | `@3bb12739c298aeb8a4eeaf626c5b8d85266b0e65 # v2.6.2` | `publish-pypi.yml` | convertido |

Observacao: o pin `# v1.4.4` em `attest-build-provenance` mantem a
**major v1**, deliberadamente nao seguindo a Dependabot PR #13 que
propoe `v4`. A v4 trocou a base de Node 20 para Node 24 e tem
breaking changes no contrato de attestation; deve ser avaliada na
proxima rodada de hardening. Mesmo motivo para `cosign-installer`
(v3 -> v4 muda mecanismo de instalacao) e `action-gh-release` (v2 ->
v3 muda contrato de release notes). As tres permanecem em **majors
estaveis** com SHA fixo. Quando Dependabot recriar PRs de major
bump, eles sobem como decisao explicita acompanhada de release
notes validadas.

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
