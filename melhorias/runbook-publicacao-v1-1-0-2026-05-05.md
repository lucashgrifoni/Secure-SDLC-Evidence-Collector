# Runbook - Publicacao v1.1.0

Data: 2026-05-05
Para: Lucas (owner do repo)
Pre-requisito: tudo neste runbook depende de UI externa (GitHub.com /
PyPI.org) e nao pode ser executado pelo Claude. O codigo e a
documentacao ja estao prontos em `main` ate o commit que acompanha
este arquivo.

A ordem importa: cada passo destrava o seguinte.

---

## Passo 1 - Tornar o repositorio publico

Por que primeiro: liberar a publicacao tambem desbloqueia
**imediatamente** 9 falhas vermelhas do Security CI/CD que hoje sao
limitacao de visibilidade (CodeQL/Trivy/Semgrep upload-sarif,
Dependency Review, Scorecard). Documentado em
`melhorias/analise-falhas-security-ci-2026-05-05.md`.

Acao na UI: <https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/settings>
> Danger Zone > Change visibility > Make public.

Verificacao por CLI apos o passo:

```powershell
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector --jq '.visibility'
# esperado: "public"

gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector --jq '.license.spdx_id'
# esperado: "Apache-2.0" (passa a ser detectado a partir do LICENSE
# canonico que ja esta no repo)
```

## Passo 2 - Habilitar branch protection em `main`

Acao na UI: Settings > Branches > Add branch protection rule.
- Branch name pattern: `main`
- Require a pull request before merging: **on**
- Require status checks to pass: **on**, e adicionar:
  - `Lint, type-check, and test (py3.12)`
  - `Lint, type-check, and test (py3.13)`
  - `Build package artifacts`
  - `Produce sample evidence bundle`
  - `Produce sample evidence bundle (windows)`
  - `Cross-OS determinism gate`
  - `SAST - CodeQL (python)` (depois que o repo for publico e o run
    rodar uma vez)
- Do not allow bypassing the above settings: **on** (incluindo admins)
- Restrict who can push to matching branches: opcional

Verificacao:

```powershell
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/branches/main/protection --jq '.required_status_checks.contexts'
# nao deve retornar 404, deve listar os contextos configurados
```

## Passo 3 - Habilitar Discussions, code scanning e secret scanning

Acao na UI:
- Settings > General > Features > Discussions: **on**
- Settings > Code security > Code scanning: **Setup > Default**
  (deve detectar o `codeql.yml` ja existente e linkar)
- Settings > Code security > Secret scanning: **Enable**

Verificacao:

```powershell
gh repo view lucashgrifoni/Secure-SDLC-Evidence-Collector --json hasDiscussionsEnabled
# {"hasDiscussionsEnabled":true}
```

## Passo 4 - Criar projeto no PyPI e configurar Trusted Publisher

Acao 4.1 (PyPI UI): <https://pypi.org/manage/account/publishing/>
> Add a new pending publisher
- PyPI Project Name: `secure-sdlc-evidence-collector`
- Owner: `lucashgrifoni`
- Repository name: `Secure-SDLC-Evidence-Collector`
- Workflow name: `release.yml`
- Environment name: `pypi`

Apos o primeiro upload bem sucedido, o "pending publisher" vira
"trusted publisher" automaticamente.

Acao 4.2 (GitHub UI): Settings > Environments > New environment >
nome `pypi`. Nao precisa adicionar secrets - o OIDC do Trusted
Publisher e o que autentica o publish.

Verificacao:

```powershell
gh api repos/lucashgrifoni/Secure-SDLC-Evidence-Collector/environments/pypi --jq '.name'
# "pypi"

# (Apos o primeiro publish, este endpoint passa a responder)
curl -s https://pypi.org/pypi/secure-sdlc-evidence-collector/json | python -c "import sys,json; print(json.load(sys.stdin)['info']['version'])"
```

## Passo 5 - (Opcional) `SNYK_TOKEN`

Se quiser manter os jobs Snyk em `security-ci-cd.yml`:
- Settings > Secrets and variables > Actions > New repository secret
- Name: `SNYK_TOKEN`
- Value: token de snyk.io > Account Settings > General > Auth Token

Caso contrario: editar `security-ci-cd.yml` para remover os 2 jobs
Snyk antes do tag - eles vao continuar vermelhos sem o token.

## Passo 6 - Tag v1.1.0

So execute apos os passos 1 a 4. Duas opcoes:

### Opcao A - mergear o release-please PR

Se ja existir um PR aberto chamado `chore(release): release X.Y.Z`
gerado pelo workflow `release-please.yml`, mergeie. O proprio
workflow cria o tag e dispara `release.yml`.

```powershell
gh pr list --search "release-please" --state open
gh pr merge <numero> --squash
```

### Opcao B - tag manual

```powershell
git -c user.email="120392060+lucashgrifoni@users.noreply.github.com" tag -a v1.1.0 -m "release v1.1.0" -s
git push origin v1.1.0
```

Em ambos os casos, acompanhar o run do `release.yml`:

```powershell
gh run watch
```

Ate todos os jobs verdes:
- `quality`
- `build`
- `provenance` (SLSA L3)
- `release-bundle`
- `sign-and-publish` (cosign keyless + GitHub Release)
- `publish-pypi` (PyPI upload via OIDC)
- `publish-container` (GHCR multi-arch)

## Passo 7 - Verificacao pos-release

Os comandos abaixo so funcionam **depois** que `release.yml` terminar
sem erro. Eles estao em
`scripts/verify-release.sh` para reproducao automatica.

```powershell
# 1) Wheel + sdist em PyPI
python -m pip install --quiet "secure-sdlc-evidence-collector==1.1.0"
python -m evidence_collector.cli.main --version
# esperado: 1.1.0

# 2) cosign verify-blob na wheel
$tag = "v1.1.0"
$base = "https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector/releases/download/$tag"
Invoke-WebRequest "$base/secure_sdlc_evidence_collector-1.1.0-py3-none-any.whl" -OutFile w.whl
Invoke-WebRequest "$base/secure_sdlc_evidence_collector-1.1.0-py3-none-any.whl.sig" -OutFile w.sig
Invoke-WebRequest "$base/secure_sdlc_evidence_collector-1.1.0-py3-none-any.whl.pem" -OutFile w.pem
cosign verify-blob `
  --certificate w.pem `
  --signature w.sig `
  --certificate-identity-regexp "https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector" `
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" `
  w.whl

# 3) SLSA verifier na wheel
slsa-verifier verify-artifact w.whl `
  --provenance-path provenance.intoto.jsonl `
  --source-uri github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector `
  --source-tag $tag

# 4) cosign verify na imagem GHCR
cosign verify ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:$tag `
  --certificate-identity-regexp "https://github.com/lucashgrifoni/Secure-SDLC-Evidence-Collector" `
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

cosign download attestation ghcr.io/lucashgrifoni/secure-sdlc-evidence-collector:$tag
```

## Passo 8 - Atualizar docs com evidencia verificada

Apos Passo 7 retornar verde:

- Marcar em `docs/MATURITY_STATUS.md` os itens externos da rodada de
  2026-05-05 como `done` (data efetiva).
- Atualizar `docs/release-readiness.md` "Last local validation pass"
  para citar o tag publicado e os hashes/saidas dos comandos do
  Passo 7.
- Acrescentar uma nova entrada em `docs/traceability.md` "Refresh
  notes" com:
  - "Cosign verify-blob: PASS (cert identity + Rekor entry url)"
  - "SLSA verifier: PASS (source-uri + source-tag)"
  - "GHCR verify: PASS"
  - "PyPI fresh-venv install: PASS"
- Mover `Roadmap status` em `docs/MATURITY_STATUS.md` de `GO WITH
  CAVEATS` para `GO`.

## Rollback

- Se algum job de `release.yml` falhar antes do publish, ele nao
  publica nada - basta corrigir e re-executar via
  `gh workflow run release.yml -f tag=v1.1.0`.
- Se a Github Release for criada parcial (assets faltando), apague-a
  via UI ou `gh release delete v1.1.0 --yes` e re-execute.
- **Nao mover tag publica.** Se um asset ja foi consumido (downloaded
  por terceiro), preferir `v1.1.1` em vez de mover `v1.1.0`.

## Resumo do criterio "GO"

A primeira release publica esta `GO` quando:

- [ ] repo `public`
- [ ] branch protection ativa em `main`
- [ ] Discussions / code scanning / secret scanning habilitados
- [ ] PyPI project + Trusted Publisher + ambiente `pypi` configurados
- [ ] tag `v1.1.0` empurrada e `release.yml` verde end-to-end
- [ ] todos os comandos do Passo 7 retornam verde
- [ ] `docs/` atualizado com evidencia verificada
