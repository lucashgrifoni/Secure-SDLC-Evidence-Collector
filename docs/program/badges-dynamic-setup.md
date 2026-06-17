# Runbook: badges dinamicas de Tests e Coverage (entrega E2)

Data: 2026-06-16
Origem: preparacao da entrega E2 (badges dinamicas reais de Tests e
Coverage). Este documento e um runbook operacional. Ele NAO cria
workflows nem edita o README; descreve apenas o setup manual que
depende do owner para destravar a entrega quando houver janela.

## Contexto

Badges dinamicas de Tests/Coverage sao geradas gravando um pequeno JSON
(`{ "schemaVersion": 1, "label": ..., "message": ..., "color": ... }`)
em um gist publico a cada run de CI, normalmente com
`Schneegans/dynamic-badges-action`. O `shields.io` le esse JSON pelo
endpoint dinamico e renderiza a badge. O passo bloqueante e gerar um
token com permissao de escrita em gist e cadastra-lo como secret; sem
ele o workflow de badges nao consegue atualizar o gist.

A ordem importa: o gist e o token (Passos 1 a 3) sao pre-requisitos do
workflow de badges, que sera criado em PR separada (fora do escopo
deste runbook).

## Pre-requisitos

- Conta GitHub do owner do repositorio
  `lucashgrifoni/Secure-SDLC-Evidence-Collector`.
- Acesso de **admin** ao repositorio (necessario para cadastrar
  secrets em Settings > Secrets and variables > Actions).
- Os passos abaixo usam apenas a UI web do GitHub. Nenhum comando
  precisa rodar localmente.

## Passo 1 - Criar o gist publico

1. Acessar https://gist.github.com enquanto logado como o owner.
2. No campo de descricao, usar algo como
   `Secure SDLC Evidence Collector - dynamic badges`.
3. No primeiro arquivo:
   - Nome: `secure-sdlc-evidence-collector-tests.json`
   - Conteudo: `{}` (placeholder; o workflow de CI sobrescreve depois).
4. Clicar em "Add file" e criar o segundo arquivo no mesmo gist:
   - Nome: `secure-sdlc-evidence-collector-coverage.json`
   - Conteudo: `{}`
5. Garantir que a visibilidade esta como **"Create public gist"**
   (botao verde no canto inferior). O endpoint do shields.io so le
   gists publicos.
6. Apos criar, anotar o **gist ID**: e a parte final da URL
   `https://gist.github.com/<usuario>/<gist_id>`. Esse `<gist_id>`
   sera usado no Passo 3 e no Passo 5.

Observacao: os dois arquivos podem viver no mesmo gist; o
`dynamic-badges-action` referencia cada arquivo pelo nome, entao um
unico `GIST_ID` cobre Tests e Coverage.

## Passo 2 - Gerar o token com escopo de gist

O token precisa de permissao de **escrita em gist** e de nada mais. Ha
dois caminhos na UI atual do GitHub; o caminho classico e o mais
simples e e o documentado pela propria action.

### Opcao A (recomendada) - Personal access token (classic)

1. GitHub > Settings > Developer settings > Personal access tokens >
   **Tokens (classic)**.
2. "Generate new token" > "Generate new token (classic)".
3. Nota/descricao: `dynamic-badges - evidence-collector`.
4. Expiracao: recomendado **90 dias a 1 ano** (renovacao manual; ver
   Passo 4 sobre validacao apos renovar).
5. Selecionar **somente** o escopo `gist`. Nenhum escopo `repo`,
   `workflow` ou outro deve ser marcado.
6. "Generate token" e copiar o valor. O token so e exibido **uma
   vez**; se perder, gerar outro.

### Opcao B - Fine-grained personal access token

Tokens fine-grained tratam gist como permissao de **conta**, nao de
repositorio:

1. GitHub > Settings > Developer settings > Personal access tokens >
   **Fine-grained tokens** > "Generate new token".
2. Em "Account permissions", localizar **"Gists"** e definir como
   **"Read and write"**.
3. Nao e necessario conceder nenhuma "Repository permission" para a
   escrita no gist.
4. Definir expiracao e gerar; copiar o valor uma unica vez.

Se a permissao "Gists" nao aparecer na conta usada, usar a Opcao A.

## Passo 3 - Cadastrar os secrets do repositorio

1. No repositorio: Settings > Secrets and variables > Actions > aba
   "Secrets" > "New repository secret".
2. Criar o secret do token:
   - Name: `GIST_TOKEN`
   - Secret: valor copiado no Passo 2.
3. "New repository secret" novamente para o ID do gist:
   - Name: `GIST_ID`
   - Secret: `<gist_id>` anotado no Passo 1.

Nunca commitar o token nem o ID em arquivo versionado; ambos vivem
apenas como secrets de Actions.

## Passo 4 - Verificar

1. Disparar o workflow de badges (a ser criado em PR separada, fora do
   escopo deste runbook) - por push no branch alvo ou via
   "Run workflow" se ele expuser `workflow_dispatch`.
2. Abrir o gist do Passo 1 e confirmar que
   `secure-sdlc-evidence-collector-tests.json` e
   `secure-sdlc-evidence-collector-coverage.json` deixaram de ser `{}`
   e passaram a conter os campos `schemaVersion`, `label`, `message` e
   `color`.
3. Se o workflow falhar com erro de permissao (HTTP 401/403) ao gravar
   o gist, revisar o escopo do token (Passo 2) e o valor do secret
   `GIST_TOKEN` (Passo 3). Apos renovar um token expirado, repetir
   este passo para confirmar a escrita.

## Passo 5 - Substituir as badges no README (iteracao futura)

Quando os JSONs do gist estiverem populados, uma iteracao futura
trocara/expandira o bloco de badges do `README.md`. As badges
dinamicas usam o endpoint do shields.io apontando para o gist:

```
https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/<usuario>/<gist_id>/raw/secure-sdlc-evidence-collector-tests.json
https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/<usuario>/<gist_id>/raw/secure-sdlc-evidence-collector-coverage.json
```

Alvos no README atual (linhas do bloco de badges no topo):

- a badge estatica `python-3.12 | 3.13` e
- a badge `openssf best practices - registration pending`

sao candidatas a serem acompanhadas pelas novas badges dinamicas de
Tests e Coverage, mantendo compatibilidade com as badges ja existentes
(CI, Security CI, PyPI, License, Cosign). A decisao final de layout e
de qual badge manter fica para a PR que fizer a troca.

## Nao-objetivos deste runbook

- Nao cria nem edita workflows de CI/CD (incluindo o workflow de
  badges em si).
- Nao edita o `README.md`.
- Nao inclui tokens, IDs reais, URLs com token, nem qualquer segredo.
- A execucao destes passos depende do owner gerar o `GIST_TOKEN`;
  ate la a entrega E2 permanece bloqueada por design.
