# Secure SDLC Evidence Collector - GitPage

Portfolio/GitHub Pages estatica para o **Secure SDLC Evidence Collector**.

Todo o conteudo vive dentro desta pasta (`gitpage/`). Nenhum arquivo fora dela e necessario ou modificado.

## Stack

- HTML semantico + CSS moderno (variaveis para a paleta)
- JavaScript vanilla, modular, sem bundler
- [Three.js 0.158](https://unpkg.com/three) via CDN para a cena 3D do hero
- [GSAP 3.12](https://unpkg.com/gsap) via CDN (ScrollTrigger incluido para futura evolucao)
- Sem backend, sem build obrigatorio, sem dados sensiveis

## Estrutura

```text
gitpage/
  index.html
  README.md
  CURSOR_PROMPT_GITPAGE.md
  assets/
    css/
      styles.css
    js/
      main.js         # reveal, counters, meters, tilt, motion toggle, active nav
      scene.js        # cena 3D do hero (Evidence Core + particulas + streams)
    data/
      evidence-demo.json
```

## Como abrir localmente

Basta abrir `gitpage/index.html` no navegador. A pagina funciona no protocolo `file://` porque todas as dependencias vem por CDN e nao usam `fetch` para arquivos locais.

Se preferir um servidor local:

```bash
# Python 3
cd gitpage
python -m http.server 8080
# depois acesse http://localhost:8080
```

Ou via `npx`:

```bash
npx --yes serve gitpage -l 8080
```

## Como publicar no GitHub Pages

Duas opcoes:

### Opcao A - Pages a partir de `/docs`

1. Copie o conteudo de `gitpage/` para uma pasta `docs/` na raiz do repositorio, ou configure a GitPage a partir desta pasta.
2. No repositorio, va em **Settings -> Pages**, escolha a branch e a pasta `/docs`.

### Opcao B - Branch `gh-pages`

1. Publique o conteudo da pasta `gitpage/` como raiz de uma branch `gh-pages`.
2. No repositorio, va em **Settings -> Pages** e selecione a branch `gh-pages`.

Nenhum build step e necessario - os assets ja sao estaticos.

## Paleta

Definida em variaveis CSS em `assets/css/styles.css`:

- `#0c124c` - fundo principal
- `#d5d8dd` - texto principal
- `#08b98b` - acento positivo
- `#5a6876` - texto secundario
- `#7c8394` - neutros / grid tecnico

## Efeitos 3D/4D implementados

- **Evidence Core** no hero: icosaedro central com wireframe + halo + pulso, cercado por tres aneis orbitais com 11 nodes representando fontes de evidencia.
- **Particle field** com ~240 particulas drifting em uma esfera, com **linhas dinamicas** conectando particulas proximas (lineage visual).
- **Streams de lineage**: 14 "packets" fluindo do core ate os nodes orbitais, reforcando a metafora de raw -> normalized -> assertion ao longo do tempo.
- **Camera parallax** via `pointermove`, com easing.
- **Reveal scroll** por secao (IntersectionObserver).
- **Meters e counters** animados no hero e na secao de scoring.
- **Tilt 3D** em cards de valor.
- **Pipe animado** em SVG na secao de modelo, com packets verdes atravessando Raw -> Normalized -> Assertion.
- **Toggle de motion** no nav, alem de respeito automatico a `prefers-reduced-motion`.
- **Pausa** da cena quando a aba esta inativa (via `visibilitychange`).
- **Fallback**: se WebGL nao estiver disponivel, o canvas do hero e ocultado e o restante da pagina continua funcional.

## Acessibilidade e UX

- Navegacao com `aria-current` por secao visivel.
- Skip-link para pular direto ao conteudo.
- Foco visivel em todos os controles.
- Contraste elevado para texto sobre o fundo `#0c124c`.
- Sem overflow horizontal em mobile (testado em viewports de 320px+).
- Nenhum texto sobreposto ao canvas: o hero usa `z-index: -1` no palco 3D e o conteudo e desenhado acima.

## Postura editorial

A pagina **nunca** afirma que o produto garante release segura ou entrega compliance automatico. O discurso consistente e:

- quais praticas minimas foram comprovadas
- quais controles possuem evidencias suficientes
- quais controles estao parcialmente atendidos
- quais evidencias estao faltando
- quais excecoes foram aprovadas
- qual nivel de confianca existe sobre a avaliacao

## Dados demo

`assets/data/evidence-demo.json` contem um bundle de exemplo aderente ao modelo descrito em `Ideia do projeto.md`. Ele nao e carregado via `fetch` para manter a pagina 100% funcional em `file://`; serve como referencia editorial e ponto de expansao futura.

## Limitacoes conhecidas / proximos passos

- O bundle demo nao e renderizado dinamicamente (evita `fetch` em `file://`). Se a pagina for servida via HTTP, e trivial adicionar um `fetch` para renderizar evidencias reais.
- GSAP esta carregado mas so uma fracao dos efeitos avancados (scroll-timelines cinematicas) foi ativada. A base esta pronta para expandir.
- Nao ha build step. Se desejar minificacao, qualquer minifier estatico resolve sem quebrar referencias.
