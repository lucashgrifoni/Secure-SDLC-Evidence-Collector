# Secure SDLC Evidence Collector - GitPage

Static portfolio / GitHub Pages site for the **Secure SDLC Evidence Collector**.

All content lives inside this folder (`gitpage/`). The Pages workflow (`.github/workflows/deploy-github-pages.yml`) publishes it at the site root and rewrites its CLI facts at build time (see below).

## Stack

- Semantic HTML + modern CSS (CSS variables for the palette)
- Vanilla, modular JavaScript with no bundler
- [Three.js 0.158](https://unpkg.com/three) via CDN for the hero's 3D scene, pinned with a Subresource Integrity hash (`integrity="sha384-..."`, `crossorigin="anonymous"`)
- No backend, no sensitive data; the only build step is the facts injection described below

## Structure

```text
gitpage/
  index.html
  README.md
  assets/
    css/
      styles.css
    js/
      main.js         # reveal, counters, meters, tilt, motion toggle, active nav, small-screen menu
      scene.js        # hero 3D scene (Evidence Core + particles + streams)
  tools/
    page_facts.py     # injects and checks the CLI facts at Pages build time (not published)
```

To change the Three.js version, update the URL and recompute the hash, for example:

```bash
curl -sL https://unpkg.com/three@0.158.0/build/three.min.js | openssl dgst -sha384 -binary | openssl base64 -A
```

## Local preview

Open `gitpage/index.html` directly in a browser. The page works under the `file://` protocol because every dependency loads via CDN and there are no `fetch` calls for local files. The links to `evidence/` and `docs/` only resolve on the published site, where the workflow generates them.

If you prefer a local server:

```bash
# Python 3
cd gitpage
python -m http.server 8080
# then open http://localhost:8080
```

Or via `npx`:

```bash
npx --yes serve gitpage -l 8080
```

## Publishing on GitHub Pages

The site is published by `.github/workflows/deploy-github-pages.yml` on every push to `main` (Settings -> Pages -> Source: "GitHub Actions"). One deploy holds three surfaces:

- `/` &mdash; this landing page (`index.html` and `assets/`)
- `/evidence/` &mdash; `bundle.json`, `report.md` and `summary.html` that the CLI generates from `examples/sample_release` in the same run
- `/docs/` &mdash; the mkdocs site

### CLI facts

The version badge and footer, the hero numbers, the scoring example (`payments-api 2026.04.10`, the sample release without its rollback plan and artifact signature), the `bundle.json` excerpt and the evidence-type count are elements marked `data-fact="..."` or `data-fact-attrs="..."`. The workflow runs the CLI, then:

```bash
python gitpage/tools/page_facts.py inject --page site/index.html --sample site/evidence/bundle.json \
  --example "$RUNNER_TEMP/example/bundle.json" --schema "$RUNNER_TEMP/schema.json" \
  --version "$(cat "$RUNNER_TEMP/version.txt")"
python gitpage/tools/page_facts.py check ...same arguments...
```

`check` fails the build when a marked fact differs from the CLI output, when a marker is missing, or when the example is no longer `not_ready` (the page text around it assumes that verdict). Pull requests that touch `gitpage/` or the workflow run this build without deploying. The values committed in `index.html` are the CLI output at the time of the last edit, so the `file://` preview stays close to the published page.

## Palette

Defined as CSS variables in `assets/css/styles.css`:

- `#0c124c` &mdash; primary background
- `#d5d8dd` &mdash; primary text
- `#08b98b` &mdash; positive accent
- `#5a6876` &mdash; secondary text
- `#7c8394` &mdash; neutral / technical grid

## 3D / 4D effects implemented

- **Evidence Core** in the hero: central icosahedron with wireframe + halo + pulse, surrounded by three orbital rings holding 11 nodes that represent evidence sources.
- **Particle field** with ~240 particles drifting on a sphere, with **dynamic lines** connecting nearby particles (visual lineage).
- **Lineage streams**: 14 "packets" flowing from the core to the orbital nodes, reinforcing the raw -> normalized -> assertion metaphor over time.
- **Camera parallax** via `pointermove`, with easing.
- **Reveal on scroll** per section (IntersectionObserver).
- **Meters and counters** animated in the hero and in the scoring section.
- **3D tilt** on the value cards.
- **Animated SVG pipe** in the model section, with green packets traversing Raw -> Normalized -> Assertion.
- **Motion toggle** in the nav, plus automatic respect for `prefers-reduced-motion`.
- **Scene pause** when the tab is inactive (via `visibilitychange`).
- **Fallback**: if WebGL is not available, the hero canvas is hidden and the rest of the page keeps working.

## Accessibility and UX

- Navigation with `aria-current` based on the visible section; below 1120px the links move into a native `<details>` menu that works without JavaScript.
- Skip-link to jump directly to the content.
- Visible focus on every control.
- Content is hidden for the scroll reveal, and numbers reset for the count-up, only after JavaScript has run with motion on. Without JavaScript, in print and with reduced motion every section and every final value is visible.
- Print uses a light stylesheet without the 3D stage or the navigation.
- The model diagram switches to a stacked text version below 720px.
- No horizontal overflow on mobile (tested on viewports starting at 320px).
- No text overlapping the canvas: the hero uses `z-index: -1` on the 3D stage and content sits above it.

## Editorial stance

The page **never** claims that the product guarantees a secure release or delivers automatic compliance. The consistent narrative is:

- which minimum practices were proven
- which controls have enough evidence
- which controls are only partially satisfied
- which evidence is missing
- which exceptions were approved
- how confident the evaluation is

## Known limitations / next steps

- The page is dark only; `prefers-color-scheme: light` renders the same dark page.
- If you want minification, any static minifier handles it without breaking references, as long as the `data-fact` markers survive.
