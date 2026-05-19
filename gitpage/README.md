# Secure SDLC Evidence Collector - GitPage

Static portfolio / GitHub Pages site for the **Secure SDLC Evidence Collector**.

All content lives inside this folder (`gitpage/`). No file outside it is required or modified.

## Stack

- Semantic HTML + modern CSS (CSS variables for the palette)
- Vanilla, modular JavaScript with no bundler
- [Three.js 0.158](https://unpkg.com/three) via CDN for the hero's 3D scene
- [GSAP 3.12](https://unpkg.com/gsap) via CDN (ScrollTrigger included for future evolution)
- No backend, no required build step, no sensitive data

## Structure

```text
gitpage/
  index.html
  README.md
  assets/
    css/
      styles.css
    js/
      main.js         # reveal, counters, meters, tilt, motion toggle, active nav
      scene.js        # hero 3D scene (Evidence Core + particles + streams)
    data/
      evidence-demo.json
```

## Local preview

Open `gitpage/index.html` directly in a browser. The page works under the `file://` protocol because every dependency loads via CDN and there are no `fetch` calls for local files.

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

Two options:

### Option A &mdash; Pages from `/docs`

1. Copy the contents of `gitpage/` into a `docs/` folder at the repository root, or configure GitPage from this folder.
2. In the repository, go to **Settings -> Pages**, pick the branch, and select the `/docs` folder.

### Option B &mdash; `gh-pages` branch

1. Publish the contents of `gitpage/` as the root of a `gh-pages` branch.
2. In the repository, go to **Settings -> Pages** and select the `gh-pages` branch.

No build step is needed &mdash; the assets are already static.

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

- Navigation with `aria-current` based on the visible section.
- Skip-link to jump directly to the content.
- Visible focus on every control.
- High contrast for text over the `#0c124c` background.
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

## Demo data

`assets/data/evidence-demo.json` contains a sample bundle that follows the model documented in the project. It is **not** loaded via `fetch` so the page stays 100% functional under `file://`; it serves as editorial reference and future expansion point.

## Known limitations / next steps

- The demo bundle is not rendered dynamically (to avoid `fetch` under `file://`). If the page is served over HTTP it is trivial to add a `fetch` that renders real evidence.
- GSAP is loaded but only a fraction of the advanced effects (cinematic scroll timelines) are wired up. The foundation is ready to expand.
- There is no build step. If you want minification, any static minifier handles it without breaking references.
