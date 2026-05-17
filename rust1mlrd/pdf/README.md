# Umbrella Protocol whitepaper — PDF build

This directory contains the public whitepaper of Umbrella Protocol in two
languages, written in **Typst** (a modern typesetting engine — single
binary, no LaTeX dependency, prettier defaults).

## Files

| File                          | Purpose                                                           |
|-------------------------------|-------------------------------------------------------------------|
| `styles.typ`                  | Shared styles, color palette, page setup, diagrams, callouts      |
| `umbrella-whitepaper-ru.typ`  | Russian source — plain language with bracketed term explanations  |
| `umbrella-whitepaper-en.typ`  | English source — full parallel translation                        |
| `build.sh`                    | Build script — installs typst if missing, compiles both PDFs      |
| `README.md`                   | This file                                                         |
| `out/`                        | Output directory (created by build) — final PDFs land here        |

## Build

```bash
./build.sh           # build both PDFs (Russian + English)
./build.sh ru        # only the Russian version
./build.sh en        # only the English version
./build.sh --watch   # auto-rebuild on file change (both)
```

The script:

1. Checks whether `typst` is installed.
2. If it is not, on macOS attempts `brew install typst`. On Linux/other
   prints manual installation instructions.
3. Compiles each `.typ` source to a PDF under `out/`.

## Install typst manually

If `build.sh` cannot install typst automatically:

- **macOS (Homebrew)**: `brew install typst`
- **macOS (manual)**: download from
  <https://github.com/typst/typst/releases>, drop the `typst` binary
  into `/usr/local/bin` or `~/.local/bin`.
- **Linux**: `cargo install --git https://github.com/typst/typst --locked typst-cli`
  or take a release binary.
- **Windows**: download a release binary, put it on `PATH`.

After install, verify with:

```bash
typst --version
# expected: typst 0.12.x (or newer)
```

## Output

Both PDFs are designed for A4 paper, with:

- A full-bleed colored cover.
- Auto-generated table of contents.
- Section-aware headers/footers (skipped on the cover).
- Color-coded comparison tables (green = good, red = absent, yellow =
  partial, gray = neutral).
- Inline diagrams of the three-key architecture, the 5-server
  distributed identity, the hybrid PQ flow, and the PIN unlock flow.

Each version is approximately 30-40 pages.

## Editing notes

The styles file (`styles.typ`) exposes:

- `setup-doc(title, author, lang, body)` — call once via `#show: doc => setup-doc(...)`
  at the top of every whitepaper file.
- `umbrella-cover(...)` — renders the cover page.
- `good/bad/warn/neutral/info/head-cell` — colored table cells.
- `callout(title, color, body)` — boxed paragraph with a colored side rule.
- `attack-box(num, title, body)` — used in the attack-scenarios chapter.
- `three-layer-keys-diagram`, `five-servers-diagram`, `hybrid-pq-diagram`,
  `unlock-flow-diagram` — pure-Typst block diagrams (no external graphics
  library needed).

To change colors globally, edit the `umbrella-primary` / `umbrella-secondary`
/ `umbrella-accent` palette at the top of `styles.typ`.

## Compatibility

- The font stacks are `New Computer Modern, Times New Roman, Libertinus
  Serif` for body text and `DejaVu Sans Mono, Menlo` for code. All of
  these ship with Typst by default (no system install required).
- Diagrams are built from native Typst boxes/grids; the `cetz` package
  is *not* required.
- Both files compile under Typst >= 0.12.

## Reproducibility

For deterministic builds (same input → byte-identical PDF), pin the
typst version. On 2026-05-17 we built with typst 0.13 (latest stable).
