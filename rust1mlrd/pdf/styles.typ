// Umbrella Protocol whitepaper — shared styles
// Imported by umbrella-whitepaper-ru.typ and umbrella-whitepaper-en.typ

// ============================================================================
// Color palette
// ============================================================================

#let umbrella-primary   = rgb("#1A3A6C")  // dark navy
#let umbrella-secondary = rgb("#2C5DA0")  // mid blue
#let umbrella-accent    = rgb("#D97706")  // amber (logo-like)
#let umbrella-bg-soft   = rgb("#F4F6FB")  // page tint
#let umbrella-rule      = rgb("#D1D5DB")  // hairline grey
#let umbrella-text-dim  = rgb("#4B5563")  // muted body

#let cell-good     = rgb("#DCFCE7")  // light green
#let cell-good-fg  = rgb("#14532D")
#let cell-bad      = rgb("#FEE2E2")  // light red
#let cell-bad-fg   = rgb("#7F1D1D")
#let cell-warn     = rgb("#FEF3C7")  // light amber
#let cell-warn-fg  = rgb("#78350F")
#let cell-neutral  = rgb("#E5E7EB")  // light grey
#let cell-neutral-fg = rgb("#374151")
#let cell-info     = rgb("#DBEAFE")  // light blue
#let cell-info-fg  = rgb("#1E3A8A")

// ============================================================================
// Page and document setup
// ============================================================================

#let setup-doc(title: "Umbrella Protocol Whitepaper", author: "Umbrella Protocol Team", lang: "en", body) = {
  set document(title: title, author: author)
  set page(
    paper: "a4",
    margin: (top: 2.4cm, bottom: 2.2cm, left: 2.2cm, right: 2.2cm),
    numbering: "1 / 1",
    number-align: center,
    header: context {
      let cur = counter(page).get().first()
      if cur > 1 {
        set text(size: 8.5pt, fill: umbrella-text-dim)
        grid(
          columns: (1fr, auto),
          align: (left, right),
          [Umbrella Protocol — #title],
          [v1.1.0 \u{2022} 2026-05-17],
        )
        v(-0.4em)
        line(length: 100%, stroke: 0.4pt + umbrella-rule)
      }
    },
  )
  set text(font: ("New Computer Modern", "Times New Roman", "Libertinus Serif"), size: 10.5pt, lang: lang)
  set par(justify: true, leading: 0.62em, first-line-indent: 0pt)
  set heading(numbering: "1.1")
  show heading.where(level: 1): it => {
    pagebreak(weak: true)
    block(below: 1.2em, above: 0em)[
      #set text(size: 22pt, weight: "bold", fill: umbrella-primary)
      #counter(heading).display() #h(0.6em) #it.body
    ]
    line(length: 100%, stroke: 0.6pt + umbrella-primary)
    v(0.6em)
  }
  show heading.where(level: 2): it => block(above: 1.4em, below: 0.6em)[
    #set text(size: 14pt, weight: "bold", fill: umbrella-secondary)
    #counter(heading).display() #h(0.4em) #it.body
  ]
  show heading.where(level: 3): it => block(above: 1.0em, below: 0.4em)[
    #set text(size: 11.5pt, weight: "bold", fill: umbrella-primary)
    #it.body
  ]
  show link: it => text(fill: umbrella-secondary, it)
  show raw.where(block: true): it => block(
    fill: umbrella-bg-soft,
    inset: (x: 10pt, y: 8pt),
    radius: 3pt,
    width: 100%,
    stroke: 0.4pt + umbrella-rule,
    text(font: ("DejaVu Sans Mono", "Menlo"), size: 8.8pt, it),
  )
  show raw.where(block: false): it => box(
    fill: umbrella-bg-soft,
    inset: (x: 3pt, y: 1pt),
    radius: 2pt,
    text(font: ("DejaVu Sans Mono", "Menlo"), size: 9pt, it),
  )
  body
}

// ============================================================================
// Cover page
// ============================================================================

#let umbrella-cover(title: "", subtitle: "", tagline: "", version: "1.1.0", date: "2026-05-17", authors: "") = {
  set page(margin: (top: 0cm, bottom: 0cm, left: 0cm, right: 0cm), numbering: none, header: none)
  block(
    fill: umbrella-primary,
    width: 100%,
    height: 100%,
    inset: 0pt,
    {
      set text(fill: white)
      v(3cm)
      // Umbrella logo glyph (ASCII-ish)
      align(center)[
        #box(
          fill: umbrella-accent,
          radius: 999pt,
          width: 3.2cm,
          height: 3.2cm,
          inset: 0pt,
          align(center + horizon)[
            #text(size: 56pt, weight: "bold", fill: white)[U]
          ],
        )
      ]
      v(1.5cm)
      align(center)[
        #text(size: 42pt, weight: "bold")[Umbrella Protocol]
      ]
      v(0.4cm)
      align(center)[
        #text(size: 22pt, fill: rgb("#CBD5E1"))[#title]
      ]
      v(0.6cm)
      align(center)[
        #text(size: 13pt, fill: rgb("#CBD5E1"), style: "italic")[#subtitle]
      ]
      v(2cm)
      align(center)[
        #box(
          stroke: 1pt + rgb("#CBD5E1"),
          inset: (x: 24pt, y: 14pt),
          radius: 4pt,
          text(size: 12pt, fill: white)[#tagline],
        )
      ]
      v(1fr)
      align(center)[
        #text(size: 11pt, fill: rgb("#CBD5E1"))[
          Version #version \u{2022} #date \
          #authors
        ]
      ]
      v(2cm)
    }
  )
}

// ============================================================================
// Verdict cells (for comparison tables)
// ============================================================================

#let good(content) = table.cell(
  fill: cell-good,
  text(fill: cell-good-fg, weight: "semibold", content),
)
#let bad(content) = table.cell(
  fill: cell-bad,
  text(fill: cell-bad-fg, weight: "semibold", content),
)
#let warn(content) = table.cell(
  fill: cell-warn,
  text(fill: cell-warn-fg, weight: "semibold", content),
)
#let neutral(content) = table.cell(
  fill: cell-neutral,
  text(fill: cell-neutral-fg, content),
)
#let info(content) = table.cell(
  fill: cell-info,
  text(fill: cell-info-fg, weight: "semibold", content),
)
#let head-cell(content) = table.cell(
  fill: umbrella-primary,
  text(fill: white, weight: "bold", content),
)

// ============================================================================
// Block helpers
// ============================================================================

#let callout(title: "", color: umbrella-secondary, body) = block(
  fill: color.lighten(85%),
  stroke: (left: 3pt + color),
  inset: (x: 12pt, y: 10pt),
  radius: (right: 3pt),
  width: 100%,
  spacing: 0.8em,
  [
    #if title != "" {
      block(below: 0.4em)[
        #text(weight: "bold", fill: color, title)
      ]
    }
    #body
  ],
)

#let attack-box(num: "", title: "", body) = block(
  stroke: 0.6pt + umbrella-rule,
  inset: (x: 12pt, y: 10pt),
  radius: 3pt,
  width: 100%,
  spacing: 0.9em,
  [
    #grid(
      columns: (auto, 1fr),
      column-gutter: 12pt,
      box(
        fill: umbrella-accent,
        inset: (x: 8pt, y: 4pt),
        radius: 3pt,
        text(fill: white, weight: "bold", size: 10pt, num),
      ),
      text(weight: "bold", fill: umbrella-primary, size: 11pt, title),
    )
    #v(0.5em)
    #body
  ],
)

#let result-row(label, value, color: umbrella-secondary) = {
  grid(
    columns: (auto, 1fr),
    column-gutter: 8pt,
    text(fill: color, weight: "semibold", label + ":"),
    text(fill: umbrella-text-dim, value),
  )
}

#let footnote-term(term, def) = footnote[
  *#term* — #def
]

// ============================================================================
// Diagrams (pure Typst, no cetz)
// ============================================================================

#let three-layer-keys-diagram(labels: (
  identity: "Identity key",
  device: "Device key",
  session: "Session key",
  desc-identity: "Distributed over 5 servers",
  desc-device: "Re-derived from PIN + 3-of-5 shares",
  desc-session: "MLS ratchet, per-message",
)) = block(
  fill: umbrella-bg-soft,
  stroke: 0.6pt + umbrella-rule,
  inset: 14pt,
  radius: 4pt,
  width: 100%,
  spacing: 0.8em,
  {
    set text(size: 9.8pt)
    grid(
      columns: (1fr, 1fr, 1fr),
      column-gutter: 8pt,
      box(
        fill: umbrella-primary,
        inset: 10pt,
        radius: 4pt,
        width: 100%,
        [
          #set text(fill: white)
          #align(center)[
            #text(weight: "bold", size: 11pt, labels.identity)
            #v(0.3em)
            #text(size: 8.4pt, fill: rgb("#CBD5E1"), labels.desc-identity)
          ]
        ],
      ),
      box(
        fill: umbrella-secondary,
        inset: 10pt,
        radius: 4pt,
        width: 100%,
        [
          #set text(fill: white)
          #align(center)[
            #text(weight: "bold", size: 11pt, labels.device)
            #v(0.3em)
            #text(size: 8.4pt, fill: rgb("#DBEAFE"), labels.desc-device)
          ]
        ],
      ),
      box(
        fill: umbrella-accent,
        inset: 10pt,
        radius: 4pt,
        width: 100%,
        [
          #set text(fill: white)
          #align(center)[
            #text(weight: "bold", size: 11pt, labels.session)
            #v(0.3em)
            #text(size: 8.4pt, fill: rgb("#FED7AA"), labels.desc-session)
          ]
        ],
      ),
    )
    v(0.4em)
    align(center)[
      #text(size: 9pt, fill: umbrella-text-dim)[
        Long-lived  →  Per-unlock  →  Per-message
      ]
    ]
  },
)

#let five-servers-diagram(labels: (
  title: "Distributed identity over 5 sealed servers",
  servers: ("DE", "CH", "IS", "NL", "JP"),
  caption: "Threshold 3-of-5 reconstructs device-key; ≤2 compromised → no leak.",
)) = block(
  fill: umbrella-bg-soft,
  stroke: 0.6pt + umbrella-rule,
  inset: 14pt,
  radius: 4pt,
  width: 100%,
  spacing: 0.8em,
  {
    align(center)[
      #text(weight: "bold", fill: umbrella-primary, size: 11pt, labels.title)
    ]
    v(0.5em)
    grid(
      columns: 5,
      column-gutter: 10pt,
      ..labels.servers.map(s => box(
        fill: umbrella-secondary,
        inset: 12pt,
        radius: 50%,
        width: 2cm,
        height: 2cm,
        align(center + horizon)[
          #text(fill: white, weight: "bold", size: 14pt, s)
        ],
      )),
    )
    v(0.4em)
    align(center)[
      #text(size: 9pt, fill: umbrella-text-dim, labels.caption)
    ]
  },
)

#let hybrid-pq-diagram(labels: (
  title: "Hybrid post-quantum encapsulation (X-Wing combiner)",
  classical: "X25519",
  classical-desc: "Classical ECDH",
  pq: "ML-KEM-768",
  pq-desc: "Post-quantum lattice KEM",
  combiner: "HKDF combiner",
  combiner-desc: "Joint shared secret",
  rng: "OsRng + identity witness (hedged seed)",
  caption: "Either half can fail; the survivor protects K.",
)) = block(
  fill: umbrella-bg-soft,
  stroke: 0.6pt + umbrella-rule,
  inset: 14pt,
  radius: 4pt,
  width: 100%,
  spacing: 0.8em,
  {
    align(center)[
      #text(weight: "bold", fill: umbrella-primary, size: 11pt, labels.title)
    ]
    v(0.5em)
    grid(
      columns: (1fr, 1fr),
      column-gutter: 14pt,
      box(
        fill: umbrella-secondary,
        inset: 10pt,
        radius: 4pt,
        width: 100%,
        [
          #set text(fill: white)
          #align(center)[
            #text(weight: "bold", labels.classical)
            #v(0.2em)
            #text(size: 8.4pt, labels.classical-desc)
          ]
        ],
      ),
      box(
        fill: umbrella-accent,
        inset: 10pt,
        radius: 4pt,
        width: 100%,
        [
          #set text(fill: white)
          #align(center)[
            #text(weight: "bold", labels.pq)
            #v(0.2em)
            #text(size: 8.4pt, labels.pq-desc)
          ]
        ],
      ),
    )
    v(0.3em)
    align(center)[
      #text(size: 12pt, fill: umbrella-text-dim, sym.arrow.b.double)
    ]
    v(0.3em)
    box(
      fill: umbrella-primary,
      inset: 10pt,
      radius: 4pt,
      width: 100%,
      [
        #set text(fill: white)
        #align(center)[
          #text(weight: "bold", labels.combiner)
          #v(0.2em)
          #text(size: 8.4pt, labels.combiner-desc)
        ]
      ],
    )
    v(0.4em)
    align(center)[
      #text(size: 8.6pt, fill: umbrella-text-dim, style: "italic", labels.rng)
    ]
    v(0.2em)
    align(center)[
      #text(size: 9pt, fill: umbrella-text-dim, labels.caption)
    ]
  },
)

#let unlock-flow-diagram(labels: (
  title: "PIN-based unlock flow",
  steps: (
    "User enters PIN",
    "Argon2id KDF",
    "Fetch 3 of 5 shares",
    "HKDF re-derive device key",
    "MLS ratchet ready",
  ),
  caption: "All transient state in mlock'd heap; wiped on background.",
)) = block(
  fill: umbrella-bg-soft,
  stroke: 0.6pt + umbrella-rule,
  inset: 14pt,
  radius: 4pt,
  width: 100%,
  spacing: 0.8em,
  {
    align(center)[
      #text(weight: "bold", fill: umbrella-primary, size: 11pt, labels.title)
    ]
    v(0.5em)
    let n = labels.steps.len()
    grid(
      columns: n,
      column-gutter: 0pt,
      ..labels.steps.enumerate().map(((i, s)) => box(
        inset: 6pt,
        width: 100%,
        align(center)[
          #box(
            fill: if i == 0 { umbrella-accent } else if i == n - 1 { umbrella-primary } else { umbrella-secondary },
            inset: 8pt,
            radius: 4pt,
            width: 100%,
            text(fill: white, size: 8.8pt, weight: "semibold", s),
          )
        ],
      )),
    )
    v(0.2em)
    align(center)[
      #text(size: 9pt, fill: umbrella-text-dim, labels.caption)
    ]
  },
)
