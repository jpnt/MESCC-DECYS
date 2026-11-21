// Inserts a source snippet from report/snippets/ as a figure.

#let snippet(path, caption: none, lang: "c") = {
  set text(size: 8pt)
  set par(justify: false)
  figure(
    caption: caption,
    raw(read("snippets/" + path), lang: lang, block: true),
  )
}
