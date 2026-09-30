// Renders a markdown file from analysis/ into the report.
// Markdown headings start at level 2, under the report chapter that includes them.
// Image paths in the markdown are relative to its own folder.

#import "@preview/cmarker:0.1.10"

#let md(dir, file) = cmarker.render(
  read("../analysis/" + dir + "/" + file),
  h1-level: 2,
  scope: (
    image: (source, alt: none, format: auto) => image("../analysis/" + dir + "/" + source, alt: alt, format: format),
  ),
)
