// Renders a markdown file from report/content/ into the report.
// Markdown "#" headings become level 2 headings, under the chapter that includes them.
// Images: paths starting with "/" are relative to the repository root (for
// example /build/lv1/pytm-dfd.png); other paths are relative to report/content/.
// Typst functions from pytm.typ and register.typ can be called from the
// markdown with <!--raw-typst #function(...) -->.

#import "@preview/cmarker:0.1.10"
#import "pytm.typ"
#import "register.typ"

// Markdown tables come out of cmarker with every column set to auto, which
// Typst shares out evenly once the text overflows, so long descriptions end
// up squeezed. Rebuild them: columns whose cells are all short stay auto,
// text columns get a share of the width in proportion to how much text they
// hold. Smaller font, left aligned, shaded header. Tables built in typst
// (register.typ, pytm.typ) set their own widths and are left untouched.
#let plain(c) = {
  if type(c) == str { c }
  else if c.has("text") { c.text }
  else if c.has("children") { c.children.map(plain).join(default: "") }
  else if c.has("body") { plain(c.body) }
  else if c.has("child") { plain(c.child) }
  else { " " }
}

#let md-table(t) = {
  if type(t.columns) != array or t.columns.any(c => c != auto) { return t }
  let n = t.columns.len()
  let header = t.children.filter(c => c.func() == table.header)
  let body = t.children.filter(c => c.func() != table.header)
  let rows = body.chunks(n)
  // A row with text only in its first cell is a group heading: span it.
  let is-group(r) = r.len() == n and n > 1 and r.slice(1).all(c => plain(c).trim() == "")
  let measured = header.map(h => h.children).flatten() + rows.filter(r => not is-group(r)).flatten()
  let col-text = range(n).map(i => measured.enumerate().filter(((k, _)) => calc.rem(k, n) == i).map(((_, c)) => plain(c).len()))
  let widths = col-text.map(lens => {
    if lens.len() == 0 or calc.max(..lens) <= 25 { auto }
    else { calc.pow(lens.sum() / lens.len(), 0.75) * 1fr }
  })
  let cells = rows.map(r => if is-group(r) {
    (table.cell(colspan: n, fill: luma(242), r.at(0).body),)
  } else { r }).flatten()
  set text(size: 9pt)
  set par(justify: false)
  table(
    columns: widths,
    align: left + top,
    fill: (x, y) => if y == 0 { luma(225) },
    ..header,
    ..cells,
  )
}

// Source of a pytm model, for listing it in the appendix. Paths in raw-typst
// blocks resolve inside the cmarker package, so the file is read here.
#let model-source(level) = read("/tools/pytm/" + level + ".py")

#let md(path) = {
  show table: md-table
  cmarker.render(
  read("content/" + path),
  h1-level: 2,
  scope: (
    image: (source, ..args) => image(
      if source.starts-with("/") { source } else { "content/" + source },
      ..args,
    ),
    model-source: model-source,
    pytm: pytm,
    register: register,
  ),
)
}
