// Tables built from the output of tools/pytm/export.py (build/<level>/pytm.json),
// so the DFD figures and the tables describing them come from the same model.

#let cells = (align: (x, y) => if y == 0 { center + horizon } else { left + top })
#let small(body) = { set text(size: 9pt); set par(justify: false); body }
#let head-fill = (x, y) => if y == 0 { luma(225) }
#let load(level) = json("../build/" + level + "/pytm.json")

#let level-names = (
  lv0: "Level 0", lv1: "Level 1", lv2: "Level 2",
  lv0boot: "Level 0 bootable", lv1boot: "Level 1 bootable", lv2boot: "Level 2 bootable",
)

// The DFD drawn by pytm for one level. Wide diagrams (level 2) get a page
// of their own in landscape so the labels stay readable.
#let dfd(level, caption, width: 100%, landscape: false) = {
  let path = "../build/" + level + "/pytm-dfd.png"
  if landscape {
    page(flipped: true, align(center + horizon, figure(
      image(path, width: 100%, height: 88%, fit: "contain"),
      caption: caption,
    )))
  } else {
    figure(image(path, width: width), caption: caption)
  }
}

// Elements of one DFD with their type and the boundaries around them.
#let pytm-elements(level, caption) = {
  let data = load(level)
  figure(
    small(table(
      columns: (1.4fr, 1fr, 2fr),
      ..cells, fill: head-fill,
      table.header([*Element*], [*Type*], [*Inside boundary*]),
      ..data.elements.map(e => ([#e.name], [#e.kind], [#if e.boundary == "" [none] else [#e.boundary]])).flatten(),
    )),
    caption: caption,
  )
}

// Flows of one DFD in diagram order, with the boundaries each one crosses.
#let pytm-flows(level, caption) = {
  let data = load(level)
  figure(
    small(table(
      columns: (auto, 1.4fr, 1.2fr, 1.2fr, 1.6fr),
      ..cells, fill: head-fill,
      table.header([*\#*], [*Data*], [*From*], [*To*], [*Crosses*]),
      ..data.flows.map(f => (
        [#f.order], [#f.name], [#f.source], [#f.sink],
        [#if f.crosses.len() == 0 [none] else [#f.crosses.join(", ")]],
      )).flatten(),
    )),
    caption: caption,
  )
}

// One row per level: findings kept, distinct threat IDs, findings excluded.
#let pytm-summary(caption) = figure(
  small(table(
    columns: (1.4fr, 1fr, 1fr, 1fr, 1fr, 1fr),
    ..cells, fill: head-fill,
    table.header([*DFD*], [*Elements*], [*Flows*], [*Findings kept*], [*Distinct threats*], [*Excluded by assumption*]),
    ..level-names.keys().map(l => {
      let d = load(l)
      ([#level-names.at(l)], [#d.elements.len()], [#d.flows.len()], [#d.findings], [#d.threats.len()], [#d.excluded])
    }).flatten(),
  )),
  caption: caption,
)

// The assumptions that excluded findings, with what they excluded.
#let pytm-exclusions(level, caption) = {
  let data = load(level)
  figure(
    small(table(
      columns: (1fr, 2.4fr, 1.2fr),
      ..cells, fill: head-fill,
      table.header([*Assumption*], [*Reason*], [*Excluded threats*]),
      ..data.assumptions.map(a => ([#a.name], [#a.description], [#a.threats.join(", ")])).flatten(),
    )),
    caption: caption,
  )
}
