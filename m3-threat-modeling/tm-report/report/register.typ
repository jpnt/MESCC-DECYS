// Tables computed from report/data/*.yaml: STRIDE per element, the threat
// register, DREAD ranking, the qualitative risk model, countermeasures,
// threat profiles and the pytm triage. Nothing here is typed by hand, so the
// numbers in every chapter stay consistent with the data.

#let threats = yaml("data/threats.yaml")
#let elements = yaml("data/elements.yaml")
#let packages = yaml("data/mitigations.yaml")
#let triage = yaml("data/pytm-triage.yaml")
#let levels = ("lv0", "lv0boot", "lv1", "lv1boot", "lv2", "lv2boot")

#let cells = (align: (x, y) => if y == 0 { center + horizon } else { left + top })
#let small(body) = { set text(size: 9pt); set par(justify: false); body }
#let head-fill = (x, y) => if y == 0 { luma(225) }

// ---------------------------------------------------------------- helpers

#let fmt(x) = {
  let s = str(calc.round(x, digits: 1))
  if s.contains(".") { s } else { s + ".0" }
}
#let score(t) = t.dread.sum() / 5
#let band(s) = if s >= 7 { "High" } else if s >= 5.5 { "Medium" } else { "Low" }

#let in-mode(t, mode) = t.mode == "both" or t.mode == mode
#let mode-label(t) = (normal: "Normal", boot: "Bootable", both: "Both").at(t.mode)
#let stride-name = (
  S: "Spoofing", T: "Tampering", R: "Repudiation",
  I: "Information disclosure", D: "Denial of service", E: "Elevation of privilege",
)
#let applicable = (
  entity: ("S", "R"),
  process: ("S", "T", "R", "I", "D", "E"),
  store: ("T", "I", "D"),
  flow: ("T", "I", "D"),
)
#let kind-label = (entity: "External entity", process: "Process", store: "Data store", flow: "Data flow")

#let cites(keys) = keys.map(k => cite(label(k))).join()

// Ranking order used by every ranked table: highest DREAD score first.
#let ranked = threats.sorted(key: t => (-score(t), t.id))
#let rank-of(id) = ranked.position(t => t.id == id) + 1

// pytm findings that map to a threat (rejected findings excluded).
#let pytm-for(id) = triage.filter(e => e.decision != "Rejected" and e.threats.contains(id)).map(e => e.id)

// OWASP-style qualitative model, derived from the DREAD factors:
// likelihood from Reproducibility, Exploitability and Discoverability,
// impact from Damage and Affected users.
#let likelihood(t) = (t.dread.at(1) + t.dread.at(2) + t.dread.at(4)) / 3
#let impact(t) = (t.dread.at(0) + t.dread.at(3)) / 2
#let level(x) = if x >= 7 { "High" } else if x >= 4 { "Medium" } else { "Low" }
#let severity-table = (
  High: (Low: "Medium", Medium: "High", High: "Critical"),
  Medium: (Low: "Low", Medium: "Medium", High: "High"),
  Low: (Low: "Note", Medium: "Low", High: "Medium"),
)
#let severity(t) = severity-table.at(level(impact(t))).at(level(likelihood(t)))

// ---------------------------------------------------------------- STRIDE per element

#let stride-matrix(mode, caption) = {
  let letters = ("S", "T", "R", "I", "D", "E")
  let rows = elements.at(mode).map(e => {
    let row = ([#e.name], [#kind-label.at(e.kind)])
    for l in letters {
      if not applicable.at(e.kind).contains(l) {
        row.push(text(fill: luma(150))[n/a])
      } else {
        let ids = threats.filter(t => t.lv1.contains(e.key) and t.stride == l).map(t => t.id)
        row.push(if ids.len() == 0 { [none] } else { [#ids.join(", ")] })
      }
    }
    row
  }).flatten()
  figure(
    small(table(
      columns: (2fr, 1fr) + (1fr,) * 6,
      ..cells, fill: head-fill,
      table.header([*Element*], [*Type*], ..letters.map(l => [*#l*])),
      ..rows,
    )),
    caption: caption,
  )
}

// ---------------------------------------------------------------- threat register

#let primary(t, mode) = {
  let keys = elements.at(mode).map(e => e.key)
  t.lv1.find(k => keys.contains(k))
}

// only: "new" lists threats specific to the mode (mode == t.mode); "all" lists every threat of the mode.
#let register(mode, caption, only: "all") = {
  let pick = threats.filter(t => if only == "new" { t.mode == mode } else { in-mode(t, mode) })
  let rows = ()
  for e in elements.at(mode) {
    let group = pick.filter(t => primary(t, mode) == e.key)
    if group.len() == 0 { continue }
    rows.push(table.cell(colspan: 5, fill: luma(240))[*#e.name* (#lower(kind-label.at(e.kind)))])
    for t in group {
      let extra = ()
      if "refs" in t { extra.push([#t.refs #cites(t.at("cite", default: ()))]) }
      let p = pytm-for(t.id)
      extra.push(if p.len() > 0 [pytm: #p.join(", ")] else [found by hand])
      rows += (
        [*#t.id*],
        [#t.stride],
        [*#t.name.* #t.desc #linebreak() #text(fill: luma(90))[#extra.join("; ")]],
        [#t.lv2],
        [#t.assets.join(", ")],
      )
    }
  }
  figure(
    small(table(
      columns: (auto, auto, 4fr, 1.6fr, auto),
      ..cells, fill: head-fill,
      table.header([*ID*], [*Type*], [*Threat*], [*Level 2*], [*Assets*]),
      ..rows,
    )),
    caption: caption,
  )
}

#let inherited(mode) = threats.filter(t => t.mode == "both").map(t => t.id).join(", ")

// ---------------------------------------------------------------- ranking

#let dread-table(caption) = figure(
  small(table(
    columns: (auto, auto, 3fr, auto, auto, auto, auto, auto, auto, auto, auto, auto),
    ..cells, fill: head-fill,
    align: (x, y) => if y == 0 { center + horizon } else if x == 2 { left } else { center },
    table.header(
      [*\#*], [*ID*], [*Threat*], [*Mode*], [*D*], [*R*], [*E*], [*A*], [*D#sub[i]*],
      [*Score*], [*Band*], [*OWASP*],
    ),
    ..ranked.enumerate().map(((i, t)) => (
      [#(i + 1)], [#t.id], [#t.name], [#mode-label(t)],
      ..t.dread.map(x => [#x]),
      [*#fmt(score(t))*], [#band(score(t))], [#severity(t)],
    )).flatten(),
  )),
  caption: caption,
)

#let risk-matrix(caption) = {
  let lv = ("Low", "Medium", "High")
  let rows = ()
  for i in lv.rev() {
    rows.push([*#i*])
    for l in lv {
      let ids = threats.filter(t => level(impact(t)) == i and level(likelihood(t)) == l).map(t => t.id)
      rows.push([*#severity-table.at(i).at(l)* #linebreak() #ids.join(", ")])
    }
  }
  figure(
    small(table(
      columns: (auto, 1fr, 1fr, 1fr),
      ..cells, fill: head-fill,
      table.header([*Impact / likelihood*], [*Low*], [*Medium*], [*High*]),
      ..rows,
    )),
    caption: caption,
  )
}

#let band-summary(caption) = {
  let count(f) = str(threats.filter(f).len())
  let row(name, f) = (
    [#name],
    [#count(t => f(t) and band(score(t)) == "High")],
    [#count(t => f(t) and band(score(t)) == "Medium")],
    [#count(t => f(t) and band(score(t)) == "Low")],
    [#count(f)],
  )
  figure(
    small(table(
      columns: (2fr, 1fr, 1fr, 1fr, 1fr),
      ..cells, fill: head-fill,
      table.header([*Threats*], [*High*], [*Medium*], [*Low*], [*Total*]),
      ..row("Normal mode only", t => t.mode == "normal"),
      ..row("Bootable mode only", t => t.mode == "boot"),
      ..row("Both modes", t => t.mode == "both"),
      ..row("All threats", t => true),
    )),
    caption: caption,
  )
}

// ---------------------------------------------------------------- countermeasures

#let threats-for(m) = threats.filter(t => t.mit.contains(m)).map(t => t.id)

#let packages-table(caption) = figure(
  small(table(
    columns: (auto, 1.2fr, 4fr, 1.3fr, 1.6fr),
    ..cells, fill: head-fill,
    table.header([*ID*], [*Package*], [*Measures*], [*STRIDE technique*], [*Threats*]),
    ..packages.map(p => (
      [*#p.id*],
      [#p.name],
      [#list(..p.measures.map(m => if m.kind == "administrative" [_(administrative)_ #m.text] else [#m.text]))],
      [#p.stride],
      [#threats-for(p.id).join(", ")],
    )).flatten(),
  )),
  caption: caption,
)

#let standards-table(caption) = figure(
  small(table(
    columns: (auto, 1.4fr, 2.6fr),
    ..cells, fill: head-fill,
    table.header([*Package*], [*Name*], [*Aligned with*]),
    ..packages.map(p => ([*#p.id*], [#p.name], [#cites(p.standards)])).flatten(),
  )),
  caption: caption,
)

#let measure-split(caption) = {
  let count(p, k) = str(p.measures.filter(m => m.kind == k).len())
  figure(
    small(table(
      columns: (auto, 2fr, 1fr, 1fr),
      ..cells, fill: head-fill,
      table.header([*Package*], [*Name*], [*Technical*], [*Administrative*]),
      ..packages.map(p => ([#p.id], [#p.name], [#count(p, "technical")], [#count(p, "administrative")])).flatten(),
    )),
    caption: caption,
  )
}

#let profile-table(caption) = figure(
  small(table(
    columns: (auto, auto, 2fr, auto, auto, 3fr),
    ..cells, fill: head-fill,
    table.header([*\#*], [*ID*], [*Threat*], [*Packages*], [*Profile*], [*What remains*]),
    ..ranked.enumerate().map(((i, t)) => (
      [#(i + 1)], [#t.id], [#t.name],
      [#if t.mit.len() > 0 { t.mit.join(", ") } else { [none] }],
      [#(Fully: "Fully mitigated", Partially: "Partially mitigated", Not: "Not mitigated").at(t.profile)],
      [#t.residual],
    )).flatten(),
  )),
  caption: caption,
)

#let profile-summary(caption) = {
  let count(p, f) = str(threats.filter(t => t.profile == p and f(t)).len())
  let row(name, f) = ([#name], [#count("Fully", f)], [#count("Partially", f)], [#count("Not", f)])
  figure(
    small(table(
      columns: (2fr, 1fr, 1fr, 1fr),
      ..cells, fill: head-fill,
      table.header([*Threats*], [*Fully*], [*Partially*], [*Not mitigated*]),
      ..row("High band", t => band(score(t)) == "High"),
      ..row("Medium band", t => band(score(t)) == "Medium"),
      ..row("Low band", t => band(score(t)) == "Low"),
      ..row("All threats", t => true),
    )),
    caption: caption,
  )
}

// ---------------------------------------------------------------- pytm triage

#let pytm-data = levels.map(l => (l, json("../build/" + l + "/pytm.json"))).to-dict()

#let pytm-name(id) = {
  for (l, d) in pytm-data {
    let hit = d.threats.find(t => t.id == id)
    if hit != none { return hit.name }
  }
  "?"
}
#let pytm-levels(id) = levels.filter(l => pytm-data.at(l).threats.any(t => t.id == id))

#let triage-table(caption) = figure(
  small(table(
    columns: (auto, 1.4fr, 1.1fr, auto, 1.2fr, 3fr),
    ..cells, fill: head-fill,
    table.header([*pytm ID*], [*pytm threat*], [*Flagged on*], [*Decision*], [*Report threats*], [*Reasoning*]),
    ..triage.map(e => (
      [#e.id],
      [#pytm-name(e.id)],
      [#e.flagged #linebreak() #text(fill: luma(90))[#{ let l = pytm-levels(e.id); if l.len() == levels.len() [all levels] else [#l.join(", ")] }]],
      [#e.decision],
      [#if e.threats.len() > 0 { e.threats.join(", ") } else { [none] }],
      [#e.note],
    )).flatten(),
  )),
  caption: caption,
)

#let hand-only() = threats.filter(t => pytm-for(t.id).len() == 0).map(t => t.id).join(", ")
#let hand-only-count() = str(threats.filter(t => pytm-for(t.id).len() == 0).len())
