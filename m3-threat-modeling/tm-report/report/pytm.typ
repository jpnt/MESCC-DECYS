// Renders the output of tools/pytm/export.py for one DFD depth.

#let cells = (
  align: (x, y) => if y == 0 { center + horizon } else { left + top },
)

// Threats pytm kept, one row per threat ID.
#let pytm-threats(level) = {
  let data = json("../build/" + level + "/pytm.json")
  show figure: set block(breakable: true)
  figure(
    table(
      columns: (auto, 1fr, auto, 1.4fr),
      ..cells,
      table.header([*ID*], [*Threat*], [*Severity*], [*Applies to*]),
      ..data.threats.map(t => (t.id, t.name, t.severity, t.targets.join(", "))).flatten(),
    ),
    caption: [pytm findings, #level: #data.findings findings, #data.threats.len() distinct threats],
  )
}

// Threats pytm excluded, one row per assumption that excluded them.
#let pytm-exclusions(level) = {
  let data = json("../build/" + level + "/pytm.json")
  show figure: set block(breakable: true)
  figure(
    table(
      columns: (1fr, 2fr, 1fr, 1fr),
      ..cells,
      table.header([*Assumption*], [*Reason*], [*Excluded*], [*Applies to*]),
      ..data.assumptions.map(a => (a.name, a.description, a.threats.join(", "), a.targets.join(", "))).flatten(),
    ),
    caption: [pytm findings excluded by assumption, #level: #data.excluded findings],
  )
}
