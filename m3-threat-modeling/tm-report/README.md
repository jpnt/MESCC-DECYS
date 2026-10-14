# AppShield threat model (M3)

Follows the OWASP Threat Modeling Process (lecture 02), starting from Figure 2 of the brief.

## Layout

- `analysis/` - the thinking. Markdown and images only.
  - `brief/` - reading of the assignment brief.
  - `lv0/`, `lv1/`, ... - one folder per DFD depth, two steps in order:
    - `1-decompose.md` - the DFD narrative and the OWASP phase 1 lists read off it (only rows new at this depth); the DFD image itself is generated from the pytm model into `build/` and rendered by the report
    - `2-stride.md` - STRIDE on this depth's elements
  - `ranking.md`, `mitigations.md` - phases 2 and 3, once over all threats (not started).
- `tools/pytm/` - one pytm model per depth (`lv0.py`, ...), mirroring `analysis/lvN/1-decompose.md`.
- `report/` - the deliverable. `main.typ` renders the `analysis/` markdown directly (cmarker), plus the pytm output.

## Build

`make report` runs every `tools/pytm/lv*.py` into `build/` (not committed), checks that each pytm threat is triaged in the matching `analysis/lvN/2-stride.md`, then builds `report.pdf`.
CI does the same on push and uploads the PDF.
Needs `uv`, `dot` (graphviz) and `typst`.

## How the steps fit

The DFD is the backbone. The phase 1 lists are read off it:

- external dependencies: what the processes run on
- entry/exit points: arrows crossing a trust boundary inwards/outwards
- assets: what is worth attacking
- trust levels: who sits on each side of each boundary

Each depth repeats: decompose (DFD, then the lists), STRIDE on the new elements, pytm model.
Ranking and mitigations are done once, over all threats.

## Checklist

Phase 1 and phase 2 threat analysis, per depth:

- lv0 - scope
  - [x] Decompose: DFD and phase 1 lists (`analysis/lv0/1-decompose.md`)
  - [x] STRIDE per element (`analysis/lv0/2-stride.md`)
  - [x] pytm model (`tools/pytm/lv0.py`), findings triaged in `2-stride.md`
- lv1 - open the circles
  - [ ] Decompose: split console and host using the brief's verbs; data stores and console storage boundary appear; new list rows (baseline and configuration become assets)
    - Carry in from `../legacy/phase1-tables` (Sérgio): system clock (ED19, the brief compares "Date and time of the most recent update"), Service Control Manager (ED8, EP3), error messages as exit points (XP2, XP5; lecture 02 slide 15), configuration as scan scope (asset 2.3)
  - [ ] STRIDE on the new elements; attach lv0 threats to the smaller circles
  - [ ] pytm model `tools/pytm/lv1.py`
  - [ ] Bootable mode: its own lv1 DFD, STRIDE and model (lecture 02, slide 25: a level 1 diagram is a "single feature / scenario")
- lv2 - only if a lv1 process is still too coarse to find specific threats

Phase 2, once:

- [ ] Rank every threat with one method: DREAD (slide 42) or Risk = Likelihood x Impact (slide 44)

Phase 3, once:

- [ ] Countermeasure per threat (slide 49)
- [ ] Threat profile: not, partially or fully mitigated (slide 50)

Report:

- [ ] Assemble `report/main.typ` from `analysis/`
- [ ] Abstract and references (rubric: organization 15%, sources 10%)
