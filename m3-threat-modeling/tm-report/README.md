# AppShield threat model (M3)

Follows the OWASP Threat Modeling Process (lecture 02), starting from Figure 2 of the brief.

## Layout

- `analysis/` - the thinking. Markdown and images only.
  - `brief/` - reading of the assignment brief.
  - `lv0/`, `lv1/`, `lv1boot/` (bootable mode), ... - one folder per DFD depth, two steps in order:
    - `1-decompose.md` - the DFD narrative and the OWASP phase 1 lists read off it (only rows new at this depth); the DFD image is generated from the pytm model into `build/`; copy it to `pytm-dfd.png` in the folder to show it in the report
    - `2-stride.md` - STRIDE on this depth's elements
  - `ranking.md`, `mitigations.md` - phases 2 and 3, once over all threats. DREAD scores in `ranking.md`, packages M1 to M10 and the threat profile in `mitigations.md`.
- `tools/pytm/` - one pytm model per depth (`lv0.py`, `lv1.py`, `lv1boot.py`), mirroring `analysis/lvN/1-decompose.md`.
- `report/` - the deliverable. `main.typ` renders the `analysis/` markdown directly (cmarker), plus the pytm output.

## Build

`make lv0`, `make lv1` and `make lv1boot` rebuild one model into `build/<level>/` (`pytm.json`, `dfd.dot`, `pytm-dfd.png`).
`make models` builds every level.
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
  - [x] Decompose (`analysis/lv1/1-decompose.md`)
  - [x] STRIDE, lv0 threats attached to the smaller circles (`analysis/lv1/2-stride.md`)
  - [x] pytm model `tools/pytm/lv1.py`
  - [x] Bootable mode: own DFD, STRIDE and model (`analysis/lv1boot/`, `tools/pytm/lv1boot.py`)
- lv2 - only if a lv1 process is still too coarse to find specific threats

Phase 2, once:

- [x] Rank every threat with one method: DREAD (slide 42) or Risk = Likelihood x Impact (slide 44)

Phase 3, once:

- [x] Countermeasure per threat (slide 49)
- [x] Threat profile: not, partially or fully mitigated (slide 50)

Report:

- [x] Assemble `report/main.typ` from `analysis/`
- [x] Abstract and references (rubric: organization 15%, sources 10%)
