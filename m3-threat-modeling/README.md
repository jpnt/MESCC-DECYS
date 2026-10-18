# AppShield threat model report

This directory holds everything needed to produce the threat model report of the AppShield integrity checking tool, written for Reliability and Cybersecurity (DECYS) following the OWASP threat modeling process. Nothing in the final PDF is pasted in by hand: the data flow diagrams are pytm models in `tools/pytm/`, the threats, DREAD scores and countermeasures are YAML files in `report/data/`, and the prose is one markdown file per section in `report/content/`. Typst puts the three together, so a diagram, a score or a sentence is changed in one place and every table that depends on it follows.

`make report` runs the whole chain. It turns each pytm model into a diagram and a list of findings in `build/`, refuses to continue if any pytm finding has not been triaged, renders the attack tree, and compiles `report.pdf`. `build/` and `report.pdf` are generated, so they can always be deleted with `make clean` and rebuilt.

```
tools/pytm/            one pytm model per DFD: lv0, lv0boot, lv1, lv1boot, lv2, lv2boot
  appshield_common.py  shared building blocks and assumptions used by every model
  export.py            writes build/<level>/{pytm.json, dfd.dot, pytm-dfd.png}
  coverage.py          fails if a pytm finding is missing from the triage
  pyproject.toml       Python dependencies (pytm), read by uv
report/
  main.typ             chapter order; the only place the structure is defined
  md.typ, pytm.typ, register.typ   turn markdown, pytm output and YAML into report content
  content/             the prose, one markdown file per section
  data/                threats, DFD elements, countermeasures and pytm triage (YAML)
  figures/             Graphviz source of the attack tree
  refs.bib             bibliography
  logo_isep.png        cover logo
```

## Requirements

- [uv](https://docs.astral.sh/uv/), which installs Python and pytm for you
- [Graphviz](https://graphviz.org/) (the `dot` command)
- [Typst](https://typst.app/) (tested with 0.15)

After cloning, run `uv sync --project tools/pytm` once. It creates `tools/pytm/.venv` and installs pytm into it; `make` then uses that environment through `uv run`.

## Making each thing

| Command | What it does |
| --- | --- |
| `make report` | Builds everything below and then `report.pdf`. |
| `make models` | Builds every DFD: `build/<level>/pytm-dfd.png` and `pytm.json`. |
| `make lv1` (or any level) | Rebuilds a single DFD, for example after editing `tools/pytm/lv1.py`. |
| `make check` | Builds every DFD and checks that each pytm finding appears in `report/data/pytm-triage.yaml`. |
| `make figures` | Renders the attack tree into `build/figures/`. |
| `make clean` | Deletes `build/` and `report.pdf`. |

## Changing the content

- **A diagram:** edit `tools/pytm/<level>.py`, then `make <level>` to look at `build/<level>/pytm-dfd.png`. Flow numbers follow the order the flows are created in the file, so moving a line renumbers the flows after it.
- **A threat, a score or a countermeasure:** edit `report/data/threats.yaml` or `mitigations.yaml`. The STRIDE matrices, registers, ranking and threat profiles are recomputed on the next build.
- **New pytm findings:** after changing a model, `make check` names any finding not yet triaged. Add an entry for it in `report/data/pytm-triage.yaml`.
- **Text:** edit the markdown in `report/content/`. Cite with `[@key]`, one key per bracket (`[@a] [@b]`, not `[@a; @b]`). Refer to a labelled table or figure with `[@tbl-...]` or `[@fig-...]`.

## Troubleshooting

**`ModuleNotFoundError: No module named 'pytm'`**
uv did not find `tools/pytm/pyproject.toml`, so it ran a plain Python without pytm. This happens when the folder is copied without that file. Check it exists, then run `uv sync --project tools/pytm`. There is no need to create or activate a virtual environment yourself: uv keeps its own in `tools/pytm/.venv`, and an activated one elsewhere only causes a harmless warning.

**`No module named 'pytm'` even though the file is there**
The environment is out of date or broken. Delete `tools/pytm/.venv` and run `uv sync --project tools/pytm` again.

**`make: *** No rule to make target 'report´'`**
A stray character was typed after the target name (here an accent key). Retype the command as `make report`.

**`label ... does not exist in the document`**
A citation key in the markdown is not in `report/refs.bib`, or two keys were grouped in one bracket. Use one key per bracket.

**`typst: command not found` or `dot: command not found`**
Install Typst or Graphviz and make sure the command is on your `PATH`.