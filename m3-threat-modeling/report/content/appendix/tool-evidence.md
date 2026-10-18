# How the models are built

All six DFDs are pytm models [@pytm] in `tools/pytm/`, one Python file per diagram (`lv0.py`, `lv0boot.py`, `lv1.py`, `lv1boot.py`, `lv2.py`, `lv2boot.py`). A shared module, `appshield_common.py`, creates the elements and flows in a uniform way and records what the brief says about each one. The host is marked as unmanaged C++ code that does not check its input bounds, the console's stores as unencrypted local files, and the console to host flows as having no authentication, encryption or replay protection. Anything the brief does not state is left at pytm's default, which is "control absent", so the tool reports the gap rather than assuming it away.

`make report` rebuilds everything in order. For each model it runs `export.py`, which draws the DFD with Graphviz and writes the findings, elements and flows to `build/<level>/pytm.json`. `make check` then refuses to continue if any pytm finding is missing from the triage table below, and Typst finally compiles the report, reading the DFD images, the flow tables and the counts in this appendix directly from those files. The report cannot show a diagram that differs from its model, or skip a finding the tool produced.

The level 1 normal mode model is reproduced here as an example of what the models look like.

<!--raw-typst #block(width: 100%, inset: 6pt, fill: luma(247), stroke: luma(200), { set text(size: 7.5pt); raw(model-source("lv1"), lang: "python", block: true) }) -->

# Findings per diagram

<!--raw-typst #pytm.pytm-summary([pytm findings per DFD]) <tbl-pytm-summary> -->

pytm reports a finding for every element a threat could apply to, so the counts grow quickly with the size of the diagram while the number of distinct threats stays almost the same. Level 2 has close to three times as many findings as level 1 but the same threat IDs, which supports the choice of level 1 as the working level for STRIDE per element.

# Excluded findings

Two assumptions in the models exclude findings that cannot apply to AppShield. pytm still records the excluded findings under the assumption that excluded them, so the exclusion is visible rather than silent.

<!--raw-typst #pytm.pytm-exclusions("lv1", [Findings excluded by assumption, level 1 normal mode]) <tbl-pytm-exclusions> -->

# Triage of the remaining findings

Every distinct threat pytm kept, across all six models, was reviewed against the threat register. *Kept* means the finding matches one or more register threats as it stands, *Merged* means it is one technique within a broader register threat, and *Rejected* means it does not apply to AppShield, for the reason given.

<!--raw-typst #register.triage-table([Triage of the pytm findings against the threat register]) <tbl-pytm-triage> -->
