# NuttX security research report (DECYS, group 10)

Security analysis of Apache NuttX RTOS: CVE taxonomy, two source-level
reproductions (CVE-2025-35003, CVE-2025-48768), a Linux-lineage design
chapter, and a Zephyr practice comparison. Written for Reliability and
Cybersecurity (DECYS), research style "Security Analysis of Existing
Systems".

`make report` compiles `report.pdf` (final report, ~50 pages) from the
markdown in `report/content/` with Typst. `make progress` compiles
`progress_report.pdf`; `make slides` compiles `slides.pdf` (13 slides,
the presentation deck). `make snippets` fetches the two NuttX release
trees the harnesses quote and rebuilds and runs the AddressSanitizer
reproductions in `report/snippets/` (see `report/snippets/Makefile`);
`make sources` only fetches.

```
report/content/      one markdown file per section
report/snippets/     ASan harnesses, verbatim upstream extracts, frozen traces
report/main.typ      report structure (typst + cmarker, as in m3)
work/                cloned upstream trees (gitignored)
idea.org             original project idea notes
```

`work/` is gitignored and regenerable (`make sources`); everything in
`report/` is source. The `.inc` files are byte-extracts of the upstream
release tags named in their headers; `make snippets` regenerates and
runs them.
