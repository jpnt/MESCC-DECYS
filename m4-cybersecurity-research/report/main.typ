// DECYS cybersecurity research project report (group #10).
// Prose lives in report/content/*.md, reproduction code in report/snippets/.
// Build with `make report` from m4-cybersecurity-research/.

#import "@preview/red-agora:0.2.0": project
#import "md.typ": md

#show: project.with(
  title: "A Security Analysis of Apache NuttX RTOS: Vulnerability Reproduction and a Zephyr Comparison",
  subtitle: "Reliability and Cybersecurity - DECYS",
  school-logo: image("logo_isep.png"),
  authors: (
    "João Pinto - 1221294@isep.ipp.pt",
    "Sérgio Cardoso - 1210891@isep.ipp.pt",
    "Vitor Santos - 1250446@isep.ipp.pt",
    "Shijo George - 1240374@isep.ipp.pt",
  ),
  mentors: (),
  jury: (),
  branch: "Critical Computing Systems",
  academic-year: "2026-2027",
  footer-text: "Master in Critical Computing Systems",
)

#set text(size: 11pt)
#set par(justify: true)
#show figure.where(kind: table): set figure.caption(position: top)
#show link: set text(fill: rgb("#1a4f8b"))
#show heading: set text(hyphenate: false)
#show heading: set par(justify: false)

#heading(numbering: none, outlined: true)[Abstract]
#md("abstract.md")

= Introduction
#md("1-introduction.md")

= Background and Related Work
#md("2-background/1-nuttx.md")
#md("2-background/2-cve-taxonomy.md")
#md("2-background/3-related-work.md")

= Kernel Design Philosophy: NuttX, Linux and Isolation
#md("3-philosophy.md")

= Case Study 1: Bluetooth HCI UART Stack Overflow (CVE-2025-35003)
#md("4-case-study/1-disclosure.md")
#md("4-case-study/2-anatomy.md")
#md("4-case-study/3-replication.md")

= Case Study 2: Inode Tree Root Removal (CVE-2025-48768) and the fs_rename UAF
#md("4-case-study/4-second-case.md")

= NuttX Engineering Practice: Zephyr as Counterfactual
#md("5-zephyr.md")

= Discussion and Lessons for Critical Systems
#md("6-discussion.md")

= Conclusion
#md("7-conclusion.md")

#pagebreak()
#bibliography("refs.bib", title: "References", style: "ieee")

#pagebreak()
#counter(heading).update(0)
#set heading(numbering: "A.1")
= Reproduction Artifacts
#md("appendix/artifacts.md")
= Full Harness Sources
#md("appendix/poc-source.md")
