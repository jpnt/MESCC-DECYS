// DECYS cybersecurity research project report (group #10).
// Prose lives in report/content/*.md, reproduction code in report/snippets/.
// Build with `make report` from m4-cybersecurity-research/.
// Section order follows the agreed WPA2-focused research structure:
// 1 intro / 2 background / 3 protocol analysis / 4 implications /
// 5 experiments / 6 mitigations / 7 evaluation / 8 conclusion, with the
// NuttX memory-safety case studies as the platform spine.

#import "@preview/red-agora:0.2.0": project
#import "md.typ": md

#show: project.with(
  title: "Key Reinstallation Without Broken Crypto: A Security Analysis of WPA2/WPA3 Handshake Implementations on Apache NuttX Products",
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

= Technical Background
#md("2-background/0-ieee80211-wpa2.md")
#md("2-background/1-nuttx.md")
#md("2-background/2-cve-taxonomy.md")
#md("2-background/3-related-work.md")

= Vulnerability Analysis: Protocol and Implementation
#md("3-philosophy.md")
#md("5-analysis/1-wpa-mechanisms.md")
#md("5-analysis/2-nuttx-cve1.md")
#md("5-analysis/3-nuttx-cve1-model.md")
#md("5-analysis/4-nuttx-cve1-results.md")
#md("5-analysis/5-nuttx-cve2.md")

= Security Implications
#md("6-implications.md")

= Practical Experiment and Reproduction
#md("7-experiment.md")

= Mitigations
#md("8-mitigations.md")

= Critical Evaluation: What Went Wrong
#md("6-zephyr.md")
#md("7-discussion.md")
#md("9-evaluation.md")

= Conclusion
#md("8-conclusion.md")

#pagebreak()
#bibliography("refs.bib", title: "References", style: "ieee")

#pagebreak()
#counter(heading).update(0)
#set heading(numbering: "A.1")
= Reproduction Artifacts
#md("appendix/artifacts.md")
= Full Harness Sources
#md("appendix/poc-source.md")
