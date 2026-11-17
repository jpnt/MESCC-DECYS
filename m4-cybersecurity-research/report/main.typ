// DECYS cybersecurity research project report (group #10).
// KRACK WPA2 — Security Analysis of Existing Systems, per the team plan
// ("KRACK WPA2 — Project Description and Work Plan", 17 Nov 2026):
// 1 Introduction / 2 Technical background / 3 The vulnerability /
// 4 Security implications / 5 Experimental reproduction /
// 6 Mitigations and evolution / 7 Critical evaluation and conclusion.
// Prose in report/content/*.md, evidence in report/snippets/ + lab/.
// Build: `make report` from m4-cybersecurity-research/.

#import "@preview/red-agora:0.2.0": project
#import "md.typ": md

#show: project.with(
  title: "Key Reinstallation Attacks against WPA2: How a Handshake State Machine Undermined Encryption Without Breaking the Cipher",
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

= The Vulnerability: Key Reinstallation
#md("5-analysis/1-wpa-mechanisms.md")
#md("3-philosophy.md")
#md("5-analysis/2-nuttx-cve1.md")
#md("5-analysis/3-nuttx-cve1-model.md")
#md("5-analysis/4-nuttx-cve1-results.md")
#md("5-analysis/5-nuttx-cve2.md")

= Security Implications
#md("6-implications.md")

= Experimental Reproduction
#md("5-experiment.md")

= Mitigations and Evolution
#md("6-mitigations.md")

= Critical Evaluation and Conclusion
#md("6-zephyr.md")
#md("7-discussion.md")
#md("7-evaluation.md")
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
