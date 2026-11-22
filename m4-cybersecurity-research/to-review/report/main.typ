// DECYS cybersecurity research project report (group #10).
// "Key Reinstallation Attacks against WPA2" per the team plan of 17 Nov 2026.
// Prose in report/content/*.md, evidence in report/snippets/ and lab/.
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
#md("2-background/3-related-work.md")

= The Vulnerability: Key Reinstallation
#md("3-analysis/1-wpa-mechanisms.md")

= Security Implications
#md("4-implications.md")

= Experimental Reproduction
#md("5-experiment.md")

= Mitigations and Evolution
#md("6-mitigations.md")

= Critical Evaluation and Conclusion
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
