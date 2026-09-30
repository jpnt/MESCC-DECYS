#import "@preview/red-agora:0.2.0": project
#import "md.typ": md
#import "pytm.typ": pytm-threats, pytm-exclusions

#show: project.with(
  title: "AppShield Threat Model Report",
  subtitle: "Confiabilidade e Ciberseguranca - DECYS",
  school-logo: image("logo_isep.png"),
  authors: (
    "João Pinto - 1221294@isep.ipp.pt",
    "Sérgio Cardoso - 1210891@isep.ipp.pt",
    "Vitor Santos - 1250446@isep.ipp.pt",
    "Shijo George - 1240374@isep.ipp.pt",
  ),
  mentors: (),
  jury: (),
  branch: "Sistemas Computacionais Criticos",
  academic-year: "2026-2027",
  footer-text: "Mestrado em Sistemas Computacionais Criticos",
)

= Introduction

This report applies the OWASP Threat Modeling Process to AppShield, a file and
registry integrity checking tool. It follows the three phases defined by the
process: (1) decompose the application, (2) determine and rank threats, and
(3) determine countermeasures and mitigation.

= Decomposition of the Application

#md("lv0", "1-decompose.md")

= Threats

#md("lv0", "2-stride.md")

= Appendix: pytm raw output

Full output of the level 0 pytm model, referenced by the "Manual vs. pytm cross-check" summary above.

#pytm-threats("lv0")

#pytm-exclusions("lv0")
