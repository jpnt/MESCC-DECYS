#import "@preview/red-agora:0.2.0": project
#import "md.typ": md
#import "pytm.typ": pytm-summary

#show: project.with(
  title: "AppShield Threat Model Report",
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

= Abstract

AppShield checks whether files and registry keys on a monitored machine still
match a trusted baseline. This report models that job in three views: level 0
for the whole system, level 1 for normal network mode with the console and host
opened into their internal parts, and level 1 bootable for offline rescue mode.

The main result is not one isolated flaw but three trust failures: the
console-to-host channel is not protected, the baseline and configuration are
trusted files that the console does not protect, and administrator access is
only as strong as the login and credential storage. Threats are found with
STRIDE (what can go wrong), cross-checked with pytm (tool-generated threat
candidates), ranked with DREAD (how serious each threat is), and mitigated with
the packages M1 to M10.

= Read this first

#md(".", "guide.md")

= Level 0

== Decomposition

#md("lv0", "1-decompose.md")

== Threats

#md("lv0", "2-stride.md")

= Level 1

== Decomposition

#md("lv1", "1-decompose.md")

== Threats

#md("lv1", "2-stride.md")

= Level 1, bootable mode

== Decomposition

#md("lv1boot", "1-decompose.md")

== Threats

#md("lv1boot", "2-stride.md")

= Ranking

#md(".", "ranking.md")

= Countermeasures

#md(".", "mitigations.md")

= References

- OWASP, Threat Modeling Process, https://owasp.org/www-community/Threat_Modeling_Process
- A. Shostack, Threat Modeling: Designing for Security, Wiley, 2014.
- DECYS lecture 02, Threat Modeling, ISEP.
- DECYS assignment brief, Threat Modeling (AppShield).
- OWASP pytm, https://github.com/OWASP/pytm

= Appendix: pytm evidence summary

The STRIDE chapters already show which `pytm` findings were matched, collapsed or rejected.
This appendix keeps only the per-level summary counts.

#figure(
  table(
    columns: (auto, auto, auto, auto),
    align: (x, y) => if y == 0 { center + horizon } else { left + top },
    table.header([*Level*], [*Kept findings*], [*Distinct threats*], [*Excluded by assumptions*]),
    ..pytm-summary("lv0"),
    ..pytm-summary("lv1"),
    ..pytm-summary("lv1boot"),
  ),
  caption: [pytm summary used by the report],
)
