#import "@preview/red-agora:0.2.0": project

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
(3) determine countermeasures and mitigation. This section covers phase 1.

= Decomposition of the Application

== External Dependencies

#figure(
  table(
    columns: (auto, 1fr),
    table.header([*ID*], [*Description*]),
    [ED1], [Windows Server - Host runs as a service on it, normal mode only. Version unspecified in the spec],
    [ED2], [Windows OS on the Console machine. Version and edition unspecified in the spec],
    [ED3], [Filesystem and Registry being scanned - source of names, sizes, timestamps, hashes],
    [ED4], [Network transport between Host and Console. Protocol unspecified. No encryption or authentication built in],
    [ED5], [Local disk on the Console machine - stores baseline data and config/credentials],
    [ED6], [MD5/SHA1 hashing implementation used by Host to compute checksums],
    [ED7], [Bootable CD/USB medium - alternate mode, Host and Console run standalone instead of as a Windows service],
    [ED8], [Firmware/BIOS of the machine being checked in bootable mode - not verifiable by the app],
  ),
  caption: [External Dependencies],
)

== Entry Points

#figure(
  table(
    columns: (auto, auto, 1fr, auto),
    table.header([*ID*], [*Name*], [*Description*], [*Trust Level*]),
    [EP1], [Host listener], [Host accepts requests from Console: version, file/registry properties], [T2],
    [EP2], [Console UI], [User tells Console which host to connect to and triggers a scan], [T1],
    [EP3], [Boot from CD/USB], [Standalone Host and Console launched on a possibly-compromised machine], [T3],
  ),
  caption: [Entry Points],
)

== Exit Points

#figure(
  table(
    columns: (auto, 1fr),
    table.header([*ID*], [*Description*]),
    [XP1], [Host to Console: raw integrity data response (filenames, sizes, hashes, ACLs, registry data)],
    [XP2], [Console to User: comparison/analysis results (what changed since the last scan)],
  ),
  caption: [Exit Points],
)

== Assets

#figure(
  table(
    columns: (auto, auto, 1fr),
    table.header([*ID*], [*Name*], [*Why it matters*]),
    [A1], [Baseline data], [Trusted snapshot from the previous scan. If altered, real tampering goes undetected],
    [A2], [Config/credentials], [Users, passwords, preferences stored locally on the Console],
    [A3], [Data in transit], [Host-Console traffic, unencrypted, readable/modifiable in transit],
    [A4], [The tool itself], [If tampered, it can no longer be trusted to detect tampering],
  ),
  caption: [Assets],
)

== Trust Levels

#figure(
  table(
    columns: (auto, auto, 1fr),
    table.header([*ID*], [*Name*], [*Description*]),
    [T1], [Console admin], [Logged-in user operating the Console],
    [T2], [Network attacker], [Anyone reachable over the network to Host or Console; no authentication exists on this channel],
    [T3], [Physical attacker], [Has physical access to a machine already assumed compromised, including its firmware/BIOS],
  ),
  caption: [Trust Levels],
)

== Data Flow Diagrams

AppShield operates in two distinct scenarios, modeled here as two separate
Level 1 DFDs: normal network deployment, and bootable media mode on a
compromised machine.

=== Network Mode

#figure(
  image("dfd/appshield-dfd-network.png", width: 90%),
  caption: [Level 1 DFD - Console and Host communicating over the network],
)

=== Bootable Media Mode

#figure(
  image("dfd/appshield-dfd-bootable.png", width: 90%),
  caption: [Level 1 DFD - standalone Host and Console running from bootable CD/USB on a compromised machine],
)
