// DECYS research project progress report, group #10 (Week 8 milestone).
// Layout follows the course progress-report template. Build: `make progress`.

#set text(font: "New Computer Modern", size: 11pt, lang: "en")
#set page(margin: 2.2cm, header: none, numbering: "1")
#set par(justify: true)
#show heading: set text(fill: rgb("#333"))
#set heading(numbering: "1.")

#let accent = rgb("#1a4f8b")

#align(center)[
 #text(size: 9pt, fill: gray)[
 João Pinto - 1221294 \
 Sérgio Cardoso - 1210891 \
 Vitor Santos - 1250446 \
 Shijo George - 1240374
 ]
]

#v(1.2cm)
#align(center)[
 #text(size: 16pt, weight: "bold", fill: accent)[
 Key Reinstallation Attacks against WPA2:\
 Handshake State-Machine Analysis, Reproduction, and Embedded\
 Supply-Chain Audit (Group 10)
 ]
]
#v(0.6cm)
#align(center)[
 #text(size: 14pt)[Project Progress Report]
]
#v(0.8cm)

#align(center)[
 #block(width: 85%, inset: 10pt, stroke: 0.5pt + accent)[
 #set text(size: 9.5pt)
 This project conducts a security analysis of WPA2 key reinstallation
 (KRACK) and its WPA3/SAE successor, per the team plan of 17 Nov 2026.
 We explain the 802.11i handshake machinery, reproduce both attacks at
 their decision points with models built from the official upstream
 sources (vulnerable vs patched, no real network involved), measure the
 SAE hunt loop's timing leak on real P-256 arithmetic, and audit where
 this code ships inside embedded products. This
 report covers the work completed to date, the
 reproduction methodology already validated,
 current project status, and the tasks remaining before the final report
 and presentation.
 ]
]

#pagebreak()

= Project Description

The goal of this project is to answer the research question, how can a
vulnerability in the WPA2 four-way handshake undermine encryption
without breaking the encryption algorithm, with executed evidence:
faithful vulnerable/patched models of the supplicant's receiver, the
same treatment for SAE's reflection flaw, a measured timing leak on the
real hunt loop, and an audit of where this code ships in embedded
products (the ESP-IDF supplicant port and vendor-blob Wi-Fi stacks). No
real network is attacked at any point.

= Approach

1. *Protocol and theory (M1).* 802.11i, WPA2, CCMP, PTK/GTK derivation,
 the four-way and group-key handshakes; the algorithm-versus-
 implementation argument; the Vanhoef & Piessens summary in our own
 words.
2. *Lab and reproduction (M2).* Receiver-side reproduction executed on
 this machine: faithful 2.3-vs-current models of wpa.c and sae.c from
 the official w1.fi releases (sha256 pinned), and a seeded statistical
 measurement of the SAE hunt loop on real P-256 arithmetic. The
 attack-side hwsim lab (krackattacks-scripts, wifi-framework,
 Wireshark PSK decryption) is documented step-by-step as the x86/Kali
 follow-up; this machine's negative result (no hwsim-capable kernel on
 arm64) is reported.
3. *Attack analysis (M3).* Root cause: why key installation was not
 idempotent; the formal-analysis view (Cremers et al.); the honest
 boundary of attacker gain (keystream reuse vs the TKIP and zero-key
 cases).
4. *Integration and delivery (M4).* Mitigations and evolution
 (idempotent installation, uniform-cost design, WPA3/SAE honest
 scope), report assembly, references, slide deck.

= Progress Achieved

*Completed:*

1. KRACK model executes the full consequence chain, PN reset on a
 replayed Message 3, keystream reuse, known-plaintext recovery of a
 second frame, with the patched control refusing the reinstall
 (`make krack`).
2. SAE reflection model: 5/5 livelocked rounds on the vulnerable
 receiver, guard-drop on the current one; the harness curve verified
 by point count (`make sae`, `tools/curve_check.py`).
3. SAE timing leak measured on the verbatim 2.3 hunt loop with a real
 P-256 oracle, seeded and reproducible: P(work beyond pad) = 0.066.
4. Supply-chain audit with checked-in evidence (ESP-IDF v4.4/v5.2 file
 lists, guard greps, READMEs, 2021 backport commits; refetchable via
 `make sources-esp`).
5. Report (30 pp.), progress report, slides (13), references per the
 plan; two rounds of adversarial (goldfish) review applied; all
 executable claims verified from a clean clone.

*Remaining:* run the attack-side lab on x86/Kali and produce the
annotated Wireshark figures (M2, per plan); rehearse slides; optional
Tamarin stretch.

= Open Issues

1. *No hwsim-capable kernel on this machine (arm64).* The attack-side
 lab (krackattacks-scripts + mac80211_hwsim + Wireshark PSK
 decryption) is fully documented and assigned (M2); it needs an
 x86/Kali host or a VM with an x86 kernel. Receiver-side models stand
 in the meantime.
2. *Vendor-blob coverage limit.* The supply-chain audit proves the
 absence of a provenance ledger in the SDK ports we could fetch; it
 cannot certify a shipping binary we cannot build or flash.
3. *Optional Tamarin stretch.* The plan's formal-analysis component
 (Cremers et al.'s public model) is scoped as a stretch, not a
 deliverable.
