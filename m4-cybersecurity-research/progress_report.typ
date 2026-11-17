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
    A Security Analysis of Apache NuttX RTOS:\
    Vulnerability Reproduction and a Zephyr Comparison (Group 10)
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
    This project conducts a security analysis of the Apache NuttX RTOS, the
    kernel behind Xiaomi's openvela consumer platform. We catalogue and
    classify NuttX's publicly disclosed CVEs, reproduce two of them at the
    source level with sanitizer-backed host harnesses, situate the design
    decisions that produce its bug profile against the Linux tradition, and
    benchmark NuttX's assurance practices against the Zephyr project's. This
    report covers the literature and CVE review completed to date, the
    reproduction methodology already validated for two vulnerabilities, the
    current project status, and the tasks remaining before the final report
    and presentation.
  ]
]

#pagebreak()

= Project Description

The goal of this project is to assess the real security posture of an RTOS
that has moved from hobbyist devices into consumer fleets. NuttX follows the
Linux programming model (POSIX APIs, everything-is-a-file, kernel and libc in
one image) without Linux's isolation machinery: in the default build the
entire firmware shares one address space, and the project's own guidance puts
input validation on the application developer. The research questions are:

1. What is NuttX's true vulnerability surface, as far as public disclosure
   and source reading can tell, given that no continuous fuzzing watches the
   tree?
2. Can representative disclosed bugs be reproduced and their fixes verified
   with reasonable effort, and what does the fix quality say about the
   process behind them?
3. What does the same problem space look like managed differently, using
   Zephyr's security team, embargoed advisories and in-tree fuzzing tooling as the
   counterfactual?

= Approach

1. *CVE and disclosure review.* Enumerate every published NuttX CVE via NVD
   and the project security page; classify by subsystem, bug class and attack
   interface; read the fix PRs.
2. *Source-level replication.* For selected CVEs, compile the verbatim
   upstream functions in host harnesses under AddressSanitizer/UBSan, with
   only the NuttX-specific glue stubbed; the patched release serves as the
   control build.
3. *Design-philosophy analysis.* Trace each reproduced failure mode back to
   the Linux-lineage design choices (flat memory, kernel-as-library, no MMU
   requirement) and to the project's stated security doctrine.
4. *Practice comparison.* Systematic comparison with Zephyr: disclosure
   handling, fuzzing and CI, hardening defaults, academic attention.

= Progress Achieved

*Completed (weeks 1-8):*

1. Full CVE catalogue and taxonomy: eleven disclosed CVEs verified against
   NVD (2018-2025); attack-surface timeline and bug-class distribution
   written up.
2. First reproduction complete: CVE-2025-35003 (Bluetooth HCI/UART stack
   buffer overflow). Harness compiles the verbatim `btuart_rxwork()` from
   the 12.7.0 tag and the 12.9.0 fixed tag as control; a crafted H4 ACL
   frame with declared length 4096 produces an ASan `stack-buffer-overflow`
   write of 4096 bytes past the 79-byte `BLUETOOTH_MAX_FRAMELEN` buffer on
   the vulnerable build, and is rejected with one log line on the fixed
   build. The EVT path was reproduced the same way.
3. Second reproduction complete: CVE-2025-48768 (inode root removal). The
   verbatim 12.9.0 `inode_unlink()` under ASan faults with a write through
   the NULL parent pointer at `offsetof(i_child)` when removing `/`,
   matching the advisory's DoS classification.
4. Third candidate analysed but honestly reported as not reproduced:
   CVE-2025-48769 (`fs_rename` use-after-free); the aliasing that makes it
   dangerous runs through the FAT driver's readdir buffers, and we will not
   publish a harness whose fidelity we cannot defend.
5. Linux-vs-NuttX design-philosophy chapter drafted; Zephyr comparison
   drafted (security team, disclosure, fuzzing posture, NCC Group 2020 assessment,
   Rtkaller/RTCON academic fuzzing literature).

*Remaining (weeks 9-11):*

1. QEMU/xtensa end-to-end demonstration on the ESP32-C3 `ble` board config,
   feeding the same H4 frame over an emulated UART (stretch; the host
   harness already proves the code path).
2. Fleet-impact section: openvela device class, PX4 lineage.
3. Final report editing, presentation slides, rehearsal of questions.

= Schedule (Table 1)

#figure(
  table(
    columns: (auto, 1fr, auto, auto, auto),
    align: (left, left, center, center, left),
    table.header([*Task*], [*Description*], [*Start*], [*Finish*], [*Responsible*]),
    [1], [CVE/disclosure review and taxonomy], [28/10/2026], [5/11/2026], [João Pinto],
    [2], [Design-philosophy analysis (Linux lineage, flat memory)], [3/11/2026], [12/11/2026], [Sérgio Cardoso],
    [3], [Replication harnesses (CVE-2025-35003, CVE-2025-48768)], [7/11/2026], [17/11/2026], [Vitor Santos],
    [4], [Zephyr practice comparison + final report and presentation], [14/11/2026], [25/11/2026], [Shijo George],
  ),
  caption: [Major tasks, owners and dates.],
)

= Open Issues

1. *No QEMU target attaches the Bluetooth UART driver.* The stock BT-enabled
   defconfigs are xtensa (ESP32 family); a full-system demo needs the xtensa
   toolchain and a synthetic HCI slave, which we timebox as a stretch goal.
2. *Disclosure sparsity limits quantitative claims.* With eleven CVEs, trend
   statistics are weak; the report leans on method (fix-PR analysis,
   reproduction) instead.
3. *Third CVE reproduction fidelity.* If time allows, CVE-2025-48769 can
   only be credibly reproduced inside a real FAT mount; this is a candidate
   for the QEMU effort rather than the host harness.
