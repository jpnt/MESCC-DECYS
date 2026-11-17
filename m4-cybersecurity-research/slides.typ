// KRACK WPA2 research presentation (DECYS, group 10).
// Build: make slides -> slides.pdf. 16:9, one point per slide.

#set text(font: "New Computer Modern", size: 20pt, lang: "en")
#set page(width: 32cm, height: 18cm, margin: (x: 2cm, y: 1.6cm), numbering: "1")
#set par(justify: false, leading: 0.85em)
#set heading(numbering: none)

#let accent = rgb("#1a4f8b")
#let ink = rgb("#222")

#show heading: set text(fill: ink)
#show heading.where(level: 1): set text(size: 30pt, weight: "bold")
#set list(marker: circle(radius: 2.2pt, fill: accent))

#let slide(title: none, body) = {
 if title != none { align(left)[#text(size: 26pt, fill: accent)[#title]] }
 body
 pagebreak()
}

// ---- 1 cover ------------------------------------------------------------
{
 align(center + horizon)[
 #text(size: 13pt, fill: gray)[Reliability and Cybersecurity (DECYS) - Critical Computing Systems]
 #v(1.2cm)
 #text(size: 34pt, weight: "bold", fill: accent)[Key Reinstallation Attacks against WPA2]
 #v(0.4cm)
 #text(size: 20pt)[How a handshake state machine undermined encryption\ without breaking the cipher]
 #v(1.4cm)
 #text(size: 14pt)[
 João Pinto - Sérgio Cardoso - Vitor Santos - Shijo George \
 Group 10 - 2026/27
 ]
 ]
 pagebreak()
}

// ---- 2 research question -------------------------------------------------
#slide[
 #text(size: 24pt, weight: "bold")[Research question]
 #v(0.8em)
 #block(width: 100%, inset: 14pt, stroke: 1pt + accent, fill: rgb("#f2f6fb"))[
 How can a vulnerability in the WPA2 four-way handshake undermine
 encryption *without actually breaking the encryption algorithm*?
 ]
 #v(0.8em)
 - AES-CCMP was never broken. The flaw is in *state*: key installation.
 - Our angle: prove it in code (vulnerable vs patched), and answer the
   embedded question: *where does this code ship?*
]

// ---- 3 background: the handshake --------------------------------------
#slide[
  #text(size: 24pt, weight: "bold")[WPA2 in 30 seconds]
  #grid(columns: (1fr, 1fr), gutter: 1em,
    image("report/figures/fourway.png", width: 100%),
    block(inset: 0.6em)[
      - CCMP = AES in *counter mode*: each (key, packet number) pair is
        used once; installing a key resets the counter.
      - Message 3 carries the *Install bit*, and 802.11 retransmits it
        routinely.
      - A receiver that re-installs on a retransmission reuses the
        keystream. The cipher is innocent.
    ])
]

// ---- 4 what we did ------------------------------------------------------
#slide[
 #text(size: 24pt, weight: "bold")[What we did]
 #v(0.6em)
 - Reproduced KRACK's decision point in a faithful model of the
 *official* wpa_supplicant 2.3 receiver (w1.fi release, sha256
 pinned) vs the current patched guard.
 - Reproduced SAE reflection DoS (WPA3/Dragonblood) on a real,
 point-counted curve; guarded build vs unguarded.
 - *Measured* the SAE hunt loop's timing leak (seeded, N=1500,
 P-256 quadratic-residue oracle).
 - Audited where this code ships in embedded products: the ESP-IDF
 supplicant port has no stated base revision; Wi-Fi crypto on RTOS
 products often runs inside closed vendor blobs.
 - Documented the plan's hwsim attack-side lab for the x86 follow-up.
]

// ---- 5 KRACK demo -------------------------------------------------------
#slide[
 #text(size: 24pt, weight: "bold")[KRACK, executed: replay resets the counter]
 #v(0.5em)
 #set text(size: 13pt)
 ```
 $./krack_vulnerable vulnerable
 [driver] set_key(PTK): TX packet number reset, key slot armed
 [wifi] TX frame1 (known ARP + zero padding) at PN=0
 == AP retransmits Msg3 (Install|Secure): the replay
 [driver] set_key(PTK): TX packet number reset, key slot armed
 [wifi] TX frame2 (secret) at PN=0
 [ATTACK] key reinstalled: PN reused, recovered: SECRET-SESSION-...
 ```
 #v(0.4em)
 #set text(size: 17pt)
 - Same input, patched guard:
 #text(size: 13pt)[`WPA: Do not re-install same PTK` → PN=3, no reuse.]
 - Known plaintext (ARP) + reused keystream = secret frame recovered.
]

// ---- 6 SAE demo ---------------------------------------------------------
#slide[
  #text(size: 24pt, weight: "bold")[WPA3/SAE: reflection + a measured leak]
  #grid(columns: (1fr, 1.05fr), gutter: 1em,
    block[
      #set text(size: 12pt)
      ```
      $ ./sae_vulnerable   # no reflection check (2.3)
      [ATTACK] reflection DoS: 5/5 rounds livelocked
      $ ./sae_fixed        # current guard
      [guard] peer commit == own commit: drop

      $ python3 tools/sae_pwe_stats.py   # seeded
      real-stops-at-4: 0.934  at-5: 0.031
      P(work beyond k=4 pad) = 0.066
      ```
      #set text(size: 15pt)
      - Echo a Commit back: the station authenticates *with itself*.
      - The password-to-point hunt takes *variable* time: the measured
        tail is the leak's size (pipeline figure, Chapter 3).
    ],
    image("report/figures/reflection.png", width: 100%, height: 12cm))
]

// ---- 7 where the code runs ----------------------------------------------
#slide[
  #text(size: 24pt, weight: "bold")[Where does this code run in embedded products?]
  #grid(columns: (1.1fr, 1fr), gutter: 1em,
    block[
      #set text(size: 16pt)
      - RTOS-class stacks ship *no supplicant* of their own: the 4-way
        handshake runs in a Wi-Fi module's *vendor blob* (companion
        chips, closed Wi-Fi libraries).
      - Or in *SDK-ported* wpa_supplicant: READMEs state *no base
        revision*, version strings stripped, KRACK-era fixes arrive as
        silent *backports* (2021 commits, grepped and checked in).
      - *Finding:* the layer holding your keys has no auditable
        provenance. Auditing a device's WPA posture means auditing a
        blob, or asking a vendor for a sync point that does not exist.
    ],
    image("report/figures/supplychain.png", width: 100%, height: 8.5cm))
]

// ---- 8 implications ------------------------------------------------------
#slide[
 #text(size: 24pt, weight: "bold")[What the attacker actually gains]
 #v(0.6em)
 - CCMP: keystream reuse → decrypt with known plaintext, replay
 broadcast. *Not* the PTK, not the passphrase.
 - TKIP: plaintext recovery + frame forging (MICAR). Certain Linux/
 Android builds: *all-zero key* installation → full MitM.
 - SAE reflection: permanent cheap DoS of authentication.
 - SAE timing: offline-grade password verification.
 - In every case: AES and Dragonfly stayed sound. The *implementation
 believed an input* it should have checked.
]

// ---- 9 mitigations -------------------------------------------------------
#slide[
 #text(size: 24pt, weight: "bold")[Mitigations and evolution]
 #v(0.6em)
 - The fix is boring: a *three-line idempotence guard*
 ("do not re-install an in-use key"), and it must be
 *uniform-cost* too (Dragonblood showed patching install isn't
 enough if work leaks the password).
 - WPA3/SAE removes PMK replay and adds PMF; its own
 reference-flow flaws (9494–99) became hash-to-element.
 - Process, not patch: hostap's fuzz-build targets (libFuzzer/AFL on the
 EAPOL parsers) are the defence that reads continuously.
 - For embedded fleets: *demand provenance* for the crypto layer
 (blob ≠ auditable), and ask the vendor "which upstream commit is
 your supplicant?", the only question this analysis makes answerable.
]

// ---- 10 evaluation --------------------------------------------------------
#slide[
 #text(size: 24pt, weight: "bold")[Critical evaluation: one category error]
 #v(0.6em)
 #set text(size: 17pt)
 | Input trusted | System | Consequence |
 | --- | --- | --- |
 | Install bit (again) | supplicant 4-way | PN reset, keystream reuse |
 | peer Commit == mine | SAE (2.6, no check) | auth with self: DoS |
 | hunt-loop work | SAE timing | password oracle |
 | Install bit (again) | RTOS SDK ports | uncheckable patch state |
 | blob-only Wi-Fi stack | RTOS products | no provenance at all |
 #v(0.6em)
 - Five fixes, all a few lines; none of them a broken cipher.
 - Formally confirmed: WPA2's crypto *proves* sound; the handoff breaks
 (Cremers et al., USENIX Sec'20). Design must assume the *message
 arrives twice, from an impostor, faster than expected*, and cost
 must not depend on the secret.
]

// ---- 11 limitations -------------------------------------------------------
#slide[
 #text(size: 24pt, weight: "bold")[What we did, and did not, do]
 #v(0.6em)
 - *Did:* receiver-side reproduction with verbatim/faithful models
 (official upstream sources, pinned hashes, seeded stats,
 point-counted curve, sanitizer traces).
 - *Did not:* over-the-air replay, this machine has no
 `mac80211_hwsim`-capable kernel (arm64); the attack-side lab
 (krackattacks-scripts + hwsim + Wireshark decryption) is
 documented step-by-step and is our x86 follow-up.
 - *Why it still holds:* the vulnerability is a branch choice, not a
 radio effect, and both branches are shown, with the patched
 control, from the same inputs.
]

// ---- 12 conclusion ---------------------------------------------------------
#slide[
 #text(size: 24pt, weight: "bold")[Conclusion]
  #v(0.8em)
  - You can break a secure cipher with a few lines of missing code:
    *security is state, not math.*
  - "No CVE mapping" is a measurement gap: embedded Wi-Fi stacks ship
    as blobs or backports, so patch state is unprovable from outside.
  - For critical systems: demand *provenance* for the code that installs
    your keys, verify *idempotence* of state transitions, and put a
    fuzzer where the spec leaves the choice to the implementer.
  #v(0.6em)
  #text(size: 13pt, fill: gray)[Report: 30 pp., 12 refs. Demos: `make krack`,
  `make sae`: deterministic, offline, no radio harmed.]
] 