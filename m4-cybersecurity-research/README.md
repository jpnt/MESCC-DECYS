# KRACK WPA2 research report (DECYS, group 10)

Security analysis of WPA2 key reinstallation (KRACK) and its WPA3/SAE
successor, per the team plan of 17 Nov 2026: the protocol machinery, the
state-machine flaw reproduced at the receiver's decision point (official
`wpa_supplicant` 2.3 vs current, sha256 pinned), the SAE reflection DoS
on a point-counted real curve, a seeded measurement of the SAE hunt
loop's timing leak, an honest account of attacker gain, the reference
hwsim lab (documented; x86 follow-up), mitigations, and an embedded
supply-chain audit (ESP-IDF supplicant port provenance, vendor-blob Wi-Fi
stacks). No real network is attacked.

```
make krack # KRACK receiver model: vulnerable + patched control
make sae # SAE reflection model + the leak measurement
make snippets # both of the above, from checked-in upstream slices
make report # report.pdf (~55 pp.)
make slides # slides.pdf (14 slides)
make progress # progress_report.pdf
make sources-esp # refetch the lab/ ESP-IDF evidence (network)
```

```
report/content/ one markdown file per section (plan's 7 chapters)
report/snippets/ models, verbatim upstream slices, frozen traces
report/main.typ structure (typst + cmarker, as in m3)
tools/ curve_check.py, sae_pwe_stats.py, esp_evidence.py
lab/ ESP-IDF + w1.fi release evidence for Chapter 3
goldfish_review_report.md review ledgers (rounds 1-2)
KRACK WPA2 Project Description and Work Plan.pdf team plan (in repo root)
```
