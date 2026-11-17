## What the attacks actually do, and what they do not

The papers (and our Chapter 3 models) bound the damage precisely, and
the boundaries matter to a critical-systems reader.

**KRACK breaks confidentiality, then integrity, and never the crypto
primitives.** The core consequence is the keystream collision our model
replays: an eavesdropper recovering plaintext from one known-plaintext
frame pair. Beyond that, the per-OS consequences the KRACK paper
enumerates: on Linux, replayed Message 3 resets the TX counter to
zero — the family CVEs 13081-13087 ride on which implementation
property each OS exposes (SAMSUNG CVE-2017-13081 accepts reinstallations
on its own; APPLE CVE-2017-13084 installs a random key; OPENBSD
CVE-2017-13086 accepts a zeroed key). None of this requires the attacker
to decrypt anything by force: they sit one hop inside the radio range.

**SAE's reflection is a denial of service, not a password leak; its
timing side channels are a password oracle, not a break.** Our modelled
livelock (Chapter 3) never recovers a secret: the reflection attacker
mounts an unauthenticated AP that traps any client into endless
retries. The cache-timing family (CVE-2019-9495/9496) is what turns
"retry until the password is confirmed" into *offline* password
verification: the attacker who measures hunt-loop work can test
candidates remotely at near-local speed. That is the integrity of WPA3's
password model being degraded to "WPA2-quality" — the paper's own
summary — not an extraction of the key.

**The severe cases live elsewhere in the cipher family.** Against
AES-CCMP, KRACK's harvest is keystream reuse — decryption of new frames
given known plaintext, and replay of broadcast/multicast frames via the
group-key variant (CVE-2017-13080) — *not* recovery of the pairwise key
or the passphrase [@krack2018]. The paper's dramatic results belong to different
targets: TKIP's Michael-MICAR interaction yields plaintext recovery and
frame forging, and on certain Linux and Android builds (`wpa_supplicant`
2.4 with the GTK bug, 2.6 with the TPTK construction) the installation
logic accepts a zeroed key — the all-zero-KCK variant gives a
man-in-the-middle trivially replaying, decrypting and forging
traffic. Both edges are *implementation* properties again: our KRACK
model reproduces the CCMP-counter reset exactly; the all-zero path is
the 2.6 TPTK trap that upstream's own capture
(`krackattacks-scripts` ships `example-tptk-attack.pcapng`) documents it [@krack]
[@krack-site].

**The practical limitations of both attacks are also implementation
limitations.** They need the attacker *in radio range* of a target
network, and they need the target to *authenticate* (KRACK needs the
4-way handshake; the reflection DoS needs an SAE exchange). Neither
works on a device that is only an AP with PMF forced, or a client
connecting to a network whose AP installs keys idempotently. In our
terms: the attacks exploit *choice*, not chance — which is exactly why
they transfer to the embedded world, where those choices get made in
vendor ports nobody re-audits.

## The NuttX supply-chain consequence

The source-tree evidence is in Chapter 3, "Where this code lives — and
why NuttX's does not". Its meaning for a fleet, stated once: a NuttX
product's WPA layer is either unauditable (vendor blobs) or
unattributable (undocumented ESP-IDF sync point), while the kernel's CVE
layer has commits, versions and credit. The audit consequence of that
asymmetry is the subject of the rest of this chapter.

## Security implications for the kernel cases

Same lens, NuttX proper: CVE-2025-35003's overflow direction (upward
through a work-queue frame) makes control-flow corruption plausible on
Cortex-M-class parts, matching the advisory's "arbitrary code execution"
as a *possibility*, not a claim; its trigger surface (UART from the
BT controller module) is exactly the trusted-hardware-component mistake
KRACK makes with the Install bit. CVE-2025-48768 is bounded: a clean
DoS where an MMU/MPU traps the NULL write, worse on flat builds; the
advisory's CVSS 6.5 is right for the first and unknowable for the
second, which is the flat-memory tax again.
