## What the attacks actually do, and what they do not

The papers (and our Chapter 3 models) bound the damage precisely, and
the boundaries matter to a critical-systems reader.

**KRACK breaks confidentiality, then integrity, and never the crypto
primitives.** The core consequence is the keystream collision our model
replays: an eavesdropper recovering plaintext from one known-plaintext
frame pair. Beyond that, the per-OS consequences the KRACK paper
enumerates: on Linux, replayed Message 3 resets the TX counter to
zero, the family CVEs 13081-13087 ride on which implementation
property each OS exposes (the IGTK variant CVE-2017-13081 enables
spoofing of protected management frames whenever 802.11w is supported
[@dv-nvd-13081]; the PeerKey STK variant CVE-2017-13084 is the one
identifier whose status differs between sources, hostap marking it
"not applicable" while the CVE record documents the property
[@dv-nvd-13084]; the TDLS variant CVE-2017-13086 is the TDLS PeerKey
reinstallation [@dv-nvd-13086]). None of this requires the attacker
to decrypt anything by force: they sit one hop inside the radio range.

**SAE's reflection is a denial of service, not a password leak; its
timing side channels are a password oracle, not a break.** Our modelled
livelock (Chapter 3) never recovers a secret: the reflection attacker
mounts an unauthenticated AP that traps any client into endless
retries. The cache-timing family (CVE-2019-9495, the EAP-PWD cache
side channel; the SAE side of the family is CVE-2019-9494) is what
turns "retry until the password is confirmed" into *offline* password
verification: the attacker who measures hunt-loop work can test
candidates remotely at near-local speed [@dv-nvd-9495] [@dv-nvd-9494].
That is the integrity of WPA3's password model being degraded to "WPA2-quality", the paper's own
summary, not an extraction of the key.

**The severe cases live elsewhere in the cipher family.** Against
AES-CCMP, KRACK's harvest is keystream reuse, decryption of new frames
given known plaintext, and replay of broadcast/multicast frames via the
group-key variant (CVE-2017-13080 [@dv-nvd-13080], "replay frames from
access points to clients" per the CVE record), *not* recovery of the pairwise key
or the passphrase [@krack]. The original paper's more severe results belong to different
targets: TKIP's Michael-MICAR interaction yields plaintext recovery and
frame forging, and on certain Linux and Android builds (`wpa_supplicant`
2.4 with the GTK bug, 2.6 with the TPTK construction) the installation
logic accepts a zeroed key, the all-zero-KCK variant gives a
man-in-the-middle trivially replaying, decrypting and forging
traffic. Both edges are *implementation* properties again: our KRACK
model reproduces the CCMP-counter reset; the all-zero path is
the 2.6 TPTK trap that upstream's own advisory documents ("a different
message sequence involving 4-way handshake can result in configuration
of an all-zero TK in v2.6", fixed by the commit "Prevent installation
of an all-zero TK") [@dv-w1fi-2017-1], and the reference capture
(`krackattacks-scripts` ships `example-tptk-attack.pcapng`) is in the
tooling repository [@krack-scripts] [@krack]
[@krack-site].

**The practical limitations of both attacks are also implementation
limitations.** They need the attacker *in radio range* of a target
network, and they need the target to *authenticate* (KRACK needs the
4-way handshake; the reflection DoS needs an SAE exchange). Neither
works on a device that is only an AP with PMF forced, or a client
connecting to a network whose AP installs keys idempotently. In our
terms: the attacks exploit *choice*, not chance, which is why
they transfer to the embedded world, where those choices get made in
vendor ports nobody re-audits.

## The embedded supply-chain consequence

The evidence is in Chapter 3 ("Where this code lives in embedded
products"); its meaning for a fleet, stated once: the WPA layer of an
embedded product is either *not in any source tree you can audit*
(offloaded modules run vendor blobs) or *not attributable to a known
upstream revision* (the ESP-IDF port has no stated sync point, and its
KRACK-era fixes arrive as backports rather than versions). The
same asymmetry is visible in the vendors' own patch ledgers (Chapter
6): Debian shipped the fix as a patched 2.4 package, not an upstream
version bump [@dv-debian-dsa3999], and Android shipped it as a patch
level inside the November 2017 releases [@dv-android-2017-11]. The rest
of this chapter reads against that fact: the same protocol, proven sound in
the abstract, becomes unverifiable at the point of shipping.

## The misconception boundary

The popular summary "KRACK broke Wi-Fi encryption" is wrong in both
halves, and the boundary matters for any defender reading the
vulnerability notes. KRACK broke *freshness*: given a known or guessable
plaintext it reveals a frame, and via the group-key variant it replays
broadcast traffic; it does not decrypt captured history, does not recover
the PTK, and does not reveal the passphrase (the last is a WPA3/SAE
side-channel property, not a KRACK one). Conversely, the severe cases in
the paper, TKIP frame forging, the Linux/Android zero-key bug, are not
hypotheticals waiting for an exploit; they were the measured results of
the original research and are cited here as the boundary of our own
claims, which stop at CCMP keystream reuse, which our model
shows.
