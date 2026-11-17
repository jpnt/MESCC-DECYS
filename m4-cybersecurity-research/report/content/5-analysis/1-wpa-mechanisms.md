## WPA2 KRACK: the mechanism, in code

KRACK (CVE-2017-13077 and the family 13078–13087 [@nvd-krack]) is not a
Wi-Fi bug and not a cryptography bug: it is a state-machine bug in the
client's 4-way handshake receiver — the supplicant, in 802.11i terms —
and the whole attack reduces to one missing `if` [@krack] [@krack-site].

We fetched the actual `wpa_supplicant` receiver sources (upstream hostap
via the Debian source archive, checked in under
`snippets/upstream/` [@wpasrc]: `wpa.c` 2.3, the KRACK-era receiver, and
`wpa.c` current, the fixed receiver) and rebuilt the receiver's decision
structure in a small model, `snippets/krack_harness.c`. The vulnerable
build mirrors 2.3 (`Install` bit on Message 3 → `wpa_sm_set_key()`,
unconditionally), and the fixed build carries the guard that the fix
added, in Jouni Malinen's own comment string: *"Do not re-install same
PTK to the driver"*. The CCMP cipher is modelled as the keystream cipher
it is (CTR mode over a key and the transmit packet number, TX PN), and
the driver contract — installing a key resets its TX PN — is reproduced
because that reset is exactly what made reinstallation fatal.

The run tells the whole story. Handshake installs the PTK (PN reset, as
always). A frame goes out at PN=0. The AP retransmits Message 3 — a
completely ordinary 802.11 event, data acknowledgements are lossy, and
the supplicant *must* answer Message 4 again in both versions. The
vulnerable receiver also *reinstalls the key* — resetting the TX
counter to zero — and the next frame goes out at PN=0 again: same key,
same PN, two plaintexts. We let the attacker sniff both ciphertexts and
possess the first plaintext (ARP is the paper's choice; every LAN has
them): the keystream from the known pair decrypts the second frame.
Full run, verbatim:

```
$ ./krack_vulnerable vulnerable
[supplicant] installing PTK to the driver
[driver] set_key(PTK): TX packet number reset, key slot armed
[supplicant] port authorized, protection enabled (RX)
[wifi] TX frame1 (known ARP + zero padding) at PN=0
== AP retransmits Msg3 (Install|Secure): the replay
[supplicant] installing PTK to the driver
[driver] set_key(PTK): TX packet number reset, key slot armed
[wifi] TX frame2 (secret) at PN=0
[ATTACK] key reinstalled: PN reused, recovered: SECRET-SESSION-TOKEN-ABCD1234567END
```

The fixed build sees the identical input and refuses the reinstall (PN
reaches 3, monotonic): no reuse, nothing to recover. That is the entire
vulnerability — a few lines of control flow — and it is the *same shape*
as our NuttX cases: an implementation trusting an input field (`Install`
bit) that a correct-by-construction peer would never set twice, with no
validation layer behind it.

## WPA3 SAE/Dragonblood: the mechanism, in code

SAE (the WPA3 handshake, "Dragonfly") failed in two ways in 2019
(CVE-2019-9494 through 9499, "Dragonblood") [@nvd-dragonblood]
[@dragonblood]: we model CVE-2019-9494 (reflection) and measure
CVE-2019-9495/9496 (timing). Part one is a missing comparison. The
commit exchange sends (blind = v+m, commit = v·G − PWE; m = our secret
scalar, v = our mask, G = the curve's base point); the 2.3 receiver
stored whatever arrived and continued, with no check that the peer's
values differ from its own. A malicious AP simply *echoes* the
station's Commit back: the station then runs the rest of the handshake
authenticating against a copy of itself. Both sides' confirm tags
evaluate the SAME expression (the reflector has only our public
material), so they agree — but by pure echo: an "authentication" of the
station with itself, no independent AP secret anywhere in the derived
key. Our harness asserts exactly this (`key_tag()` executed on both
views), and the DoS is the station stuck retrying a handshake that can
never yield usable data.
The station retries: each retry costs the supplicant commit work and a
session slot on the target — a permanent, cheap DoS of the handshake
state machine [@dragonblood]. Current `sae.c` contains exactly the
missing comparison (*"would be evidence of a reflection attack"*).
`snippets/sae_harness.c` implements the true group law on a small curve
(field prime p=1009, group order 987 = 3×7×47, exact integer
arithmetic; the tiny group is a vehicle for the state machine, not a
real-curve cost estimate) and drives five independent Commit exchanges
(a fixed count, not a sample): the 2.3-shaped receiver is stuck in all
five, the guarded receiver drops the echo in round one.

Part two is a side channel, and we measured it against a
control-flow-faithful replica of the real hunt loop rather than a
simplified model of it: `sae_derive_pwe_ecc` (extracted verbatim to
`snippets/sae_derive_pwe_pre_dragonblood.inc`) hunts for a
password-derived curve point, padding to k=4 iterations to hide how
long the hunt took. The replica (`tools/sae_pwe_stats.py`) reproduces
the loop control line for line, and evaluates each candidate with the
real quadratic-residue test (Legendre symbol, Euler criterion) on NIST
P-256, over 1500 seeded 8-byte pseudo-passwords — each standing for one
candidate — with a fixed histogram range so the block below is
reproducible:

```
$ python3 ../tools/sae_pwe_stats.py
real-stops-at-4: 0.934
real-stops-at-5: 0.031
real-stops-at-6: 0.019
real-stops-at-7: 0.009
P(work beyond the k=4 pad) = 0.066
```

About 6–7% of password candidates do *extra* cryptographic work the
rest never do (±0.6pp at N=1500) — runtime is password-correlated,
which is the signal the Dragonblood cache/retry attacks extract to
verify a guessed password offline at near-local speed (their
"dictionary attack in a handshake" result: one candidate verified per
handshake interaction, the same cost structure as an offline wordlist
run) [@dragonblood]. The class-level statement
in the paper is "loop count leaks"; our number is what that leak
measures on the upstream loop itself.

## Where this code lives — and why NuttX's does not

This is the part that decides whether this section is about NuttX at
all. Verified in the trees (the wpa_supplicant sources are checked in
under `snippets/upstream/`; the ESP-IDF claims were grepped from the
fetched tags via `make sources-esp`, and the greps themselves live in
this and the companion files):

- **NuttX has no supplicant.** `apps/wireless` contains `bluetooth`,
  `ieee802154`, `iwpan`, `wapi` and `gs2200m` — no hostap. The gs2200m
  example hands the WPA2 *passphrase* to the Wi-Fi
  module's firmware (`gs2200m_main.c`: a join command with "8 to 63
  ascii passphrase for WPA2-PSK"): the handshake runs inside a vendor
  blob on a companion chip. `wapi` configures via wireless ioctls
  (`IW_AUTH_WPA_VERSION_*`), again expecting the driver to hold the
  state machine. The kernel tree carries no 802.11 crypto either; the
  ESP32 paths route into Espressif's closed `libnet80211`/`libpp`.
- **ESP-IDF carries the supplicant, and its provenance is
  undocumented.** [@esp-wpasupplicant] `components/wpa_supplicant/README.md` says only
  "ported for ESP family of platforms" — no base commit, and the version
  string is stripped: neither the README nor the build records it.
  Dating has to be done by content: ESP-IDF v4.4 has DPP files and no
  `dragonfly.c` (the file where SAE lives upstream); v5.2 has
  `dragonfly.c` and `sae_pk.c` (SAE's hash-to-element variant, added
  after Dragonblood), i.e. post-2019 upstream. The KRACK-era guard and
  the reflection guard *are* present in both greps — but as *backports*:
  v4.4's history carries 2021 commits titled "Prevent reinstallation of
  an already in-use group key" and "Group key reinstallation fixes",
  applied to a snapshot of no stated base commit.

The consequence for a fleet is uncomfortable and worth stating exactly:
a NuttX-based Wi-Fi product's WPA security is (a) *not in any source
tree you can audit* when it runs on an offloaded module — gs2200m,
ESP32's closed blobs — and (b) *not attributable to a known upstream
revision* when it runs on Espressif's ported source, whose sync point
is lost and whose KRACK-era fixes are backports rather than a version.
Compare the NuttX CVE record (Chapter 2's table and Chapter 3's case
studies): the kernel's memory-safety CVEs have commits, versions and
credit. The WPA layer — the part carrying the
actual keys — has no equivalent ledger. Our KRACK and SAE harnesses are
therefore both a security analysis *and* a supply-chain statement: we
could verify the supplicant mechanism against a versioned upstream
(Debian's 2.3 and current hostap, checked in) and against two ESP-IDF
releases' ported source, but not against the binary actually shipping
on the boards.

## The honest limits of this section

We do not run an access point: the reflection attack and the PN reuse
require injecting or re-delivering frames, and we model the receiving
code instead. The consequence traces are exact (the state machines are
the upstream ones, the SAE key derivation is faithful on a real curve,
and the PWE statistics use real P-256 arithmetic), but the *radio* layer
is the papers', not ours. The gap is named and bounded once, in Section
5's "What we could not do"; we do not re-argue it here.