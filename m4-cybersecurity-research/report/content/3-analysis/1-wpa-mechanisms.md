## WPA2 KRACK: the mechanism, in code

KRACK (CVE-2017-13077 and the family 13078–13087 [@nvd-krack]) is not a
Wi-Fi bug and not a cryptography bug: it is a state-machine bug in the
client's 4-way handshake receiver — the supplicant, in 802.11i terms —
and the whole attack reduces to one missing `if` [@krack] [@krack-site].

We fetched the actual `wpa_supplicant` receiver sources from upstream
(w1.fi release archives: `wpa_supplicant-2.3.tar.gz`, sha256 `eaaa5bf3…9d7b6a`, and `hostapd-2.6.tar.gz`, sha256 `01526b90…7117d` — both checked in under `lab/`; the extracted files mirrored under `report/snippets/upstream/`) [@wpasrc]: `wpa.c` 2.3, the KRACK-era
receiver, and `wpa.c` current, the fixed receiver and rebuilt the receiver's decision
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
vulnerability — a few lines of control flow — and it is a shape that
recurs across every stack in this report: an implementation trusting an
input field (`Install` bit) that a correct-by-construction peer would
never set twice, with no validation layer behind it.

## WPA3 SAE/Dragonblood: the mechanism, in code

SAE (the WPA3 handshake, "Dragonfly") failed in the ways of its 2019 advisory family
(CVE-2019-9494 through 9499, "Dragonblood") [@nvd-dragonblood]
[@dragonblood]. We model CVE-2019-9494 (reflection; note the upstream history: the
reflection guard landed with the 2017 KRACK-era batch — it is already
in the 2.6 release — while CVE-2019-9495/9496, which we measure, came
with Dragonblood itself in the 2.10 rewrite to constant-time
hash-to-element). The remaining variants (CVE-2019-9497/9498/9499:
confirm reflection, key-confirmation downgrade, and the timing
distance-attack refinement) follow from the same missing-comparison
and variable-work families and are not modelled here. Part one is a missing comparison. The
commit exchange sends (blind = v+m, commit = v·G − PWE; m = our secret
scalar, v = our mask, G = the curve's base point); the 2.3 receiver
stored whatever arrived and continued, with no check that the peer's
values differ from its own. A malicious AP simply *echoes* the
station's Commit back: the station then runs the rest of the handshake
authenticating against a copy of itself. Both sides' confirm tags
evaluate the SAME expression (the reflector has only our public
material), so they agree — but by pure echo: an "authentication" of the
station with itself, no independent AP secret anywhere in the derived
key. Our harness demonstrates exactly this: it computes `key_tag()` from
both views and the two tags are identical only because the reflector
has no values of its own; the DoS is the station stuck retrying a
handshake that can never yield usable data.
The station retries: each retry costs the supplicant commit work and a
handshake session allocated on the target — a permanent, cheap DoS of the handshake
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
P-256, over 1500 seeded 8-byte pseudo-passwords (each one candidate, the
sample unit below is per-password) with a fixed histogram range so the
block is reproducible:

```
$ python3 ../tools/sae_pwe_stats.py
real-stops-at-4: 0.934
real-stops-at-5: 0.031
real-stops-at-6: 0.019
real-stops-at-7: 0.009
P(work beyond the k=4 pad) = 0.066
```

About 6–7% of passwords hunt past the pad (binomial 95% CI ±1.2pp at
N=1500) — runtime is password-correlated,
which is the signal the Dragonblood cache/retry attacks extract to
verify a guessed password offline at near-local speed (their
"dictionary attack in a handshake" result: one candidate verified per
handshake interaction, the same cost structure as an offline wordlist
run) [@dragonblood]. The class-level statement
in the paper is "loop count leaks"; our number is what that leak
measures on the upstream loop itself.

## Where this code lives in embedded products

This section answers the question the protocol analysis leaves open:
*which implementation of it ships in a real product?* Verified in the
trees (the wpa_supplicant sources are checked in under
`report/snippets/upstream/`, taken from the official w1.fi releases;
the ESP-IDF claims were fetched via the GitHub API and the file lists,
guard greps, READMEs and commit records are checked in under `lab/`,
refetchable with `make sources-esp`):

- **RTOS-class Wi-Fi stacks ship no supplicant.** In the RTOS most
  often cited for consumer Wi-Fi devices, the wireless application
  layer carries no hostap at all; its companion-chip examples hand the
  WPA2 *passphrase* straight to module firmware, so the handshake runs
  inside a vendor blob. The dominant embedded Wi-Fi SDK behaves the
  same at the binary level: closed Wi-Fi libraries (`libnet80211`,
  `libpp`), with the supplicant source port living in the SDK.
- **ESP-IDF carries the supplicant, and its provenance is
  undocumented.** [@esp-wpasupplicant] `components/wpa_supplicant/README.md` (fetched at v4.4 and v5.2 into `lab/wpa_readme_v*.md`) says only
  "ported for ESP family of platforms" — no base commit, and the version
  string is stripped: neither the README nor the build records it.
  Dating has to be done by content: ESP-IDF v4.4 has DPP files and no
  `dragonfly.c` (the file where SAE lives upstream); v5.2 has
  `dragonfly.c` and `sae_pk.c` (SAE's hash-to-element variant, added
  after Dragonblood), i.e. post-2019 upstream. The KRACK-era guards and
  the reflection guard *are* present in both greps — fetched files
  `lab/v44_wpa.c`, `lab/v52_wpa.c`, `lab/v44_sae.c` — but as *backports*:
  the PTK guard above has a driver-side sibling, and v4.4's history
  (`lab/esp_v4.4_reinstall_commits.txt`) carries 2021 commits titled
  "Prevent reinstallation of an already in-use group key"
  (035909872b) and "Group key reinstallation fixes" (20bb0c3b02),
  applied to a snapshot of no stated base commit. The closed Wi-Fi
  stack itself (`net80211`, `pp`) ships as prebuilt blobs linked from
  `components/esp_wifi/lib/` (`lab/esp_wifi_prebuilt_blobs.txt`).

The consequence for a fleet is uncomfortable and worth stating exactly:
an RTOS-based Wi-Fi product's WPA security is (a) *not in any source
tree you can audit* when it runs on an offloaded module — gs2200m,
ESP32's closed blobs — and (b) *not attributable to a known upstream
revision* when it runs on Espressif's ported source, whose sync point
is lost and whose KRACK-era fixes are backports rather than a version.
Compare how the same vendors handle their other components: published
advisories with CVEs, versions and credit. For the supplicant port
there is no equivalent ledger — no base revision, no CVE mapping from
upstream hostap advisories to SDK releases. Our KRACK and SAE harnesses are
therefore both a security analysis *and* a supply-chain statement: we
could verify the supplicant mechanism against a versioned upstream
(Debian's 2.3 and current hostap, checked in) and against two ESP-IDF
releases' ported source, but not against the binary actually shipping on the boards.

## The honest limits of this section

We do not run an access point: the reflection attack and the PN reuse
require injecting or re-delivering frames, and we model the receiving
code instead. The consequence traces are exact (the state machines are
the upstream ones, the SAE key derivation is faithful on a real curve,
and the PWE statistics use real P-256 arithmetic), but the *radio* layer
is the papers', not ours. The gap is named and bounded once, in Section
5's "What we could not do"; we do not re-argue it here.