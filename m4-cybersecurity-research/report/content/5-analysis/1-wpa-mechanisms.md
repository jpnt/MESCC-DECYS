## WPA2 KRACK: the mechanism, in code

KRACK (CVE-2017-13077 and the family 13078–13087 [@nvd-krack]) is not a Wi-Fi bug and
not a cryptography bug: it is a state-machine bug in the supplicant's
4-way handshake receiver, and the whole attack reduces to one missing
`if` [@krack] [@krack-site]. We fetched the actual `wpa_supplicant` sources (upstream sources via the Debian archive [@wpasrc]:
`wpa.c` 2.3, the KRACK-era receiver; `wpa.c` current, the fixed receiver) and rebuilt the receiver's decision structure in a small
model, [@krack] [@krack-site]. Modelled in `snippets/krack_harness.c`, the vulnerable build mirrors 2.3
(`INSTALL bit on Message 3 → wpa_sm_set_key()`, unconditionally), and
the fixed build carries the guard that the fix added, in Jouni Malinen's
own comment string: *"Do not re-install same PTK to the driver"*. The
CCMP cipher is modelled as the keystream cipher it is (CTR mode over a
key and a packet number), and the driver contract — installing a key
resets its TX counter — is reproduced because that reset is exactly what
made reinstallation fatal.

The run tells the whole story. Handshake installs the PTK (PN reset, as
always). A frame goes out at PN=0. The AP retransmits Message 3 — a
completely ordinary 802.11 event, data acknowledgements are lossy, and
the supplicant *must* answer Msg4 again in both versions. The
vulnerable receiver also *reinstalls the key* — resetting the TX counter
to zero — and the next frame goes out at PN=0 again: same nonce, same
key, two plaintexts. We let the attacker sniff both ciphertexts and
possess the first plaintext (ARP is the paper's choice; every LAN has
them): the keystream from the known pair decrypts the second frame.
Output:

```
[wifi] TX frame1 (known ARP + zero padding) at PN=0
== AP retransmits Msg3 (Install|Secure): the replay
[driver] set_key(PTK): TX packet number reset, key slot armed
[wifi] TX frame2 (secret) at PN=0
[ATTACK] key reinstalled: PN reused, recovered: SECRET-SESSION-TOKEN-...
```

The fixed build sees the identical input and refuses the reinstall: PN
monotonic, no reuse, nothing to recover. That is the entire vulnerability
in ten lines of control flow — and it is the *same shape* as our NuttX
cases: an implementation trusting an input field (`Install bit`) that a
correct-by-construction peer would never set twice, with no validation
layer behind it.

## WPA3 SAE/Dragonblood: the mechanism, in code

SAE (the WPA3 handshake, "Dragonfly") failed in two ways in 2019
(CVE-2019-9494 through 9499, "Dragonblood") [@nvd-dragonblood] [@dragonblood]. Part one is a missing
comparison. The commit exchange sends (blind = v+m, commit = v·G − PWE);
the 2.3 receiver stored whatever arrived and continued, with no check
that the peer's values differ from its own. A malicious AP simply
*echoes* the station's Commit back: the station then runs the rest of
the handshake authenticating against a copy of itself, no real AP secret
ever enters the key, and the exchange never yields usable material —
the station retries forever, which is a permanent, cheap DoS of the
handshake state machine [@dragonblood]. Current `sae.c` contains exactly the missing
comparison (*"would be evidence of a reflection attack"*).
`snippets/sae_harness.c` implements the true group law on a small curve
(p=1009, order 1024, exact integer arithmetic — no abstractions to
break) and drives five rounds: the 2.3-shaped receiver livelocks on all
five, the guarded receiver drops the echo in round one.

Part two is a side channel, and we measured it against the real loop
rather than model it: `sae_derive_pwe_ecc` (extracted verbatim to
`snippets/sae_derive_pwe_pre_dragonblood.inc`) hunts for a password-
derived curve point, padding to k=4 iterations to hide how long the hunt
took. Against a real quadratic-residue oracle on NIST P-256
(`tools/sae_pwe_stats.py`), the padding does not hide it:

```
real-stops-at-4: 0.933   real-stops-at-5: 0.039
real-stops-at-6: 0.017   real-stops-at-7: 0.005
P(work beyond the k=4 pad) = 0.067
```

Six to seven percent of password candidates do *extra* cryptographic
work the rest never do — runtime is password-correlated, which is the
signal the Dragonblood cache/retry attacks extract to verify a guessed
password from a distance. The class-level statement in the papers is
"loop count leaks"; our number is what that leak measures on the
upstream loop itself.

## Where this code lives, and where NuttX's lives

This is the part that decides whether this section is about NuttX at
all. Verified in the trees (we fetched both; claims below are from the
sources, not the marketing):

- **NuttX has no supplicant.** `apps/wireless` contains `bluetooth`,
  `ieee802154`, `iwpan`, `wapi`, `gs2200m` and `lora_pkt_fwd` — no
  hostap. The gs2200m example hands the WPA2 *passphrase* to the Wi-Fi
  module's firmware (`gs2200m_main.c`: a join command with "8 to 63
  ascii passphrase for WPA2-PSK"): the handshake runs inside a vendor
  blob on a companion chip. `wapi` configures via wireless ioctls
  (`IW_AUTH_WPA_VERSION_*`), again expecting the driver to hold the
  state machine. The kernel tree carries no 802.11 crypto either; the
  ESP32 paths route into Espressif's closed `libnet80211`/`libpp`.
- **ESP-IDF carries the supplicant, and its provenance is
  undocumented.** [@esp-wpasupplicant] `components/wpa_supplicant/README.md` says only
  "ported for ESP family of platforms" — no base commit, no version
  string (stripped). Dating has to be done by content: v4.4 has DPP
  files and no `dragonfly.c`; v5.2 has `dragonfly.c`/`sae_pk.c`, i.e.
  post-2019 upstream. The KRACK-era guard and the reflection guard *are*
  present in both greps — but as *backports*: v4.4's history carries
  2021 commits titled "Prevent reinstallation of an already in-use group
  key" and "Group key reinstallation fixes", applied to a snapshot whose
  base commit nobody can state.

The consequence for a fleet is uncomfortable and worth stating exactly:
a NuttX-based Wi-Fi product's WPA security is (a) *not in any source
tree you can audit* when it runs on an offloaded module — gs2200m,
ESP32's closed blobs — and (b) *not attributable to a known upstream
revision* when it runs on Espressif's ported source, whose sync point
is lost and whose KRACK-era fixes are backports rather than a version.
Compare Section 2's NuttX CVE record: the kernel's memory-safety CVEs
have commits, versions and credit. The WPA layer — the part carrying the
actual keys — has no equivalent ledger. Our KRACK and SAE harnesses are
therefore both a security analysis *and* a supply-chain statement: we
could verify the supplicant mechanism against Debian's audited sources
and against ESP-IDF's *current code*, but not against the binary
actually shipping on the boards.

## The honest limits of this section

We do not run an access point: the reflection attack and the PN reuse
require injecting or re-delivering frames, and we model the receiving
code instead. The consequence traces are exact (the state machines are
the upstream ones, the key schedule is faithful on a real curve, and the
PWE statistics use real P-256 arithmetic), but the *radio* layer is the
papers', not ours. What we would need for that — programmable Wi-Fi
adapters with monitor/injection support — is also the main obstacle to
over-the-air validation of every one of Section 2's CVEs, and it is
named as such in Sections 4 and 5.