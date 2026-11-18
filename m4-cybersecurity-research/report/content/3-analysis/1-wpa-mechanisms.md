## WPA2 KRACK: the mechanism, in code

KRACK (CVE-2017-13077 and the family 13078 to 13087 [@nvd-krack]) is not a
Wi-Fi bug and not a cryptography bug: it is a state-machine bug in the
client's 4-way handshake receiver, the supplicant, in 802.11i terms
and the whole attack reduces to one missing `if` [@krack] [@krack-site].

We fetched the actual `wpa_supplicant` receiver sources from upstream
(w1.fi release archives: `wpa_supplicant-2.3.tar.gz`, sha256 `eaaa5bf3…9d7b6a`, and `hostapd-2.6.tar.gz`, sha256 `01526b90…7117d`, both checked in under `lab/`; the extracted files mirrored under `report/snippets/upstream/`) [@wpasrc]: `wpa.c` 2.3, the KRACK-era
receiver, and `wpa.c` current, the fixed receiver and rebuilt the receiver's decision
structure in a small model, `snippets/krack_harness.c`. The vulnerable
build mirrors 2.3 (`Install` bit on Message 3 → `wpa_sm_set_key()`,
unconditionally), and the fixed build carries the guard that the fix
added, in Jouni Malinen's own comment string: *"Do not re-install same
PTK to the driver"*. The CCMP cipher is modelled as the keystream cipher
it is (CTR mode over a key and the transmit packet number, TX PN), and
the driver contract, installing a key resets its TX PN, is reproduced
because that reset is what made reinstallation fatal.

<!--raw-typst #figure(image("/figures/reflection.png", width: 78%), caption: [The SAE reflection path: the client's own Commit is echoed, accepted, and the handshake degenerates into self-authentication; current code compares and drops.]) <fig-reflection> -->

The run tells the whole story. Handshake installs the PTK (PN reset, as
always). A frame goes out at PN=0. The AP retransmits Message 3, a
completely ordinary 802.11 event, data acknowledgements are lossy, and
the supplicant *must* answer Message 4 again in both versions. The
vulnerable receiver also *reinstalls the key*, resetting the TX
counter to zero, and the next frame goes out at PN=0 again: same key,
same PN, two plaintexts. We let the attacker sniff both ciphertexts and
possess the first plaintext (ARP is the paper's choice; every LAN has
them): the keystream from the known pair decrypts the second frame.
Full run, verbatim:

```
$./krack_vulnerable vulnerable
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
vulnerability, a few lines of control flow, and it is a shape that
recurs across every stack in this report: an implementation trusting an
input field (`Install` bit) that a correct-by-construction peer would
never set twice, with no validation layer behind it. Upstream's own
advisory words the mechanism the same way: reinstalling a key
"clear[s] the RX packet number to an old value", which breaks replay
protection on RX and reuses packet numbers on TX, and the fix
commit states the invariant two ways, the same TPTK set once as the PTK
and the same PTK installed once [@dv-w1fi-2017-1]
[@dv-hostap-ptk-guard-commit].

<!--raw-typst #figure(image("/figures/state-machine.png", width: 92%), caption: [The supplicant's RSNA pairwise state machine. The vulnerable path (red) re-enters PTK-NEGOTIATING/PTK-DONE on a retransmitted Message 3 and installs again; the patched path (blue dashed) keeps the reply but skips installation. This is Figure 3 of the original paper [@krack], reproduced from the same state descriptions.]) <fig-fsm> -->


## WPA3 SAE/Dragonblood: the mechanism, in code

SAE (the WPA3 handshake, "Dragonfly") failed in the ways of its 2019 advisory family
(CVE-2019-9494 through 9499, "Dragonblood") [@nvd-dragonblood]
[@dragonblood]. We model CVE-2019-9494 (reflection; note the upstream history: the
reflection guard landed with the 2017 KRACK-era batch, it is already
in the 2.6 release, while CVE-2019-9495/9496, which we measure, came
with Dragonblood itself in the 2.10 rewrite to constant-time
hash-to-element). The remaining variants (CVE-2019-9497/9498/9499:
confirm reflection, key-confirmation downgrade, and the timing
distance-attack refinement) follow from the same missing-comparison
and variable-work families and are not modelled here. Part one is a missing comparison. The
commit exchange sends (blind = v+m, commit = v·G − PWE; m = our secret
scalar, v = our mask, G = the curve's base point); the 2.3 receiver
stored whatever arrived and continued, with no check that the peer's
values differ from its own. A malicious AP *echoes* the
station's Commit back: the station then runs the rest of the handshake
authenticating against a copy of itself. Both sides' confirm tags
evaluate the SAME expression (the reflector has only our public
material), so they agree, but by pure echo: an "authentication" of the
station with itself, no independent AP secret anywhere in the derived
key. Our harness demonstrates this: it computes `key_tag()` from
both views and the two tags are identical only because the reflector
has no values of its own; the DoS is the station stuck retrying a
handshake that can never yield usable data.
The station retries: each retry costs the supplicant commit work and a
handshake session allocated on the target, a permanent, cheap DoS of the handshake
state machine [@dragonblood]. Current `sae.c` contains the 
missing comparison (*"would be evidence of a reflection attack"*).
`snippets/sae_harness.c` implements the true group law on a small curve
(field prime p=1009, group order 987 = 3×7×47, exact integer
arithmetic; the tiny group is a vehicle for the state machine, not a
real-curve cost estimate) and drives five independent Commit exchanges
(a fixed count, not a sample): the 2.3-shaped receiver is stuck in all
five, the guarded receiver drops the echo in round one.

### The group algebra of the reflection, worked out

Everything below is the algebra of the checked-in upstream files, not a
textbook restatement: the sending side is `sae_derive_commit()` and
`sae_derive_commit_element_ecc()` in `report/snippets/upstream/sae_2.3.c`
(verbatim identical in 2.6 and current), the receiving side is
`sae_derive_k_ecc()` and `sae_derive_keys()` in the same file. The code's
own comments name the quantities, and `sae_get_rand_and_mask()` draws the
two secrets (`sae_rand` and `mask`, both from `sae_get_rand()`,
1 < value < r, neither transmitted):

```c
/* commit-scalar = (rand + mask) modulo r */          /* sae_derive_commit */
/* COMMIT-ELEMENT = inverse(scalar-op(mask, PWE)) */  /* sae_derive_commit_element_ecc */
```

Call a party's on-wire pair (s, C) with s = (r + m) mod q and
C = -(m·PWE), the minus being `crypto_ec_point_invert()` in
`sae_derive_commit_element_ecc`. Honest exchange, A with (r_A, m_A), B
with (r_B, m_B). A's receiver computes, per the verbatim comment block in
`sae_derive_k_ecc`:

```c
/*
 * K = scalar-op(rand, (elem-op(scalar-op(peer-commit-scalar, PWE),
 *                                        PEER-COMMIT-ELEMENT)))
 * If K is identity element (point-at-infinity), reject
 * k = F(K) (= x coordinate)
 */
```

that is K_A = r_A·(s_B·PWE + C_B). Substituting the definitions:
s_B·PWE + C_B = (r_B + m_B)·PWE - m_B·PWE = r_B·PWE, so **K_A = r_A·r_B·PWE**;
symmetrically K_B = r_B·r_A·PWE. Each mask cancels against the *other*
party's scalar sum, and the shared secret is the product of the two
untransmitted r values, anchored to the password through PWE (which
enters only via the cancelled sums). That cancellation is SAE's Commit
binding: seeing (s, C) on the wire leaks neither r nor m, and K cannot be
formed without one of them.

Reflect: the malicious AP answers A's Commit with A's own (s_A, C_A).
A's receiver stores them as the peer's and computes

```
K = r_A·(s_A·PWE + C_A) = r_A·((r_A + m_A)·PWE - m_A·PWE) = r_A²·PWE
```

The mask cancels exactly as before, but the surviving factor is A's own
rand, twice. The key material then follows `sae_derive_keys()` verbatim
in 2.3 (`sae_cur.c` keeps the same construction for the non-H2E case):

```c
/* keyseed = H(<0>32, k)
 * KCK || PMK = KDF-512(keyseed, "SAE KCK and PMK",
 *                      (commit-scalar + peer-commit-scalar) modulo r)
 * PMKID = L((commit-scalar + peer-commit-scalar) modulo r, 0, 128)
 */
```

Under reflection the scalar sum degenerates to 2·s_A mod q and k is the
x-coordinate of r_A²·PWE: every input to the KDF is a function of A's own
secrets and the password. The AP contributes nothing, and needs no
password knowledge to "share" the key: it never computes the key, it
copies A's frames. The confirm tags match for the same reason.
`sae_write_confirm()` sends `CN(KCK, send-confirm, own_commit_scalar,
COMMIT-ELEMENT, peer-commit-scalar, PEER-COMMIT-ELEMENT)` and
`sae_check_confirm()` evaluates the same expression with the own/peer
slots swapped (both call shapes are in `sae_2.3.c` lines 998-1064); when
peer = own by echo, the two argument permutations are the identical
byte string, so any tag the reflector returns, namely A's own, verifies.
`send-confirm` is the only remaining asymmetry, a two-byte counter the
reflector replays. The independence of the two commitments is precisely
what the swapped-slot construction assumes; reflection satisfies the
check while emptying it of meaning. The harness makes the self-reference
executable: `snippets/sae_harness.c` lines 202-208 compute
`key_tag(&sta, &reflect)` and `key_tag(&reflect, &sta)` and report them
equal (`int key_match = (ours == theirs); /* trivially true BY ECHO */`)
with own and peer values identical, the stuck condition.

### The guard, verbatim, and what 2.3 does instead

The fix is a comparison. From `sae_parse_commit()` in
`report/snippets/upstream/sae_2.6_reflection_fixed.c`, `src/common/sae.c`
at hostap 2.6, lines 1123-1146 (current `sae_cur.c` carries the
identical block at lines 2242-2265):

```c
	/*
	 * Check whether peer-commit-scalar and PEER-COMMIT-ELEMENT are same as
	 * the values we sent which would be evidence of a reflection attack.
	 */
	if (!sae->tmp->own_commit_scalar ||
	    crypto_bignum_cmp(sae->tmp->own_commit_scalar,
			      sae->peer_commit_scalar) != 0 ||
	    (sae->tmp->dh &&
	     (!sae->tmp->own_commit_element_ffc ||
	      crypto_bignum_cmp(sae->tmp->own_commit_element_ffc,
				sae->tmp->peer_commit_element_ffc) != 0)) ||
	    (sae->tmp->ec &&
	     (!sae->tmp->own_commit_element_ecc ||
	      crypto_ec_point_cmp(sae->tmp->ec,
				  sae->tmp->own_commit_element_ecc,
				  sae->tmp->peer_commit_element_ecc) != 0)))
		return WLAN_STATUS_SUCCESS; /* scalars/elements are different */

	/*
	 * This is a reflection attack - return special value to trigger caller
	 * to silently discard the frame instead of replying with a specific
	 * status code.
	 */
	return SAE_SILENTLY_DISCARD;
```

The 2.3 file has no such lines: `grep -c reflection` on `sae_2.3.c`
returns 0. What 2.3 does instead, in `sae_parse_commit_scalar()`
(lines 750-793), is compare the arriving scalar only against the scalar
remembered from an already-*accepted* session, the 802.11 re-use rule
(the comment cites IEEE Std 802.11-2012, 11.3.8.6.1), then store
unconditionally and fall through:

```c
	if (sae->state == SAE_ACCEPTED && sae->peer_commit_scalar &&
	    crypto_bignum_cmp(sae->peer_commit_scalar, peer_scalar) == 0) {
		wpa_printf(MSG_DEBUG, "SAE: Do not accept re-use of previous "
			   "peer-commit-scalar");
```

```c
	crypto_bignum_deinit(sae->peer_commit_scalar, 0);
	sae->peer_commit_scalar = peer_scalar;
```

and `sae_parse_commit()` ends with the unconditional tail call
`return sae_parse_commit_element(sae, pos, end);` (line 916), which
stores the peer element the same way and returns success. During an
in-progress handshake `sae->state` is `SAE_COMMITTED`, not
`SAE_ACCEPTED`, so the one comparison that exists cannot fire; the
validity checks that do run are format only, `0 < scalar < r` (lines
778-784) and "on curve" (`sae_parse_commit_element_ecc`), and an echo
passes both.
The echoed (s, C) is stored, `sae_process_commit()` derives r_A²·PWE, and
`sae_check_confirm()` (lines 1025-1064) compares the HMAC against the
echoed tag and returns 0. Every branch the receiver could take on a
reflected Commit is an accept branch. The guard closes the livelock path
itself, not the whole confirm family: if the reflected Commit had been
slightly altered the 2.6 guard rejects, and the separate confirm-
reflection result of Dragonblood (CVE-2019-9497) is fixed only in the
2.10 rewrite, not by these lines.

### What each retry costs the station

The livelock is not free for the victim, and the bill is readable from
the call graph rather than measured in cycles (our curve is a
state-machine vehicle, not a cost model, per the harness header). Each
re-Commit restarts at `sae_prepare_commit()` (2.3 line 504; current
`sae_cur.c` line 1347), which runs the entire Commit build:
`sae_derive_pwe_ecc()`, a minimum of k = 4 HMAC-SHA256 candidate hunts
(`u8 counter, k = 4;`, 2.3 line 294; the loop runs to `counter > 200`
before the "This should not happen in practice" break, line 334) each
with a point-decomposition solve; then `sae_derive_commit()`, i.e. two
`sae_get_rand()` rejection draws plus a `crypto_bignum_add`/`mod`, then
`sae_derive_commit_element_ecc()`, one `crypto_ec_point_mul()` and one
`crypto_ec_point_invert()`. After the echoed reply arrives,
`sae_process_commit()` adds `sae_derive_k_ecc()`: two further
`crypto_ec_point_mul()` and one `crypto_ec_point_add()`, then
`sae_derive_keys()`'s HMAC, SHA256-PRF and `crypto_bignum_add`/`mod`.
On retry, `sae_clear_temp_data()` and `sae_clear_data()` free and
`os_memset(sae, 0, sizeof(*sae))` the per-session structure (2.3 lines
73-102) and it is allocated again. The order of magnitude per attempt is
therefore four full EC scalar multiplications before the confirm even
starts, the 2.6-era `sae_derive_commit()` `do { ... } while` scalar
draw (from the function's opening line, `sae_2.6_reflection_fixed.c`
line 655) possibly looping the two `sae_get_rand()`s again, all of it
against the attacker's cost of one copied frame. The retransmission
timers themselves live in the supplicant-side SAE state machine outside
these files (hostap's `sme` layer, which we did not fetch, so we do not
quote their values); what the checked-in code shows is that every expiry
walks the full path above again. That asymmetry, a station's complete
re-commit for the reflector's single echo, is the DoS's engine.

<!--raw-typst #figure(image("/figures/pipeline.png", width: 80%), caption: [The SAE password-to-point hunt: each counter value is one KDF and residue test; when a point is found at counter i, the loop's runtime encodes i. The k=4 pad masks only small i.]) <fig-pipeline> -->

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
$ python3../tools/sae_pwe_stats.py
real-stops-at-4: 0.934
real-stops-at-5: 0.031
real-stops-at-6: 0.019
real-stops-at-7: 0.009
P(work beyond the k=4 pad) = 0.066
```

About 6 to 7% of passwords hunt past the pad (binomial 95% CI ±1.2pp at
N=1500), runtime is password-correlated,
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
 "ported for ESP family of platforms", no base commit, and the version
 string is stripped: neither the README nor the build records it.
- **The dating method is a systematic probe, not a file-name guess.**
 Three questions separate a base-revision claim from an undated
 snapshot, and all three run over checked-in files only (the GitHub
 tree listings, fetched sources, and the pinned w1.fi copies under
 `lab/`), via `tools/esp_guard_probe.py`, output in
 `lab/esp_guard_probe.md`, rerunnable with `make sources-esp`:
 (i) *When did this guard string enter upstream?* Probed with the
 official 2.3 and 2.6 files as anchors: "Do not re-install same PTK to
 the driver" is absent from 2.3 (`official_wpa_2.3_wpa.c`) and present
 in 2.6 (`official_wpa_2.6_wpa.c`, line 620); the reflection guard
 ("evidence of a reflection attack") is absent from 2.3's `sae.c` and
 present at `official_sae_2.6.c` line 1125.
 (ii) *Which guards does each ESP release carry?* v4.4's `wpa.c`: PTK
 guard absent, GTK guard present (`v44_wpa.c`, "Detect possible key
 reinstallation" line 796, "already in-use GTK" line 799); `v44_sae.c`:
 reflection guard present, line 1250. v5.2's `v52_wpa.c`: PTK guard
 present, line 763; GTK guard lines 879, 1017. v5.2's `sae.c` is not in
 `lab/` (the fetch rule takes `wpa.c` per tag; the file-listed
 `sae.c` path is the same at both tags), so the probe says so instead
 of guessing.
 (iii) *Does each hit live where upstream keeps it?* The GTK-guard
 string appears only in `wpa.c` at every snapshot (cross-checked in the
 sae files too: absent); the reflection guard only in the sae files.
 A guard that had landed in the wrong file would signal hand-edited
 porting rather than a sync, and the probe would show it.
 The picture this yields is inconsistent with any single upstream
 snapshot: v4.4 has DPP files (present at both tags, so DPP is not a
 discriminator) but no `dragonfly.c`, the file where SAE's
 hash-to-element work lives upstream; its `sae.c` has the post-2018
 reflection guard (so the snapshot is not 2.3-era) yet lacks the PTK
 guard that shipped in 2.6; and its `sae_derive_pwe_ecc` pads to
 `k = 40` (`lab/v44_sae.c` line 430) where official 2.3/2.6 pad to 4,
 a value upstream chose for a different reason than ESP's port
 documents. v5.2 has `dragonfly.c` and `sae_pk.c` (SAE-PK, added after
 Dragonblood), i.e. post-2019 upstream. No release between 2.6 and 2.9
 reproduces (ii)+(iii) together: the KRACK-era guards are in as
 *backports* applied to a snapshot whose base commit nothing states.
- **The fix timeline that is recorded, and the one that is not.**
 `tools/esp_timeline.py` parses the fetched commit record
 `lab/v44_commits.json` (GitHub API
 `commits?sha=v4.4&path=components/wpa_supplicant&per_page=100`; the
 record carries `sha`, `parents[].sha`, `commit.author.date` and the
 full message for each commit) into
 `lab/esp_v4.4_timeline.md`, sorted by author date then SHA, one table
 per keyword family:

| Date | Short SHA | Parent(s) | Commit subject |
|---|---|---|---|
| 2021-04-06T12:38:44Z | `035909872b` | `9d649505bc` | wpa_supplicant: Prevent reinstallation of an already in-use group key |
| 2021-04-22T07:35:49Z | `20bb0c3b02` | `7f34657013` | wpa_supplicant: Group key reinstallation fixes |

 (from `lab/v44_commits.json`; the second commit's body says verbatim
 "This commit reverts previous commit for GTK reinstallation fix and
 corrects original fix.") The KRACK-subject window of the same table is
 *empty*: no commit in the fetched page has a subject matching
 `reinstalled` or `re-install`, because the fetched window spans
 2020-01-07 to 2021-12-23 (100 commits, one API page), and the 2017
 PTK-side KRACK batch predates it; the PTK guard's absence in
 `v44_wpa.c` while the 2021 GTK backports are present is the asymmetry
 the timeline records but cannot explain. That is the factual state:
 group-key backports with dates and parents, pairwise-key fix present
 in source with no commit record at this tag, base revision nowhere.
 The closed Wi-Fi
 stack itself (`net80211`, `pp`) ships as prebuilt blobs linked from
 `components/esp_wifi/lib/` (`lab/esp_wifi_prebuilt_blobs.txt`).

### What a defender can conclude, and what this evidence cannot give them

Read positively, the probe above supports four statements about an
ESP-IDF build. (1) The v4.4 supplicant's 4-way receiver carries no
`ptk.installed` guard: `grep -n "Do not re-install same PTK"
lab/v44_wpa.c` finds nothing, and `wpa_supplicant_install_ptk()` there
(`lab/v44_wpa.c`, line 694) prints and installs unconditionally; that
matches the 2.3-side shape of our KRACK model for *this file*, the
pairwise install path. (2) The GTK path in the same v4.4 tree does
carry the in-use comparison (`v44_wpa.c` line 796), so the group-key
reinstallation class, CVE-2017-13087 in upstream terms, is closed at
this tag, and the 2021 backport commits say when the corrected version
landed. (3) The SAE reflection guard is present in v4.4's `sae.c` (line
1250), so the CVE-2019-9494 livelock is not this file's failure mode.
(4) v5.2 carries the PTK guard (line 763), so whatever v4.4's pairwise
path was, the later tag matches the fixed shape.

None of that transfers to a device, and the reasons are structural, not
rhetorical. The binary that actually encrypts frames is not in any of
these files: the supplicant hands keys to the closed `libnet80211`/
`libpp` blobs (`lab/esp_wifi_prebuilt_blobs.txt`) over a driver ABI, and
the TX-counter reset that made KRACK fatal is *the driver's* behavior; a
guard-free install call is only fatal if the driver resets the replay
counter on re-install, and that question is answerable only inside a
blob we cannot read. Absence of a base revision cuts both ways: v4.4's
port lacking the PTK guard string is evidence about Espressif's tree,
not proof that a given product's build is vulnerable, because a vendor
fork may patch it silently and the tree we can fetch is Espressif's, not
the product's. The commit record makes the fleet problem concrete:
`035909872b` and `20bb0c3b02` are dated 2021-04-06 and 2021-04-22 with
parents `9d649505bc` and `7f34657013` (`lab/v44_commits.json`), and the
same table has *no* 2017-2018 KRACK-era row and no version bump anywhere
in the fetched window: a fleet operator holding a device at "v4.4.x"
cannot map the build to fixed or affected from the SDK's own metadata,
only from a source probe like the one above. And because the KRACK CVEs
are numbered per product family (13077..13087 split across supplicant,
driver and AP roles, [@nvd-krack]), "is my device patched for CVE-2017-
13087?" is not even a question the vendor's version string can answer:
the answer lives in files whose revision no ledger records. What the
evidence does give a defender is a *prior* and a *test*: treat an
SDK-port supplicant as unaudited until grepped, grep the guard strings
the upstream fix used (they are the observable signature, and they cost
seconds), and remember that for the driver half of the attack the only
honest position is "unverifiable from source".

<!--raw-typst #figure(image("/figures/supplychain.png", width: 88%), caption: [How the supplicant reaches the device: an SDK port of unknown revision, or a closed binary. Neither path leaves an auditable mapping to upstream releases.]) <fig-supply> -->

The consequence for a fleet is worth stating plainly:
an RTOS-based Wi-Fi product's WPA security is (a) *not in any source
tree you can audit* when it runs on an offloaded module, gs2200m,
ESP32's closed blobs, and (b) *not attributable to a known upstream
revision* when it runs on Espressif's ported source, whose sync point
is lost and whose KRACK-era fixes are backports rather than a version.
Compare how the same vendors handle their other components: published
advisories with CVEs, versions and credit. For the supplicant port
there is no equivalent ledger, no base revision, no CVE mapping from
upstream hostap advisories to SDK releases. Our KRACK and SAE harnesses are
therefore both a security analysis *and* a supply-chain statement: we
could verify the supplicant mechanism against a versioned upstream
(the official 2.3 release and current hostap, checked in) and against two ESP-IDF
releases' ported source, but not against the binary actually shipping on the boards.

## Limits of this section

We do not run an access point: the reflection attack and the PN reuse
require injecting or re-delivering frames, and we model the receiving
code instead. The consequence traces are exact (the state machines are
the upstream ones, the SAE key derivation is faithful on a real curve,
and the PWE statistics use real P-256 arithmetic), but the *radio* layer
is the papers', not ours. The gap is named and bounded once, in Chapter 5's "What we could not do"; we do not re-argue it here.