## Patches: what the fix lines actually look like

Across the three case studies, every fix is the same three-act shape
and the report's thesis is easiest to defend by showing the patches
side by side:

Every fix below is a verbatim quote from a file checked in under
`report/snippets/upstream/`, with the enclosing function named, or a
labelled quote from the upstream advisory or commit that introduced it.

| Bug | Fix (quoted) | Location | Where the check belongs |
|---|---|---|---|
| KRACK (#3 of 4) | `if (sm->ptk.installed) { wpa_dbg(... "WPA: Do not re-install same PTK to the driver"); return 0; }` | `wpa_supplicant_install_ptk()` in `wpa_cur.c` [@wpasrc] | receiver: installation must be idempotent |
| GTK variants | `if ((sm->gtk.gtk_len == (size_t) gd->gtk_len AND os_memcmp(sm->gtk.gtk, gd->gtk, sm->gtk.gtk_len) == 0) OR ...) return 0;`, debug string "Not reinstalling already in-use GTK to the driver" | `wpa_supplicant_install_gtk()` in `wpa_cur.c` [@wpasrc] | same idea, per key type and direction |
| SAE reflection | `if (!sae->tmp->own_commit_scalar OR crypto_bignum_cmp(sae->tmp->own_commit_scalar, sae->peer_commit_scalar) != 0 OR ...) return WLAN_STATUS_SUCCESS;`, comment "would be evidence of a reflection attack" | `sae_parse_commit()` in `sae_2.6_reflection_fixed.c` [@wpasrc] | receiver: commitments must be independent |
| SAE timing | branch-free PWE loop (`counter <= k OR !found` with `const_time_select_*()` at every step) plus the fixed-iteration H2E path `sae_prepare_commit_pt()` (`sae->h2e = 1`) | `sae_derive_pwe_ecc()` and `sae_prepare_commit_pt()` in `sae_cur.c` [@wpasrc] | design: the variable loop was the flaw |

The 2.3-era loop shows the contrast the table rests on: `sae_2.3.c`
`sae_derive_pwe_ecc()` has `u8 counter, k = 4;` and exits candidates
with `if (res == 0) continue;`, so the iteration count was observable in
the control flow itself; the current file replaced that shape with
constant-time selection, exactly the commits the upstream advisory lists
("SAE: Minimize timing differences in PWE derivation", "SAE: Avoid
branches in is_quadratic_residue_blind()", "SAE: Use const_time
selection for PWE in FFC") [@dv-w1fi-2019-1]. The group-key guard's
history is equally checkable: the two-condition comparison in
`wpa_supplicant_install_gtk()` above is the 2017-10-16 pair "Prevent
reinstallation of an already in-use group key" plus "Extend protection
of GTK/IGTK reinstallation of WNM-Sleep Mode cases", whose diff adds the
separate `gtk_wnm_sleep` tracking the checked-in file shows
[@dv-hostap-gtk-commit] [@dv-hostap-wnm-commit].

Two lessons generalize. First, a *missing guard of a few lines* is the
normal form of these vulnerabilities, which is why source reading finds
them (Chapter 3) and why continuous fuzzing of the parser surface
(hostap's dedicated fuzz targets) is the only defence at fleet scale. Second, the KRACK
GTK and SAE-timing fixes show that *idempotence alone is not enough*:
installations must be idempotent AND uniform-cost, and state machines
must validate the *provenance* of peer messages, not merely their
format.

## The vendor patch window for KRACK, by advisory

The coordinated release was 2017-10-16: CERT/CC published VU#228519 that
day (last revised 2017-11-16), stating that the flaws are "in the
standard itself as opposed to individual implementations" and listing
the assigned CVEs [@dv-cert-228519]. The same day, w1.fi published its
advisory with the merge commits listed and the recommendation to update
to v2.7 "once available" [@dv-w1fi-2017-1], and Debian issued DSA-3999
for package `wpa` covering CVE-2017-13077 to 13082, 13086 to 13088,
fixed in `2.3-1+deb8u5` (jessie) and `2:2.4-1+deb9u1` (stretch); note
the stretch fix is a 2.4-based patched package, not an upgrade to 2.6
[@dv-debian-dsa3999]. Apple shipped its client fixes in the releases
dated that same week: iOS 11.1, tvOS 11.1 and watchOS 4.1 (13077,
13078, 13080 among them), with the distinctive wording "A logic issue
existed in the handling of state transitions. This was addressed with
improved state management." [@dv-apple-ios-111] [@dv-apple-tvos-111]
[@dv-apple-watchos-41]; macOS High Sierra 10.13.1 (Security Updates
2017-001 Sierra, 2017-004 El Capitan) carried the same Wi-Fi entries
[@dv-apple-macos-10131]. Android's was a *patch level*, not an OS
release: Google's bulletin published November 6, 2017 states "Security
patches for the KRACK vulnerabilities are provided under the
2017-11-06 security patch level" and lists the nine CVEs as EoP/High in
`external/wpa_supplicant_8` with public AOSP commit links for Android
5.0.2 to 8.0 [@dv-android-2017-11]; CERT/CC's vendor section for AOSP
was updated 2017-11-08 pointing at that bulletin [@dv-cert-228519].
The December 1, 2017 Android bulletin carries no KRACK entries, which
bounds the Android timeline at the November 6 patch level
[@dv-android-2017-12]. On the AP side, the same commit window added
`wpa_disable_eapol_key_retries=1`, a hostapd option that stops
retransmitting the key-installing EAPOL-Key frames for clients that
cannot be updated [@dv-hostap-ap-workaround-commit]. Two corrections
against how this window is often summarized: CERT/CC's own list assigns
CVE-2017-13084 to PeerKey STK reinstallation (Apple and the OS
distros) [@dv-nvd-13084], and w1.fi marks that identifier "not
applicable" for hostap because its PeerKey implementation never
installed the key ("the actual installation of the key into the driver
does not work"; DLS PeerKey is "obsolete and not known to have been
deployed") [@dv-w1fi-2017-1]. The widely quoted per-OS table in the
KRACK paper ("on Apple devices the reinstallation is of a random key")
is the paper's own OS analysis [@krack], not the CVE's content, and it
concerns a different identifier again (CVE-2017-13087 in the paper's
numbering). The fleet consequence
is visible in the dates: the protocol disclosure, the w1.fi patches,
and the Debian and Apple packages all landed on 2017-10-16 or the same
week, while Android's carriers needed a patch-level boundary three
weeks later. The FT (802.11r) side of the family closed with the
companion commit "hostapd: Avoid key reinstallation in FT handshake"
(CVE-2017-13082), which only skips the *second* driver install if the
first succeeded, an explicitly driver-conditional form of the same
invariant [@dv-hostap-ft-commit]. A defender's question is not
"is KRACK fixed" but
"which of these ledgers does my device appear in".

## Why idempotence was not enough: the uniform-cost rule after Dragonblood

WPA3/SAE's timing class (CVE-2019-9494: "observable timing differences
and cache access patterns", full password recovery when combined with
an offline dictionary attack, all releases up to and including 2.7)
[@dv-nvd-9494] was closed in two structurally different steps, and only
the second is a design fix. The first is defensive coding inside the
existing hunt-and-peck loop: the advisory's commit list turns every
password-dependent branch in the PWE derivation into constant-time
selection [@dv-w1fi-2019-1], and that is the `const_time_select_bin`
machinery quoted from `sae_cur.c` in the table above. The second is hash-to-element
(H2E), the successor of the CFRG's draft-irtf-cfrg-hash-to-curve,
standardised as RFC 9380, whose own text cites Dragonblood as the
motivation for rejecting "rejection sampling" (hunt-and-peck) and
demands constant-time implementations of its encodings [@dv-rfc9380].
With H2E the password-to-point map is a fixed formula, so the
attacker-choosable variable does not exist; hostap's implementation of
this path landed six months after the advisories (commit
"SAE: Implement hash-to-element PT/PWE crypto routines", 2019-10-15)
[@dv-hostap-h2e-commit] and is visible in the checked-in `sae_cur.c` as
`sae_prepare_commit_pt()`, which sets `sae->h2e = 1` and skips
`sae_derive_pwe_ecc()` entirely by taking the PT from a stored value
[@wpasrc]. The tie to KRACK's fix is exact: `install_ptk`'s
`sm->ptk.installed` guard makes the *state effect* of a repeated input
invisible (idempotence); H2E makes the *cost* of the input's
processing independent of the secret (uniform cost). Both are the same
defensive principle, "the execution must not depend on what the
attacker cannot already see", applied one layer apart, and Chapter 3's
0.066 leak probability is the measurement of what depending on it
cost.

## Did "retransmit-safe, idempotent install" become normative afterwards?

Partially, and the honest version is worth stating. Within the affected
codebase the rule was made normative in the implementation: the fix
commit messages articulate it as an invariant to be preserved against
future change ("reinstallations of the PTK are prevented by (1) assuring
the same TPTK is only set once as the PTK, and (2) that one particular
PTK is only installed once... this patch hardens wpa\_supplicant such
that future changes do not accidentally break this property")
[@dv-hostap-ptk-guard-commit], and the GTK fix states the same for
group keys ("do not install the given key if it is already in use")
[@dv-hostap-gtk-commit]. The IEEE 802.11 standard text itself, however,
is paywalled and not verifiable offline, so this report claims no
amendment number for a normative install-idempotence clause; what is
documented in the fetched primary sources is that each handshake
mechanism in the standard got its own identifier: the four-way, group
key, FT (802.11r), 802.11w-dependent IGTK, TDLS, and WNM-Sleep (802.11v)
cases are CVE-2017-13077/13078, 13080/13081, 13082, 13079/13081, 13086
and 13087/13088 respectively [@nvd-krack] [@dv-nvd-13086]
[@dv-nvd-13081], which is how a *family* of ten
identical mistakes in one standard's mechanisms, rather than ten bugs,
gets numbered. The generalisable normative statement in this record is
CERT/CC's: the vulnerabilities are "in the standard itself as opposed
to individual implementations thereof; as such, any correct
implementation is likely affected" [@dv-cert-228519].

## Implementation changes beyond the patch

WPA3's own response to KRACK-class failure is instructive as engineering
practice: SAE removes PMK-replay exposure, PMF (802.11w) protects
handshake and deauth frames, and the RFC 8032 "hunt-and-peck" flaw
(Dragonblood) taught the next generation, hash-to-element,
zero-rtt-PK, to make the *implementation* the thing that cannot leak.
For embedded stacks specifically: hostap's own
fuzz-build targets (`make fuzz`, libFuzzer/AFL on the EAPOL parsers) are
the lesson learned at protocol level, the parser surface is now a
continuous, instrumented target rather than code trusted at compile
time. On the device side the same argument demands a vendor that can
answer "which upstream commit is your supplicant?"; a product that
cannot, ships the blob path above.

## What the patches and our reproductions prove together

The patched builds are our control groups: the same replayed Message 3
that resets the transmit counter in the 2.3 model is refused by the
current guard ("Do not re-install same PTK to the driver"), and the same
echoed SAE commit that livelocks the 2.3-shaped receiver is dropped by
the comparison string from `sae_parse_commit()`, which upstream added in
2015 and which is present in both checked-in fixed `sae.c` copies
("evidence of a reflection attack") [@dv-hostap-reflection-commit]. The
reflection fix's provenance matters: it landed years *before*
Dragonblood numbered it, which is why Chapter 3 calls it part of the
2017-era guards rather than the 2019 response. The comparison is exact
because we took the pairs from the
upstream releases themselves, which is the demonstration
available without radio hardware that *the check, not the cipher, is
the security*.
