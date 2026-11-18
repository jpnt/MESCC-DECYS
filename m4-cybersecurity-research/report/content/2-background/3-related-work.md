## Related work, and why "which implementation?" is the question that matters here

WPA2's history is a sequence of implementation failures, not algorithm
failures: the KRACK CVEs are numbered per product because each vendor's
handshake code failed differently. That makes the reproduction target
and the provenance of whatever copy of it ships in a device, the
substance of the analysis. The literature below is positioned against
that claim: what each work establishes, by what method, and what this
report can and cannot borrow from it.

### The KRACK line: one technique, three papers

**Vanhoef and Piessens, CCS 2017** (*Key Reinstallation Attacks:
Forcing Nonce Reuse in WPA2*) [@krack] is the source of the mechanism
Chapter 2 reconstructs and Chapter 3 models. Its contribution is a
named attack class, key reinstallation, plus the specific result that
the 4-way handshake's own state machine makes reinstallations
mandatory-accept: message 3 must be answered because message 4 may
have been lost, and the supplicant state machine the paper reproduces
from the standard (from 802.11r, [1, Fig. 13-17]) still accepts Msg3 in
PTK-DONE [@krack]. Method: read the standard's scattered textual
description into a state machine, then attack the implementation
surface with a channel-based MitM and measure per-OS behaviour (its
Table 1 is why our CVE references are per-product). What it does *not*
claim, and Chapter 4 keeps inside those bounds: it recovers neither
the PTK nor the passphrase, and it breaks no primitive. The same
result was presented as a technical briefing at Black Hat Europe 2017
under the title *Key Reinstallation Attacks: Breaking the WPA2
Protocol* [@dv-bh-eu-2017]; the briefing and the krackattacks.com
disclosure are the primary sources for the per-CVE wording, since the
paper itself describes behaviour per OS rather than per identifier
[@dv-krack-cve-list].

**The same authors at CCS 2018** (*Release the Kraken: New KRACKs in
the 802.11 Standard*) [@krack2018] is the follow-up, and it is the
correct citation for the "the fix is not enough" half of this report's
argument, which the earlier bib entry's stray title had obscured. Its
contributions: attacks generalised so they no longer depend on
hard-to-win race conditions; a systematic sweep of every handshake in
the standard that installs keys, finding FILS and TPK also vulnerable;
the WNM-Sleep bypass of 802.11's official countermeasure ("a device
shouldn't reinstall an already in-use key", defeated by first letting
the victim install a *different* key, then reinstalling the old one);
and a patch audit that found implementation-specific flaws of its own,
including ANonce/SNonce reuse during rekeys, which is the mechanism by
which a *patched* hostapd AP could reinstall the same session key
indefinitely, and the honest source for "deterministic" ANonce-style
variants of KRACK [@krack2018] [@dv-krack-followup]. Method: the same
state-machine reading, applied to the whole standard, plus device
testing. Relation to ours: it establishes that idempotence-by-comparison
(the guard in our fixed model) is a necessary but not sufficient
condition, which is why Chapter 6 presents it as one layer of a
defence rather than as the end of the story.

**He and Mitchell, WiSe 2005** (*Analysis of the 802.11i 4-way
Handshake*) [@he2005] is the pre-KRACK formal analysis that makes
KRACK surprising: it proved the handshake's session key secret and both
parties' identities confirmed, and the CCS paper is explicit that its
own attacks violate neither property, because "the proofs do not model
key installation. Put differently, their models do not state when the
negotiated key should be installed" [@krack]. Read together with
Cremers et al. below, this is the two-point baseline of this report's
thesis: the abstract protocol was proved sound, and the soundness
statement was silent about the exact thing that broke.

The same section names the three neighbouring failure modes that KRACK
is *not*, which is useful for drawing our own boundary. Zenner's nonce
reset problem is the same symptom from a power failure, and cannot be
forced remotely [@zenner2009]. Beurdouche et al. and de Ruiter and
Poll found TLS composite state machines that wrongly allow handshake
messages to be repeated, but no attack on the repetition, and the CCS
paper conjectures a TLS key reinstallation on that basis
[@beurdouche2015messy] [@deruiter2015]. McGrew's deterministic-IV
survey covers nonce generation practice without treating reinstallation
as a risk at all [@mcgrew-iv-gen]. The common shape is worth naming,
since it is the shape of our whole subject: a message-repetition rule
plus a nonce that resets is the bug, and it had been seen in three
places without being exploited in any of them.

### Formal analysis: what Cremers et al. actually prove, and what they abstract away

**Cremers, Kiesl and Medinger, USENIX Security 2020** (*A Formal
Analysis of IEEE 802.11's WPA2: Countering the Kracks Caused by
Cracking the Counters*) [@cremers2020] is the rigorous version of the
distinction this report leans on, and it is worth stating precisely
what its model does and does not contain, because that is why KRACK was
invisible to earlier proofs. Their Tamarin model is the first detailed
enough to *exhibit* the KRACK attacks: two state machines for the
four-way handshake (supplicant and authenticator), the group-key
handshake, WNM sleep mode, and the data-confidentiality protocol, with
the standard Dolev-Yao treatment of cryptography deliberately relaxed
so that the attacker can exploit nonce *reuse* rather than being
handed perfect encryption. Under the countermeasures, they prove
secrecy of the PMK, of the PTK, and of the group temporal keys, plus
injective agreement for the four-way handshake from both parties'
perspectives, through roughly 70 lemmas [@cremers2020]
[@cremers2020prepub].

What remains outside it is stated by the authors and is the interesting
part for a reader of this report: the analysis is of the *protocol
design*, and they list side channels, the wider 802.11 stack design,
and "the decisions made for individual implementations" as attack
vectors their model does not cover; they also note that group-key
reinstallations on the supplicant side were neither proved impossible
nor found [@cremers2020]. So the boundary is not that the proof was
wrong; it is that "the driver resets this key's transmit counter" and
"this packet number was already used" are statements about an
installation and a counter, not about a term algebra. This is exactly
why our contribution is a code model rather than a second proof: the
claim we needed to test was about control flow and a counter reset,
which is the layer between the proof and the product. Their models and
proofs are public, which is what makes the optional stretch of this
project a comparison rather than a reconstruction.

### The SAE line: from side channels to a changed design

**Vanhoef and Ronen, IEEE S&P 2020** (*Dragonblood: Analyzing the
Dragonfly Handshake of WPA3 and EAP-pwd*) [@dragonblood] is the source
for everything Chapter 3 does with SAE, and its internal structure maps
onto our two SAE results. Design-level: the reflection DoS, where a
malicious peer echoes the victim's own Commit and the handshake
degenerates into self-authentication, plus the downgrade and
key-confirmation variants (our CVE-2019-9494/9496 family)
[@nvd-dragonblood]. Implementation-level: the timing and
micro-architectural cache attacks on the password-to-point hunt, whose
purpose is offline password verification at near-local cost, one
candidate per handshake interaction [@dragonblood]. Note that the
cache-attack half is *not* an instance of the KRACK class at all: no
key is reinstalled, and nothing about the counters is reset. What the
two share is the deeper lesson that a security property can live in the
execution time of an honest implementation. Method for the side-channel
half: Flush+Reload on the instruction cache of a real hostap build
monitoring the branch structure of the loop, on P-256, plus a
measurement of attack cost against real hardware. Relation to ours:
Chapter 3 measures the upstream loop's own iteration-count leak
offline, which is the *cause* the cache attack reads remotely; our
0.066 figure is a statement about the loop, not a cache attack, and we
say so where we state it. The ePrint version carries the same content
with an earlier date [@dv-eprint-dragonblood].

The fix history matters here because it is a *design* fix, and it is
the standardisation aftermath of this paper. RFC 7664's
hunting-and-pecking loop is what made the iteration count
password-dependent in the first place, while already recommending that
the residue test blind its input [@rfc7664]. Dragonfly's hash-to-element
replacement removes the loop, so there is no count to leak, and it is
the change the authors proposed and saw adopted, in the WPA3 programme
and in EAP-pwd's successor drafts, on top of the hash-to-curve
construction standardised as RFC 9380 [@dv-rfc9380] [@dragonblood].
Chapter 2's description of the loop and Chapter 6's treatment of H2E
both rest on this pairing of specification and patch history.

### The embedded/side-channel frontier, and what we deliberately do not claim

The paper that comes closest to the micro-architectural frontier our
models stop in front of is Schepers, Ranganathan and Vanhoef's
*Practical Side-Channel Attacks against WPA-TKIP* (ASIA CCS 2019)
[@schepers2019asiaccs]. Contribution: cache-based side channels that
recover the MIC keys of WPA-TKIP by observing cache access patterns
from an unprivileged user-mode process on the machine running the
supplicant, the same threat model Dragonblood uses for its SAE cache
attack, where the spy is likewise an unprivileged process monitoring
instruction-cache lines [@dragonblood]. Relation to ours: this is
precisely the frontier we do not cross. Our models have no such
observer, no cache, and no radio; the TKIP MICAR result and the cache-timing family
are cited as the papers' measured outcomes and not re-derived (see the
honesty note in Chapter 1). The distinction is worth keeping sharp
because it is the distinction this report draws everywhere:
protocol-logic bugs are reproducible offline from the code, and
micro-architectural ones are not, and the two families therefore carry
different evidence obligations. The embedded question in Chapter 3 is a
*provenance* question about shipped source, not a side-channel
measurement, which is why it is answerable with file listings and greps
instead of counters.

### Later Wi-Fi state-machine bugs, as a class

Two results bracket the period after KRACK and show that the failure
mode was not a single missing boolean. *Fragment and Forge* (USENIX
Security 2021) found that the kernel's handling of fragments and
aggregated subframes could drop the payload of unfragmented MPDUs and
decrypt others, leaking traffic with no handshake involvement at all
[@rsaa2021]. *Framing Frames* (USENIX Security 2023) found that a
client's transmit queue could be manipulated so that a frame is
encrypted under a different key than the one its header claims
[@rsaa2023]. Both are, like KRACK, defects in the mapping between a
frame and the key/counter state that is supposed to protect it, and
both are outside the reach of the idempotent-installation fix: the
guarantee that CCMP needs is not "install once" but "the state that
encrypted this frame is the state the receiver will use to decrypt
it". Their relevance to this report is as the strongest available
counter-evidence to a too-comfortable reading of our own conclusion:
fixing key installation closed one instance of the class, not the
class. For completeness, the group-key prior art *Predicting,
Decrypting, and Abusing WPA2/802.11 Group Keys* (USENIX Security 2016)
[@vanhoef2016groupkeys] is the other side of the same coin: it attacks
how a GTK is *chosen*, whereas CVE-2017-13080 attacks how an unchanged
GTK is *installed*, and Chapter 2's group key handshake paragraph needs
both to be clear about which failure is which.

### The reproduction tooling

The plan's reference lab is the tooling the original research used,
`krackattacks-scripts` and its `wifi-framework`/`mac80211_hwsim`
testbed [@krack-scripts] [@wifi-framework]. Contribution: a
scapy-based attack suite and a simulated Wi-Fi testbed that let a
handshake be re-delivered deterministically without radio hardware,
plus per-CVE test scripts and reference captures (including the
TPTK/all-zero-key examples Chapter 4 refers to). Relation to ours: it
is the boundary of our own results. Chapter 5 documents the setup
step by step and reports the negative result, that this machine has no
hwsim-capable kernel, so the attack-side capture remains an x86
follow-up. That is why the report's executable contribution is a
receiver-side model rather than a capture, and why the model's driver
contract is reproduced from the pinned upstream sources rather than
from a live kernel.
