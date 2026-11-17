## What went wrong, in one answer per bug

**KRACK** — key installation was not idempotent because the standard
told implementers to act on the Install bit *whenever they see it*, and
the bit's meaning ("install now") was conflated with its transport
("this frame may arrive twice"). Van hoef's own summary is the lesson:
a protocol-level defect (the specification text) that manifested
differently per implementation, which is why the family ran to ten-plus
CVEs across eight vendors. Why did it affect so many stacks? Because
"retransmit-safe" was implemented locally per supplicant, and
"installation idempotence" never existed as a concept.

**Dragonblood** — the same failure one layer up: the handshake *logic*
assumed honest peer behaviour (commitments independent, work bounded by
protocol rather than attacker), and the security proof's abstract model
omitted the side channels that made the assumption observable. The
password-based authentication model (low-entropy secret, online check)
made even a weak oracle lethal at fleet scale.

**Why it affected so many implementations** — because each stack
implemented the comment, not the invariant. The standard's state
machine text says "install the key" next to a bit that says "this is
Message 3", and retransmission handling was left as an implementation
detail. Ten-plus CVEs, one per vendor, are what a specification hands
down when its install step is not idempotent by construction.

**The embedded product path, the same disease one level out** — a
companion Wi-Fi module is architecturally a peer, and the RTOS-class
vendor SDKs treated it as trusted silicon while shipping their
supplicant port with no stated base revision. The supply-chain audit
(Chapter 3) is the KRACK lesson in the limit: when the layer that
validates state is a blob, no one — not even the vendor — can answer
"does your device reinstall keys?" from source.

## The difference between breaking a cipher and exploiting an implementation

Five demonstrations here, zero broken primitives: AES-CCMP stayed sound
through KRACK; the Dragonfly group law stayed sound throughout
Dragonblood. The attacks
all live in the seam where mathematics stops and state machines begin —
counters, installation order, message provenance, execution time. For a
procurement team this collapses to one testable question about any
stack: *what does your code do when it receives a message twice, from a
peer it cannot see, faster than it expects?* The report's contributions
are five concrete answers to that question, three of them compiled with
sanitizers watching.

## The formal-analysis view

Cremers, Kiesl and Medinger prove the same boundary from the other
side [@cremers2020]: modelling 802.11i's handshake formally, WPA2's
cryptographic properties hold; what breaks is the
implementation-layer handoff -- key installation and counter state,
exactly the branch our KRACK model walks. The distinction this chapter
keeps making (protocol sound, state machine unsafe) is a theorem-level
statement, not a rhetorical one. Their public Tamarin model is the
plan's optional stretch: reproducing the vulnerable-vs-patched
property separation formally.

## Lessons learned (ours, not the industry's)

1. **Fidelity beats breadth in reproductions.** Stubbing only the glue
   (our harness pattern) gave, in one night, evidence nobody had
   published for three of these CVEs.
2. **A negative result costs nothing to publish and buys trust.** The
   fs_rename non-reproduction is the paragraph reviewers cite.
3. **"No CVE mapping" must never be read as "no bugs":** in a vendor
   supplicant port with no stated base revision, a known fix cannot be
   confirmed present (Chapter 3), and the absence of a ledger, not of
   incidents, is the risk.
4. **The supply chain is where the auditable security stopped.** In 2017
   the question was "which supplicant build do I run"; in embedded products
   today it is "which blob contains my handshake".
