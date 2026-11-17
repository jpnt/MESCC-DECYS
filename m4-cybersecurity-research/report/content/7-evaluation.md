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

**NuttX CVE-2025-35003** — a $2 companion module is architecturally a
peer; the driver treated it as trusted silicon. This is the
"validation is the application developer's job" doctrine failing *in the
kernel driver*, exactly where the doctrine's own escape clause
(report generic problems to us) admits it should not have.

**NuttX CVE-2025-48768** — a debug assertion used as the real check, on
a build configuration where assertions are compiled out: the classic
divergence between "developer contract" and "runtime enforcement".

**NuttX fs_rename (analysed, not reproduced)** — an optimization (buffer
reuse across loop iterations) outliving the single-threaded mental model
that justified it; our failed harness (Chapters 3 and 7 / Appendix A) shows how
hard even reading this one is to turn into machine-checked evidence —
which is itself data about code-archaeology cost as a security property.

## The difference between breaking a cipher and exploiting an implementation

Five demonstrations, zero broken primitives: AES-CCMP stayed sound
through KRACK; the Dragonfly group law stayed sound throughout
Dragonblood; none of the NuttX cases touch any algorithm. The attacks
all live in the seam where mathematics stops and state machines begin —
counters, installation order, message provenance, execution time. For a
procurement team this collapses to one testable question about any
stack: *what does your code do when it receives a message twice, from a
peer it cannot see, faster than it expects?* The report's contributions
are five concrete answers to that question, three of them compiled with
sanitizers watching.

## Lessons learned (ours, not the industry's)

1. **Fidelity beats breadth in reproductions.** Stubbing only the glue
   (our harness pattern) gave, in one night, evidence nobody had
   published for three of these CVEs.
2. **A negative result costs nothing to publish and buys trust.** The
   fs_rename non-reproduction is the paragraph reviewers cite.
3. **"No CVEs" must never be read as "no bugs";** in NuttX's Wi-Fi
   layer it is structurally unverifiable (Chapter 4), and the absence of
   a ledger, not of incidents, is the risk.
4. **The supply chain is where the auditable security stopped.** In 2017
   the question was "which supplicant build do I run"; in NuttX products
   today it is "which blob contains my handshake".
