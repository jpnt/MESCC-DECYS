## Patches: what the fix lines actually look like

Across all five case studies, every fix is the same three-act shape —
and the report's thesis is easiest to defend by showing the patches
side by side:

| Bug | Fix | Size | Where the check belongs |
|---|---|---|---|
| CVE-2025-35003 | reject `pktlen` > RXBUFSIZE; reject `len` > IOB_BUFSIZE | ~10 lines | driver entry + stack entry (two layers, both missing) |
| CVE-2025-48768 | `if (desc.parent == NULL) goto errout` | 5 lines | kernel primitive refusing its caller's assumption |
| KRACK (#3 of 4) | `if (sm->ptk.installed) return 0;` in `install_ptk` | 3 lines | receiver: installation must be idempotent |
| GTK variants | "Not reinstalling already in-use GTK" guards | 5 lines | same idea, per key type and direction |
| SAE reflection | compare peer commit against own before accepting | ~10 lines | receiver: commitments must be independent |
| SAE timing | fixed-iteration hash-to-element | whole loop | design: the variable loop was the flaw |

Two lessons generalize. First, a *missing three-line check* is the
normal form of these vulnerabilities — which is why source reading finds
them (Section 4) and why tooling that reads continuously (Section 7's
Zephyr contrast) is the only defence at fleet scale. Second, the KRACK
GTK and SAE-timing fixes show that *idempotence alone is not enough*:
installations must be idempotent AND uniform-cost, and state machines
must validate the *provenance* of peer messages, not merely their
format.

## Implementation changes beyond the patch

WPA3's own response to KRACK-class failure is instructive as engineering
practice: SAE removes PMK-replay exposure, PMF (802.11w) protects
handshake and deauth frames, and the RFC 8032 "hunt-and-peck" flaw
(Dragonblood) taught the next generation — hash-to-element,
zero-rtt-PK — to make the *implementation* the thing that cannot leak.
For embedded stacks specifically: the supplicant belongs in a language
and process with memory isolation and continuous fuzzing (the Zephyr/
OSS comparison, Section 7); on Linux-class systems the same lesson
produced `wpa_supplicant`'s long-standing fuzz-build targets. NuttX's
own `CONFIG_BUILD_PROTECTED` exists for the *kernel* side of this
argument; what nothing provides in the NuttX ecosystem today is a
protected place to put the supplicant — the crypto lives either in the
flat kernel or in a blob.

## What the patches and our reproductions prove together

The patched builds are our control groups: the same input that overflows
12.7's buffer is warned-and-dropped by 12.9's; the same replayed
Message 3 that resets PN in the 2.3 model is refused by the current
model's guard. The comparison is exact because we took the pairs from
the upstream commits themselves — which is the cleanest demonstration
available without radio hardware that *the check, not the cipher, is
the security*.
