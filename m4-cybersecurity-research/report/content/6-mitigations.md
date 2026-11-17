## Patches: what the fix lines actually look like

Across the three case studies, every fix is the same three-act shape —
and the report's thesis is easiest to defend by showing the patches
side by side:

| Bug | Fix | Size | Where the check belongs |
|---|---|---|---|
| KRACK (#3 of 4) | `if (sm->ptk.installed) return 0;` in `install_ptk` | 3 lines | receiver: installation must be idempotent |
| GTK variants | "Not reinstalling already in-use GTK" guards | 5 lines | same idea, per key type and direction |
| SAE reflection | compare peer commit against own before accepting | ~10 lines | receiver: commitments must be independent |
| SAE timing | fixed-iteration hash-to-element | whole loop | design: the variable loop was the flaw |

Two lessons generalize. First, a *missing guard of a few lines* is the
normal form of these vulnerabilities — which is why source reading finds
them (Chapter 3) and why continuous fuzzing of the parser surface
(hostap's dedicated fuzz targets) is the only defence at fleet scale. Second, the KRACK
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
For embedded stacks specifically: hostap's own
fuzz-build targets (`make fuzz`, libFuzzer/AFL on the EAPOL parsers) are
the lesson learned at protocol level — the parser surface is now a
continuous, instrumented target rather than code trusted at compile
time. On the device side the same argument demands a vendor that can
answer "which upstream commit is your supplicant?"; a product that
cannot, ships the blob path above.

## What the patches and our reproductions prove together

The patched builds are our control groups: the same replayed Message 3
that resets the transmit counter in the 2.3 model is refused by the
current guard ("Do not re-install same PTK to the driver"), and the same
echoed SAE commit that livelocks the 2.3-shaped receiver is dropped by
the comparison string from current `sae.c` ("evidence of a reflection
attack"). The comparison is exact because we took the pairs from the
upstream releases themselves — which is the cleanest demonstration
available without radio hardware that *the check, not the cipher, is
the security*.
