We studied the WPA2 key-reinstallation failure — and its WPA3 successor
— as one security subject: the protocol mechanics (Chapter 2), the
receiver-side reproductions (Chapter 3), the honest scope of the
attacker's gain (Chapter 4), the lab that would extend them over the air
(Chapter 5), the mitigations (Chapter 6), and what went wrong (Chapter
7).

The reproductions are the part we can defend line by line. In the 2.3
receiver, a replayed Message 3 reinstalls the key, resets the transmit
counter, and lets a known ARP frame decrypt a second frame; the patched
receiver, fed the identical bytes, answers the retransmission without
installing and the counter keeps counting. In SAE, the reflection
livelock occupies five of five rounds until the guard — the exact
comparison string from current upstream — drops the echo; and the
hunt loop's work is measurably password-dependent (6.6% beyond its own
anti-leak padding), on real P-256 arithmetic. The negative results are
reported too: this machine ran no radio, and the model's scope stops at
CCMP keystream reuse where the original paper's went to TKIP forging
and zero-key installs.

The embedded counterpart of the research question produced its own
finding: the code that holds the keys has no provenance ledger at the
device layer — offloaded modules run vendor blobs, and the leading
RTOS-class SDK port states no upstream base revision, with KRACK-era
guards arriving as silent backports. The conclusion for critical
systems is not to fear a broken cipher; it is to ask, of any stack that
claims to implement a secure protocol, the one question this whole
report answers for hostap: *what exactly do you do when a message
arrives twice, from a peer you cannot see?* State is where security
lives, and state is where it is lost.
