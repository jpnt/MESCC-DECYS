Key reinstallation (KRACK) is the most consequential WPA2 vulnerability
of the last decade: by replaying one handshake message, an attacker can
force a client to reinstall a key it is already using, resetting its
packet numbers and reusing the encryption keystream — without touching
AES. The research question this report answers is how that is possible
while the cipher itself remains unbroken. We answer it in code: a
faithful model of the supplicant's four-way-handshake receiver, built
from the official `wpa_supplicant` 2.3 sources (release tarball, sha256
pinned) and the current patched receiver, shows the reinstallation
branch, the counter reset, the keystream collision, and — from one
known ARP frame — the recovery of a second frame's plaintext. The
patched model, fed the identical input, refuses the reinstall and no
reuse occurs. The same method is applied to WPA3's handshake (SAE): the
reflection denial of service from CVE-2019-9494 is demonstrated on a
real, point-counted elliptic curve (livelocked retries in the
vulnerable flow, guard-drop in the patched one), and the timing side
channels are quantified by measuring the upstream password-to-point
hunt loop against a real quadratic-residue oracle on NIST P-256: about
6.6% of passwords take detectably longer, the signal that turns a
remote handshake into a password oracle. We then answer the embedded
counterpart of the research question — which implementation of all this
ships inside real devices — with a source audit of the vendor path
(ESP-IDF's supplicant port with no stated base revision, Krack-era
fixes as silent backports, and Wi-Fi crypto living inside closed
binaries on RTOS-based products). The report closes with mitigations
(idempotent installation, uniform-cost design, WPA3/SAE and its honest
scope), a root-cause evaluation of why a protocol-level assumption
broke so many independent implementations, and a formal-analysis view
(Cremers et al.) that proves the same boundary: WPA2's cryptography is
sound; its state machine is where security is lost. No real network was
attacked at any point; all experiments run offline and deterministically.
