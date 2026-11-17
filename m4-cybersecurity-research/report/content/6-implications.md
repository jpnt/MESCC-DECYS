## What the attacks actually do, and what they do not

The papers (and our Sections 3 and 5 models) bound the damage precisely, and
the boundaries matter to a critical-systems reader.

**KRACK breaks confidentiality, then integrity, and never the crypto
primitives.** The core consequence is the keystream collision our model
replays: an eavesdropper recovering plaintext from one known-plaintext
frame pair. Beyond that, the per-OS consequences the KRACK paper
enumerates: on Linux, replayed Message 3 resets the TX counter to
zero — the family CVEs 13081-13087 ride on which implementation
property each OS exposes (SAMSUNG CVE-2017-13081 accepts reinstallations
on its own; APPLE CVE-2017-13084 installs a random key; OPENBSD
CVE-2017-13086 accepts a zeroed key). None of this requires the attacker
to decrypt anything by force: they sit one hop inside the radio range.

**SAE's reflection is a denial of service, not a password leak; its
timing side channels are a password oracle, not a break.** Our modelled
livelock (Section 3) never recovers a secret: the reflection attacker
mounts an unauthenticated AP that traps any client into endless
retries. The cache-timing family (CVE-2019-9495/9496) is what turns
"retry until the password is confirmed" into *offline* password
verification: the attacker who measures hunt-loop work can test
candidates remotely at near-local speed. That is the integrity of WPA3's
password model being degraded to "WPA2-quality" — the paper's own
summary — not an extraction of the key.

**The practical limitations of both attacks are also implementation
limitations.** They need the attacker *in radio range* of a target
network, and they need the target to *authenticate* (KRACK needs the
4-way handshake; the reflection DoS needs an SAE exchange). Neither
works on a device that is only an AP with PMF forced, or a client
connecting to a network whose AP installs keys idempotently. In our
terms: the attacks exploit *choice*, not chance — which is exactly why
they transfer to the embedded world, where those choices get made in
vendor ports nobody re-audits.

## The NuttX supply-chain consequence

Section 3 verified in the source trees where WPA actually executes in a
NuttX product: nowhere in the OS. It is in the Wi-Fi module's firmware
(the gs2200m example hands the raw passphrase to the module; the ESP32
NuttX path routes into Espressif's closed `libnet80211`/`libpp` blobs),
or in Espressif's ported `wpa_supplicant`, whose upstream sync point is
undocumented and whose KRACK-era guards arrive as silent backports
(2021 commits titled "Group key reinstallation fixes" on a snapshot of
unknown base version).

For the kernel, NuttX maintains an honest ledger — eleven CVEs, each
with commits, versions and credit. For the layer that holds the network
keys, the ledger does not exist. A procurement team asking "is our Wi-Fi
stack patched against KRACK?" of a NuttX-based product gets an *answer*
from vendor support, not an *auditable fact*. That asymmetry — audited
memory safety in one tree, unauditable crypto state machines in the
blob next to it — is, for us, the most important thing this report
found. It is also why our "demo without radio" (Sections 3 and 5) is a feature
of the methodology, not an apology: it is what an auditor *can* do with
sources, and the report states what remains impossible without them.

## Security implications for the kernel cases

Same lens, NuttX proper: CVE-2025-35003's overflow direction (upward
through a work-queue frame) makes control-flow corruption plausible on
Cortex-M-class parts, matching the advisory's "arbitrary code execution"
as a *possibility*, not a claim; its trigger surface (UART from the
BT controller module) is exactly the trusted-hardware-component mistake
KRACK makes with the Install bit. CVE-2025-48768 is bounded: a clean
DoS where an MMU/MPU traps the NULL write, worse on flat builds; the
advisory's CVSS 6.5 is right for the first and unknowable for the
second, which is the flat-memory tax again.
