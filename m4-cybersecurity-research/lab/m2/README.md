# M2 - Lab and Reproduction (executed)

This directory holds the executed M2 reproduction: a working, isolated WPA2
lab in which key reinstallation is driven against an unpatched client, a
patched client resists the identical attack, and a normal four-way handshake
is captured and decrypted in Wireshark/tshark with the pre-shared key.

Unlike the attack-side procedure documented in Chapter 5 of the report (which
was previously only described, because the earlier arm64 host shipped no
`mac80211_hwsim`), this lab was actually run on `decys-vm` (Ubuntu 24.04
aarch64, whose generic kernel does carry `mac80211_hwsim`). Everything here is
raw evidence from that machine.

No real network is touched. The access point is Mathy Vanhoef's modified
`hostapd` from `krackattacks-scripts`; it only tests a client that connects to
an SSID we define and whose passphrase we set, on virtual radios that share a
simulated medium inside one VM.

## Environment

- Host: `decys-vm`, Ubuntu 24.04.5 LTS, kernel 7.0.0-42-generic, aarch64.
- Radios: `mac80211_hwsim radios=2` -> `wlan0` (access point) and `wlan1`
  (victim client), plus the `mon`/`hwsim0` monitor interfaces.
- Access point: `krackattacks-scripts` modified `hostapd` (built from source),
  SSID `testnetwork`, PSK `abcdefgh`, RSN/CCMP, channel 1.
- Tooling: `krack-test-client.py` (now Python 3; scapy 2.6.1, pycryptodome
  3.9.9 in its venv), `tshark`/`tcpdump`, `iw`, `wpa_supplicant`.
- Clients (built from the official w1.fi releases, sha256 recorded in
  `config/environment.txt`):
  - Unpatched A: `wpa_supplicant` v2.3 (no reinstall guard -> fully vulnerable).
  - Unpatched B: `wpa_supplicant` v2.6 (partial guard `!tk_to_set`; still
    vulnerable via the TPTK / all-zero-key path).
  - Patched: distro `wpa_supplicant` v2.10 (correct guard `ptk.installed`).

See `REPRODUCE.md` for the exact build and run steps, and
`config/environment.txt` for versions, hashes, and guard provenance.

## What is demonstrated

1. A normal four-way handshake captured and decrypted (M2 Step 6). All four
   EAPOL messages are present and the data frames decrypt with the PSK. See
   `captures/normal-handshake.pcap` and `analysis/`.

2. Key reinstallation reproduced on an unpatched client, and refused by a
   patched one, under an identical attack. This is the core before/after and
   the direct evidence for "the fix, not the cipher". See
   `analysis/reinstall-evidence-summary.txt` and `logs/*-attack.cl.log`.

3. An honest account of the simulated medium's limit: the tool's own on-air
   verdict line does not fire under `mac80211_hwsim` (explained below).

## Results

### Four-way handshake capture and decryption (Step 6)

`captures/normal-handshake.pcap` contains one clean handshake between the AP
(`02:00:00:00:00:00`) and the client (`02:00:00:00:01:00`):

| Msg | Dir | Key Info | Replay Ctr | Nonce | MIC |
|-----|-----|----------|-----------|-------|-----|
| 1 | AP -> STA | 0x008a | 1 | ANonce `a6ebb28b...` | not set |
| 2 | STA -> AP | 0x010a | 1 | SNonce `15686efc...` | set |
| 3 | AP -> STA | 0x13ca (Install bit set) | 2 | ANonce `a6ebb28b...` (same as Msg1) | set |
| 4 | STA -> AP | 0x030a | 2 | zero | set |

Decryption with `wpa-pwd` key `abcdefgh:testnetwork` turns the opaque
protected data frames into real traffic (100 LLC frames: MDNS, ICMPv6, ARP,
IGMP). Field dump in `analysis/handshake-eapol-fields.txt`; decrypted protocol
hierarchy in `analysis/decrypted-protocol-hierarchy.txt`.

### Key reinstallation: unpatched vs patched

The AP retransmits four-way Message 3 sixteen times during one association.
The victim's own `wpa_supplicant` debug log records what it does each time:

| Client | `Installing PTK to the driver` | `Do not re-install same PTK` | Behaviour |
|--------|-------------------------------|------------------------------|-----------|
| Unpatched v2.3 | 17 (1 initial + 16 reinstalls) | 0 | Reinstalls the PTK on every retransmitted Message 3 |
| Patched v2.10 | 1 (initial only) | 16 | Refuses every reinstall, still replies with Message 4 |

Both clients receive the identical 16 retransmissions and both still complete
the handshake 17 times; only the unpatched client reinstalls the key. This is
CVE-2017-13077 (pairwise key reinstallation in the four-way handshake), and the
patched client's guard firing 16 times is the fix. Raw logs:
`logs/u-2.3-attack.cl.log`, `logs/p-2.10-attack.cl.log`.

### Tool runs and the CVE mapping

`krack-test-client.py` was run against the unpatched clients with the variants
below. In every case the attack executed (the AP log shows the handshake and
the Message 3 retransmissions), and the client behaved as recorded above.

| Test | Command | CVE (indicative) | Observed |
|------|---------|------------------|----------|
| Pairwise key reinstall | `krack-test-client.py` | CVE-2017-13077 | Attack ran; reinstall confirmed by victim log (see table above) |
| Group key reinstall | `--group` | CVE-2017-13080 | Attack ran (`logs/u-2.3-group.ap.log`); no on-air verdict (see limitation) |
| Group key init RSC | `--gtkinit` | CVE-2017-13079/13081 | Attack ran (`logs/u-2.3-gtkinit.ap.log`, 44 group-key renewals with max/zero RSC); no on-air verdict |
| Broadcast replay check | `--replay-broadcast` | prerequisite | Attack ran (`logs/u-2.3-replaybc.ap.log`); no on-air verdict |
| TPTK / all-zero key | `--tptk` (v2.6) | CVE-2017-13077/13078 | Attack ran (`logs/tptk-2.6.ap.log`); no on-air verdict |

CVE identifiers are indicative; confirm each against the CVE record when
writing the report, as the exact identifier depends on the precise key and
handshake involved.

## Limitation of the simulated route (reported, not hidden)

`krack-test-client.py` decides "vulnerable" by watching the client's encrypted
data frames for an IV/packet-number reset (or an all-zero key) after it forces
a reinstallation. On `mac80211_hwsim` this verdict never fires: the client's
transmit IVs increase monotonically on the air even while `wpa_supplicant`
reinstalls the key (captured directly: IVs `0x2f, 0x30, 0x31 ... 0x3b` with no
reset). The reinstallation is a supplicant state-machine event; on real
hardware the driver resets the packet number when the key is installed, but the
shared in-kernel `mac80211` datapath used by two `hwsim` radios does not expose
that reset on the wire, so the sniffer sees no artifact to flag.

This matches the project plan's own caution that the `hwsim` route is "finicky"
and "only meaningful if the client stack is actually vulnerable", and its
recommendation to move the victim to a real old device for an unambiguous
tool verdict (or to use the `wifi-framework`, which hooks the client rather
than sniffing the shared medium). The reinstallation itself is not in doubt
here: it is proved directly from the victim's own key-install log, and the
patched client refusing the identical attack is the control.

A software-only tool verdict *is* obtainable with the **wifi-framework**, which
detects the all-zero-key reinstall (a changed key value, observable on the wire)
rather than the hidden PN reset. That lab is set up and run under
[`wifi-framework/`](wifi-framework/README.md): vulnerable `wpa_supplicant` 2.5
is flagged ("Client encrypted a frame with an all-zero key!"), patched 2.10 is
not - the framework returning the verdict with no hardware.

## Files

```
captures/
  normal-handshake.pcap          clean 4-way handshake, decryptable with abcdefgh:testnetwork
  attack-4way-retransmit.pcap    capture during the attack (initial handshake clear; retransmits are encrypted data)
logs/
  u-2.3-attack.cl.log            unpatched victim debug log: 16 PTK reinstalls
  p-2.10-attack.cl.log           patched victim debug log: 16 guard refusals
  u-2.3-attack.ap.log            AP log for the before run (16 Message 3 retransmissions)
  p-2.10-attack.ap.log           AP log for the after run
  u-2.3-default.ap.log           krack-test-client.py default (pairwise)
  u-2.3-group.ap.log             --group
  u-2.3-gtkinit.ap.log           --gtkinit
  u-2.3-replaybc.ap.log          --replay-broadcast
  tptk-2.6.ap.log                --tptk against v2.6
config/
  krack-hostapd.conf             the AP config used by krack-test-client.py (interface, SSID, PSK, CCMP)
  clean-ap-hostapd.conf          minimal hostapd config for the clean-handshake capture
  client.conf                    wpa_supplicant config for the victim (ssid/psk)
  environment.txt                host, kernel, client versions, tarball sha256, guard provenance
wifi-framework/                  software-only route: real tool verdict with no hardware (see its README)
analysis/
  handshake-eapol-fields.txt     per-message Key Info / Replay Counter / Nonce / MIC
  normal-handshake-eapol.txt     the four EAPOL frames
  decrypted-protocol-hierarchy.txt   tshark protocol hierarchy after decryption
  attack-eapol.txt               EAPOL frames seen in the attack capture
  reinstall-evidence-summary.txt the before/after PTK-install vs guard counts
```
