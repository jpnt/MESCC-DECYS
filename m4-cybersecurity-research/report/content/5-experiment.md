## Lab setup

The team plan specifies the reference environment: an isolated Linux lab
running Mathy Vanhoef's `krackattacks-scripts` (`krack-test-client.py`)
against a modified hostapd [@krack-scripts], with `mac80211_hwsim`
virtual WLAN interfaces and the `wifi-framework` [@wifi-framework] so
no physical radio is involved, and a deliberately unpatched
`wpa_supplicant` 2.3-2.6 client as the before case; the w1.fi advisory
confirms 2.4-2.6 as exactly the versions with the severe TK
configurations (2.4/2.5 install an all-zero TK on the GTK sequence,
2.6 on the 4-way sequence via the TPTK construction) [@dv-w1fi-2017-1].

We executed this lab. It was at first only described, because the
earlier project machine was arm64 with no `mac80211_hwsim` in its
kernel; it has since been run in full on an isolated Ubuntu 24.04
aarch64 VM whose generic kernel does carry the module. The configuration
files, packet captures, tool output and client logs are collected under
`lab/m2/`. No real network is touched: the modified hostapd only serves
an SSID we define, on virtual radios sharing a simulated medium inside
one VM, and the tool requires the passphrase, so it only tests a network
we control.

The procedure, reproducible by the team on any Ubuntu or Kali host
(x86 or arm64) whose kernel ships `mac80211_hwsim`:

1. `git clone https://github.com/vanhoefm/krackattacks-scripts && cd krackattacks-scripts/krackattack && ./build.sh && ./pysetup.sh` compiles the modified hostapd and builds the Python 3 scapy venv.
2. `modprobe mac80211_hwsim radios=2` gives two virtual radios: the modified hostapd (`hostapd.conf`, SSID `testnetwork`, PSK `abcdefgh`, CCMP) on `wlan0`, and the victim `wpa_supplicant` on `wlan1`. The before case is built from the official w1.fi releases (2.3, no guard; 2.6, the partial `!tk_to_set` guard); the after case is a current `wpa_supplicant` 2.10.
3. Baseline capture: a plain hostapd on `wlan0` plus a monitor interface, with `tcpdump` on the monitor while the client associates once. The capture holds all four EAPOL messages and decrypts in Wireshark with the PSK (`wpa-pwd abcdefgh:testnetwork`). We annotate Messages 1-4: Key-Info bits, ANonce/SNonce, replay counters, MIC, and the Install bit in Message 3; this is the figure for Chapter 2's handshake walkthrough.
4. Before case: `sudo ./krack-test-client.py` (plus `--group`, `--gtkinit`, `--replay-broadcast`, and `--tptk` for the 2.6 TPTK construction). The script blocks Message 4, retransmits Message 3, and the victim reinstalls the key.
5. After case: repeat against the current `wpa_supplicant`; the patched client answers the retransmission without reinstalling.

### Executed results

The clean four-way handshake was captured and decrypted. All four EAPOL
messages are present; Message 3 carries the Install bit and reuses the
Message 1 ANonce, the replay counters increment 1, 1, 2, 2, and with the
PSK Wireshark turns the client's protected data frames back into
plaintext (MDNS, ICMPv6, ARP). This is the packet-level figure the rest
of the report builds on.

The reinstallation itself is read directly from the victim's own key
log. Under an identical attack, sixteen Message 3 retransmissions, the
unpatched `wpa_supplicant` 2.3 installed the PTK seventeen times (one
initial install and sixteen reinstalls) and refused none, while the
patched 2.10 installed once and refused all sixteen (`WPA: Do not
re-install same PTK to the driver`) yet still answered with Message 4.
The same sixteen-for-sixteen attack, opposite outcomes: this is the fix,
not the cipher.

The simulated medium has one honest limit. `krack-test-client.py` reaches
its verdict by watching the client's data frames for a packet-number
reset, and on `mac80211_hwsim` that reset is not visible on the air: the
shared in-kernel datapath keeps the transmit counter incrementing
monotonically even while the supplicant reinstalls the key, so the script
prints no verdict. The reinstallation is not in doubt (the victim log
above proves it); the tool's own detector simply needs an artifact the
virtual medium hides. The plan anticipated this, recommending a real
device or the `wifi-framework` for an unambiguous tool verdict.

The `wifi-framework` [@wifi-framework] supplies that in software. Its
`example-krack-zero-key` test resends Message 3 and tries to decrypt the
client's reply with an all-zero key; a changed key value, unlike a
packet-number reset, is observable on the wire. Against a vulnerable
`wpa_supplicant` 2.5 it reports `Client encrypted a frame with an
all-zero key!`; against the patched 2.10 the identical attack yields
nothing. This is the key-reinstallation verdict obtained with no radio at
all, and it corroborates the receiver-side model below.

Alongside the executed lab we also built a receiver-side model
reproduction, reproducible in one command each (Appendix A). No radio,
no real network, no client or AP is put at risk; nothing here would work
against a network we do not own, and nothing needs to.

| Experiment | Evidence | Faithfulness anchor |
|---|---|---|
| KRACK key reinstallation | keystream reuse + known-plaintext recovery | wpa.c 2.3 control structure vs current guard string |
| SAE reflection DoS | 5/5 livelock vs guard-drop round 1 | sae.c 2.3 state flow; real group law (p=1009) |
| SAE hunt-loop leak | P(work beyond pad) = 0.066 (seeded, N=1500, per-password) | faithful loop-control replica + real P-256 QR oracle |

## Packet analysis: the frames, without the air

The four-way handshake is three byte patterns the models replay verbatim
from the EAPOL-Key layout: type 0x02 (Key), the Key-Info field with the
Install bit (0x0100) set and clear, and the same 802.11 frame retransmit
that the standard's own retry rules make ordinary. On a real lab this is
what Wireshark shows and what `hostapd_cli`'s state machine walks; the
KRACK reference PoCs do nothing more than *re-deliver Message 3* on the
wire (krackattacks.com's scripts reproduce this against a controlled
client). Our reproduction removes the delivery step, the supplicant
callback `wpa_sm_rx_eapol()` is fed the same bytes, because the
interesting event was never the radio but the receiver's response to it.

<!--raw-typst #figure(image("/figures/fourway.png", width: 78%), caption: [The reproduction's input surface: the message sequence, the Install bit's position, and the retransmission that the model replays directly into the receiver callback.]) <fig-lab-frames> -->
