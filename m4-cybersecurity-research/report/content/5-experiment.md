## Lab setup

The team plan specifies the reference environment: an isolated Linux lab
running Mathy Vanhoef's `krackattacks-scripts` (`krack-test-client.py`)
against a modified hostapd [@krack-scripts], with `mac80211_hwsim`
virtual WLAN interfaces and the `wifi-framework` [@wifi-framework] so
no physical radio is involved,
Kali Linux as the supported host, and a deliberately unpatched
`wpa_supplicant` 2.4-2.6 client as the before case; the w1.fi advisory
confirms those as exactly the versions with the severe TK
configurations (2.4/2.5 install an all-zero TK on the GTK sequence,
2.6 on the 4-way sequence) [@dv-w1fi-2017-1]. That is the lab we
prepared and the one we document here as the *attack-side* procedure;
our own executed evidence is the receiver-side reproduction below,
because this machine has no Linux kernel with `mac80211_hwsim` compiled
in (verified: the podman machine's kernel ships no hwsim module, and
neither the extra-modules RPM nor any fetch we attempted provides one
the module exists only on x86 Fedora kernels, and our VM host is
arm64). The plan anticipates this: no radios are required, and the
negative result (no real-AP experiment from *this* machine) is reported
rather than hidden.

What the executed procedure looks like, step by step, on a supported
host, so the demonstration is reproducible by the team on any x86
machine or VM with Kali:

1. `git clone https://github.com/vanhoefm/krackattacks-scripts && cd
 krackattacks-scripts/krackattack &&./build.sh &&./pysetup.sh`
 (compiles the patched hostapd; builds the scapy venv).
2. Start the virtual network: `wifi-framework` or manual
 `modprobe mac80211_hwsim radios=2`, wpa_supplicant (2.6 as the
 vulnerable before-case) attached to `wlan1`, hostapd
 (`hostapd/hostapd.conf`, SSID `testnetwork`, PSK `abcdefgh`) on
 `wlan0`.
3. Baseline capture: run `tcpdump -i wlan0 -w normal.pcapng` while the
 client associates; import into Wireshark, add the PSK (Edit ->
 Preferences -> Protocols -> IEEE 802.11 -> Decrypt Info: wpa-pwd
 `abcdefgh:testnetwork`), and annotate Messages 1-4: Key-Info bits,
 ANonce/SNonce, replay counters, MIC, and the Install bit in Message
 3, this is the figure for Chapter 2's handshake walkthrough.
4. Before case: `sudo./krack-test-client.py` (plus `--group`,
 `--tptk` for the 2.6 TPTK construction) and have the client request
 DHCP; the script blocks Message 4, retransmits Message 3, and
 reports whether the pairwise/group key is reinstalled (PN reset)
 the packet-number reset our receiver model reproduces is observed
 there directly in the client's TX IVs.
5. After case: repeat against current `wpa_supplicant`; the expected
 and reported outcome is negative, the patched client answers the
 retransmission without reinstalling, the guard behaviour in
 our fixed model build.

Then the receiver-side executed reproduction, which we *did* run here:

All experiments in this report are host-side and reproducible in one
command each (Appendix A). No radio, no real network, no client or AP
is put at risk; nothing here would work against a network we do not own,
and nothing needs to.

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
interesting event was never the radi

<!--raw-typst #figure(image("/figures/fourway.png", width: 78%), caption: [The reproduction's input surface: the message sequence, the Install bit's position, and the retransmission that the model replays directly into the receiver callback.]) <fig-lab-frames> -->
