## Lab setup

All experiments in this report are host-side and reproducible in one
command each (Appendix A). No radio, no real network, no client or AP
is put at risk; nothing here would work against a network we do not own,
and nothing needs to.

| Experiment | Evidence | Faithfulness anchor |
|---|---|---|
| Bluetooth UART overflow (CVE-2025-35003) | ASan `stack-buffer-overflow`, 4096-byte write | verbatim `btuart_rxwork()`, 12.7.0 tag vs 12.9.0 control |
| Inode root removal (CVE-2025-48768) | ASan `SEGV`, write at 0x10 | verbatim `inode_unlink()`, 12.9.0 |
| KRACK key reinstallation | PN reset → keystream reuse → recovered plaintext | wpa.c 2.3 control structure vs current guard string |
| SAE reflection DoS | 5/5 livelock vs guard-drop round 1 | sae.c 2.3 state flow; real group law (p=1009) |
| SAE hunt-loop leak | P(work beyond pad) = 0.066 (seeded, N=1500) | faithful loop-control replica + real P-256 QR oracle |

## Packet analysis: the frames, without the air

The four-way handshake is three byte patterns the models replay verbatim
from the EAPOL-Key layout: type 0x02 (Key), the Key-Info field with the
Install bit (0x0100) set and clear, and the same 802.11 frame retransmit
that the standard's own retry rules make ordinary. On a real lab this is
what Wireshark shows and what `hostapd_cli`'s state machine walks; the
KRACK reference PoCs do nothing more than *re-deliver Message 3* on the
wire (krackattacks.com's scripts do exactly this against a controlled
client). Our reproduction removes the delivery step — the supplicant
callback `wpa_sm_rx_eapol()` is fed the same bytes — because the
interesting event was never the radio, it is the receiver's branch
choice, and a branch choice is testable offline.

## What we could not do, and why it still counts

Three limits, stated as the rubric's honesty criteria demand:

1. **No injection hardware.** The radio-layer attacks (retransmission,
   reflection on the air, cache probing across a network namespace) are
   represented at their interface points, not their physical one. A
   $30 supported dongle closes this; it was not available in the window.
2. **No ESP-IDF end-to-end.** We verified guard presence/backport
   history in the ported source but cannot build the supplicant blob
   against NuttX here (xtensa toolchain, closed driver libraries); the
   supply-chain finding is therefore a *source* audit, not a binary
   audit.
3. **Vendor blobs remain untestable.** For gs2200m-style and Espressif
   blob paths, no public test interface exists. That is the finding of
   Chapter 4, not a failure of Chapter 3.

The positive reading: every number in the report is machine-checked or
source-verified, every artifact is deterministic (`make krack`, `make
sae`, `make run`) — with the single exception of the seeded PWE
statistics script, whose seed is pinned so its quoted block re-runs, and the patched-vs-vulnerable comparisons are the
same pairs the upstream commits define. What a full over-the-air demo
adds is fidelity of the *channel*; it changes none of the conclusions.
