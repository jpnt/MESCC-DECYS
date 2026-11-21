# M2 - KRACK reproduction lab (executed)

This directory is a self-contained, reproducible demonstration of one attack:
the **four-way-handshake pairwise key reinstallation, CVE-2017-13077**. An
unpatched `wpa_supplicant` 2.3 reinstalls the pairwise key on every
retransmitted Message 3; a patched `wpa_supplicant` 2.10 refuses the identical
attack. A normal four-way handshake is also captured and decrypted, to
establish the baseline. Everything a teammate needs to reproduce it lives here;
`REPRODUCE.md` is the step-by-step.

No real network is touched. The access point is Mathy Vanhoef's modified
`hostapd` from `krackattacks-scripts`, running on two virtual radios
(`mac80211_hwsim`) that share a simulated medium inside one VM. It only tests a
client that connects to an SSID we define with a passphrase we set.

## What is demonstrated

The attacker forces the access point to retransmit four-way **Message 3**. The
victim's own `wpa_supplicant -dd -K` debug log records, for each one, whether it
reinstalled the pairwise key (`Installing PTK to the driver`) or refused
(`Do not re-install same PTK`). Two client builds receive the identical attack:

| Client | `Installing PTK` | `Do not re-install same PTK` | Behaviour |
|--------|------------------|------------------------------|-----------|
| **Unpatched v2.3** | **17** (1 initial + 16 reinstalls) | **0** | Reinstalls the key on every retransmission → **vulnerable** |
| **Patched v2.10** | **1** (initial only) | **16** | Refuses every reinstall, still completes the handshake → **patched** |

Both clients get the same 16 retransmissions and both complete the handshake
each time; only the unpatched client reinstalls the key. The single factor that
changes the outcome is the reinstallation guard — the fix, not the cipher (CCMP
is unchanged throughout). Raw evidence: `logs/u-2.3-attack.cl.log`,
`logs/p-2.10-attack.cl.log`, summarised in
`analysis/reinstall-evidence-summary.txt`.

A clean baseline handshake is in `captures/normal-handshake.pcap`: all four
EAPOL messages present, and the protected data frames decrypt with the PSK
(`wpa-pwd` key `abcdefgh:testnetwork`) back to 100 LLC frames of ordinary
traffic. Per-message field dump in `analysis/handshake-eapol-fields.txt`.

## Limitation of the simulated route (reported, not hidden)

On `mac80211_hwsim` the attack tool's own on-air "...reinstalls the key" verdict
does not fire: the shared in-kernel datapath keeps the transmit packet number
incrementing monotonically even while `wpa_supplicant` reinstalls the key, so
the sniffer sees no reset to flag. The reinstallation itself is not in doubt —
it is proved directly from the victim's own key-install log, with the patched
client refusing the identical attack as the control. For an on-air tool verdict
one would use a real old device, or the software-only `wifi-framework` (kept
outside this attack demo under `../lab/supplementary/wifi-framework/`).

## Directory map

```
scripts/
  run-attack.sh                drives the attack against one client; prints install/guard counts
  capture-normal-handshake.sh  captures + decrypts one clean four-way handshake
krackattacks-scripts/          git submodule: Vanhoef's modified hostapd + krack-test-client.py
                               (pinned; `git submodule update --init` to fetch, then build per REPRODUCE.md)
config/
  client.conf                  victim wpa_supplicant config (ssid/psk)
  clean-ap-hostapd.conf        plain hostapd config for the baseline capture
  krack-hostapd.conf           AP config used by the KRACK harness
  environment.txt              host, kernel, client versions, tarball sha256, guard provenance
logs/
  u-2.3-attack.{cl,ap}.log     unpatched victim (17/0) + access-point log
  p-2.10-attack.{cl,ap}.log    patched victim (1/16) + access-point log
captures/
  normal-handshake.pcap        clean 4-way handshake, decryptable with abcdefgh:testnetwork
  attack-4way-retransmit.pcap  capture during the attack
analysis/
  reinstall-evidence-summary.txt   the before/after install-vs-guard counts
  handshake-eapol-fields.txt       per-message Key Info / Replay Counter / Nonce / MIC
  normal-handshake-eapol.txt       the four EAPOL frames
  decrypted-protocol-hierarchy.txt tshark protocol hierarchy after decryption
  attack-eapol.txt                 EAPOL frames seen in the attack capture
```

See `REPRODUCE.md` for the build and run steps, and `config/environment.txt`
for versions, hashes and guard provenance.

## Supplementary material (moved out of this directory)

`attack/` holds only the core pairwise demonstration. The group-key handshake,
the `--gtkinit`, `--replay-broadcast` and `--tptk` (temporary-PTK, v2.6)
variants, the extra `wpa_supplicant` 2.6 client, and the software-only
`wifi-framework` route are **not** part of it. Their logs and material have been
relocated to `../lab/supplementary/` (`logs/` and `wifi-framework/`) for
reference. `REPRODUCE.md` explains how to re-run a variant via the script's
`MODE` variable.
