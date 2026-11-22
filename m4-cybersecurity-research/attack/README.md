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
one would use a real old device, or the software-only `wifi-framework`, which is
outside the scope of this attack demo.

## Directory map

```
scripts/
  run-attack.sh                drives the pairwise four-way attack; prints PTK install/guard counts
  run-variant.sh               drives the group-key family (--group/--gtkinit/--replay-broadcast)
  capture-normal-handshake.sh  captures + decrypts one clean four-way handshake
krackattacks-scripts/          git submodule: Vanhoef's modified hostapd + krack-test-client.py
                               (pinned; `git submodule update --init` to fetch, then build per REPRODUCE.md)
config/
  client.conf                  victim wpa_supplicant config (ssid/psk)
  clean-ap-hostapd.conf        plain hostapd config for the baseline capture
  krack-hostapd.conf           AP config used by the KRACK harness
  environment.txt              host, kernel, client versions, tarball sha256, guard provenance
logs/
  u-2.3-attack.{cl,ap}.log     unpatched victim (PTK 17/0) + access-point log
  p-2.10-attack.{cl,ap}.log    patched victim (PTK 1/16) + access-point log
  u-2.3-group.{cl,ap}.log      unpatched group-key (GTK 25/0) + AP log
  p-2.10-group.{cl,ap}.log     patched group-key (GTK 1/24) + AP log
  u-2.3-gtkinit.{cl,ap}.log    unpatched --gtkinit run + AP log
  p-2.10-gtkinit.{cl,ap}.log   patched --gtkinit run + AP log
  {u-2.3,p-2.10}-replay-broadcast.{cl,ap}.log  broadcast-replay prerequisite
captures/
  normal-handshake.pcap        clean 4-way handshake, decryptable with abcdefgh:testnetwork
  attack-4way-retransmit.pcap  capture during the attack
analysis/
  reinstall-evidence-summary.txt   the before/after pairwise install-vs-guard counts
  group-family-evidence-summary.txt  --group / --gtkinit / --replay-broadcast results
  handshake-eapol-fields.txt       per-message Key Info / Replay Counter / Nonce / MIC
  normal-handshake-eapol.txt       the four EAPOL frames
  decrypted-protocol-hierarchy.txt tshark protocol hierarchy after decryption
  attack-eapol.txt                 EAPOL frames seen in the attack capture
```

See `REPRODUCE.md` for the build and run steps, and `config/environment.txt`
for versions, hashes and guard provenance.

## Group-key-family tests (included)

Besides the core pairwise four-way demonstration, the group-key family is
reproduced on the same 2.3-vs-2.10 lab via `scripts/run-variant.sh`: the
group-key handshake (`--group`, CVE-2017-13080), the GTK-init RSC test
(`--gtkinit`, CVE-2017-13079/-13081) and the `--replay-broadcast` prerequisite.
The before/after result is read the same way as the pairwise case — from the
victim's own `-dd -K` GTK install-vs-guard log, since the tool's on-air verdict
is a false negative under `mac80211_hwsim` (kernel broadcast-replay protection
drops the tool's probe). Headline: unpatched 2.3 reinstalls the group key 25×
(guard 0); patched 2.10 installs once and guards all 24. Full write-up in
`analysis/group-family-evidence-summary.txt`; raw logs under `logs/`.

The temporary-PTK variant (`--tptk`, `wpa_supplicant` 2.6) and the software-only
`wifi-framework` route are **not** part of this repository.
