# Reproducing the M2 lab

This lab demonstrates one thing: the four-way-handshake **pairwise** key
reinstallation (CVE-2017-13077). An unpatched `wpa_supplicant` 2.3 reinstalls
the pairwise key on every retransmitted Message 3; a patched `wpa_supplicant`
2.10 refuses. The proof is the victim's own `-dd -K` debug log — **2.3 = 17
installs / 0 guards, 2.10 = 1 install / 16 guards**.

Target: a Linux VM whose kernel ships `mac80211_hwsim` (Ubuntu 24.04's generic
kernel does, on aarch64 and x86_64). All steps run as a normal user with
`sudo`. No wireless hardware is needed. Run everything from this directory
(`attack/`).

The attack access point is pinned as a git submodule at
`attack/krackattacks-scripts`, so there is nothing to clone by hand. If you
cloned this repository without submodules, fetch it once:

```
git submodule update --init attack/krackattacks-scripts
```

(or clone the repo with `git clone --recurse-submodules ...`).

## 1. Dependencies

```
sudo apt update
sudo apt install build-essential libnl-3-dev libnl-genl-3-dev pkg-config \
  libssl-dev net-tools git sysfsutils python3-venv iw rfkill tshark tcpdump \
  isc-dhcp-client
```

## 2. Build the test access point (modified hostapd) and its venv

The source is the pinned `krackattacks-scripts` submodule; just build it:

```
cd krackattacks-scripts/krackattack
./build.sh        # builds ../hostapd/hostapd
./pysetup.sh      # creates venv/ with scapy + pycryptodome
cd ../..          # back to attack/
```

`disable-hwcrypto.sh` is not needed on `hwsim` (virtual radios do no hardware
offload). The AP config `krackattacks-scripts/hostapd/hostapd.conf` already sets
`interface=wlan0`, `ssid=testnetwork`, `wpa_passphrase=abcdefgh`, CCMP.

## 3. Build the victim clients (unpatched 2.3, patched 2.10)

The `wpa_supplicant` bundled in the repo is already patched, so it is not a
valid before-case. Build the genuine pre-patch release, and use the distro
build as the patched after-case:

```
# Unpatched - v2.3 (no reinstall guard). OpenSSL 3 is too new for 2.3, so use internal crypto.
cd ~; curl -fsSLO https://w1.fi/releases/wpa_supplicant-2.3.tar.gz
tar xf wpa_supplicant-2.3.tar.gz; cd wpa_supplicant-2.3/wpa_supplicant
cp defconfig .config
printf 'CONFIG_LIBNL32=y\nCONFIG_TLS=internal\nCONFIG_INTERNAL_LIBTOMMATH=y\n' >> .config
make -j2 wpa_supplicant
```

The patched after-case is the distro build, `/usr/sbin/wpa_supplicant` (v2.10,
guard `if (sm->ptk.installed)`).

The victim config lives in this repo at `config/client.conf` (SSID
`testnetwork`, PSK `abcdefgh`, RSN/CCMP); the scripts default to it.

## 4. Virtual radios and NetworkManager

```
# Keep NetworkManager from grabbing the virtual radios (reload, do not restart - keeps SSH up):
printf '[keyfile]\nunmanaged-devices=interface-name:wlan0;interface-name:wlan1;interface-name:mon*;interface-name:hwsim*\n' \
  | sudo tee /etc/NetworkManager/conf.d/99-unmanage-hwsim.conf
sudo systemctl reload NetworkManager

sudo modprobe mac80211_hwsim radios=2    # -> wlan0 (AP), wlan1 (client)
sudo rfkill unblock all
```

`scripts/run-attack.sh` re-creates the radios and does a clean reset at the
start of every run, so the two runs below begin identically.

## 5. Run the attack (before / after)

From this directory. The script drives the modified-hostapd KRACK harness,
starts the victim with `-dd -K`, generates traffic, and prints the
install-vs-guard counts read from the victim log:

```
# Before: unpatched 2.3 -> expect 17 installs / 0 guards (VULNERABLE)
scripts/run-attack.sh ~/wpa_supplicant-2.3/wpa_supplicant/wpa_supplicant logs/u-2.3-attack

# After: patched 2.10 -> expect 1 install / 16 guards (PATCHED)
scripts/run-attack.sh /usr/sbin/wpa_supplicant logs/p-2.10-attack
```

(The scripts default `KDIR`/`HOSTAPD` to the `krackattacks-scripts` submodule
built in step 2; override those env vars only if you built it elsewhere.)

Each call writes `<prefix>.cl.log` (victim, the evidence) and `<prefix>.ap.log`
(access point). Confirm the counts directly:

```
grep -c 'Installing PTK to the driver' logs/u-2.3-attack.cl.log   # 17
grep -c 'Do not re-install same PTK'   logs/u-2.3-attack.cl.log   # 0
grep -c 'Installing PTK to the driver' logs/p-2.10-attack.cl.log  # 1
grep -c 'Do not re-install same PTK'   logs/p-2.10-attack.cl.log  # 16
```

Both clients receive the same 16 retransmissions and both complete the
handshake each time; only the unpatched client reinstalls the key. That is the
whole before/after result.

> **hwsim caveat.** On `mac80211_hwsim` the tool's own on-air "...reinstalls
> the key" verdict does not fire: the shared in-kernel datapath never resets
> the on-air packet number when the key is reinstalled. The victim `-dd -K`
> log counted above is the authoritative evidence. See
> `README.md` ("Limitation of the simulated route").

## 6. Capture and decrypt a nominal handshake

A single call brings up a plain (unmodified) AP, captures one clean four-way
handshake, and decrypts it with the PSK:

```
scripts/capture-normal-handshake.sh captures/normal-handshake.pcap
```

It prints the four EAPOL messages and the decrypted protocol hierarchy. In the
Wireshark GUI the same key is added under Edit > Preferences > Protocols >
IEEE 802.11 > Decryption keys, type `wpa-pwd`, value `abcdefgh:testnetwork`.

## Optional / supplementary

The core demonstration above is the pairwise four-way reinstallation on 2.3 vs
2.10. Logs from supplementary runs that are **not** part of it — the group-key
handshake (`--group`), the `--gtkinit` and `--replay-broadcast` variants, the
temporary-PTK path (`--tptk`) against `wpa_supplicant` 2.6, and a software-only
tool verdict via the `wifi-framework` — are kept outside this directory under
`../lab/supplementary/` (`logs/` and `wifi-framework/`). To reproduce one, pass
its flag through the script's `MODE` variable, e.g.
`MODE=--group scripts/run-attack.sh ...`.
