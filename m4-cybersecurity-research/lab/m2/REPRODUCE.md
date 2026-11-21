# Rebuilding the M2 lab

Target: a Linux VM whose kernel ships `mac80211_hwsim` (Ubuntu 24.04's generic
kernel does, on both aarch64 and x86_64). All steps run as a normal user with
`sudo`. No wireless hardware is needed.

## 1. Dependencies

```
sudo apt update
sudo apt install build-essential libnl-3-dev libnl-genl-3-dev pkg-config \
  libssl-dev net-tools git sysfsutils python3-venv iw rfkill tshark tcpdump \
  isc-dhcp-client
```

## 2. Build the test access point (modified hostapd) and its venv

```
git clone https://github.com/vanhoefm/krackattacks-scripts.git
cd krackattacks-scripts/krackattack
./build.sh        # builds ../hostapd/hostapd
./pysetup.sh      # creates venv/ with scapy + pycryptodome
```

`disable-hwcrypto.sh` is not needed on `hwsim` (virtual radios do no hardware
offload). The AP config `hostapd/hostapd.conf` already sets `interface=wlan0`,
`ssid=testnetwork`, `wpa_passphrase=abcdefgh`, CCMP.

## 3. Build the victim clients

The `wpa_supplicant` bundled in the repo is already patched (2.7-devel, guard
`if (sm->ptk.installed)`), so it is NOT a valid before-case. Build genuine
pre-patch releases instead:

```
# Unpatched A - v2.3 (no guard). OpenSSL 3 is too new for 2.3, so use internal crypto.
cd ~; curl -fsSLO https://w1.fi/releases/wpa_supplicant-2.3.tar.gz
tar xf wpa_supplicant-2.3.tar.gz; cd wpa_supplicant-2.3/wpa_supplicant
cp defconfig .config
printf 'CONFIG_LIBNL32=y\nCONFIG_TLS=internal\nCONFIG_INTERNAL_LIBTOMMATH=y\n' >> .config
make -j2 wpa_supplicant

# Unpatched B - v2.6 (partial guard !tk_to_set; the TPTK / all-zero-key case). Builds against OpenSSL 3.
cd ~; curl -fsSLO https://w1.fi/releases/wpa_supplicant-2.6.tar.gz
tar xf wpa_supplicant-2.6.tar.gz; cd wpa_supplicant-2.6/wpa_supplicant
cp defconfig .config; echo 'CONFIG_LIBNL32=y' >> .config
make -j2 wpa_supplicant
```

The patched after-case is the distro build, `/usr/sbin/wpa_supplicant` (v2.10).

Client config `~/client.conf`:

```
ctrl_interface=/var/run/wpa_supplicant
network={
    ssid="testnetwork"
    psk="abcdefgh"
    key_mgmt=WPA-PSK
    proto=RSN
    pairwise=CCMP
    group=CCMP
}
```

## 4. Virtual radios and NetworkManager

```
# Keep NetworkManager from grabbing the virtual radios (reload, do not restart - keeps SSH up):
printf '[keyfile]\nunmanaged-devices=interface-name:wlan0;interface-name:wlan1;interface-name:mon*;interface-name:hwsim*\n' \
  | sudo tee /etc/NetworkManager/conf.d/99-unmanage-hwsim.conf
sudo systemctl reload NetworkManager

sudo modprobe mac80211_hwsim radios=2    # -> wlan0 (AP), wlan1 (client)
sudo rfkill unblock all
```

Before each run, reset cleanly:

```
sudo pkill -f krack-test-client; sudo pkill -x hostapd
sudo pkill -f -- '-i wlan1 -c'; sudo pkill -f dhclient; sudo pkill -f 'ping -I wlan1'
sudo rm -f /run/wpa_supplicant/wlan1
sudo modprobe -r mac80211_hwsim; sleep 1; sudo modprobe mac80211_hwsim radios=2; sleep 2
sudo rfkill unblock all
```

## 5. Run the KRACK test (before / after)

In the `krackattack` directory:

```
sudo ./venv/bin/python ./krack-test-client.py            # or --group, --tptk, --gtkinit, --replay-broadcast
```

Wait for "Ready. Connect to this Access Point...", then in another shell start
the victim and give it an address (persistent dhclient; the single-shot
`-1` form can miss its window under the attack):

```
sudo <path-to>/wpa_supplicant -d -D nl80211 -i wlan1 -c ~/client.conf   # -d to log key installs
sudo dhclient wlan1
sudo ping -I wlan1 192.168.100.254     # generate client traffic
```

Read the victim's reinstall behaviour directly from its `-d` log:

```
grep -c 'Installing PTK to the driver' <client log>   # unpatched: many; patched: 1
grep -c 'Do not re-install same PTK'   <client log>   # unpatched: 0;    patched: many
```

Note: on `hwsim` the tool's own "...reinstalls the pairwise key" verdict does
not fire, because the shared `mac80211` datapath does not reset the on-air
packet number when the key is reinstalled. The victim `-d` log is the
authoritative evidence here; for a tool verdict use a real old device or the
`wifi-framework`. See README.md ("Limitation of the simulated route").

## 6. Capture and decrypt a normal handshake

Use a plain AP (no attack) so the handshake is clean:

```
cat >/tmp/ap.conf <<'CONF'
interface=wlan0
ssid=testnetwork
hw_mode=g
channel=1
wpa=2
wpa_passphrase=abcdefgh
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
CONF
sudo ip link set wlan0 down
sudo ~/krackattacks-scripts/hostapd/hostapd /tmp/ap.conf &
sudo ip addr add 192.168.100.254/24 dev wlan0; sudo ip link set wlan0 up
sudo iw dev wlan0 interface add mon0 type monitor; sudo ip link set mon0 up
sudo tcpdump -i mon0 -w normal-handshake.pcap &
sudo /usr/sbin/wpa_supplicant -D nl80211 -i wlan1 -c ~/client.conf &
sudo ip addr add 192.168.100.2/24 dev wlan1
# let the client associate and chatter, then stop tcpdump
```

Decrypt with the PSK:

```
tshark -r normal-handshake.pcap -Y eapol                      # all four messages
tshark -r normal-handshake.pcap -o wlan.enable_decryption:TRUE \
  -o 'uat:80211_keys:"wpa-pwd","abcdefgh:testnetwork"' -q -z io,phs
```

In the Wireshark GUI the same key is added under Edit > Preferences >
Protocols > IEEE 802.11 > Decryption keys, type `wpa-pwd`, value
`abcdefgh:testnetwork`.
