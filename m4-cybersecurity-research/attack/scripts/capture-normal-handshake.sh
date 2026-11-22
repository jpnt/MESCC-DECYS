#!/bin/bash
# capture-normal-handshake.sh - capture one clean WPA2 four-way handshake with a
# plain (unmodified) AP and decrypt it with the PSK. No attack involved; this
# just shows the capture/decrypt pipeline is correct (report Section 5.4).
# Usage: capture-normal-handshake.sh [out.pcap]   (default: normal-handshake.pcap)
# Env: HOSTAPD, CONF, APCONF, SECS, PSK, SSID (see README.md / REPRODUCE.md).

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OUT="${1:-$(pwd)/normal-handshake.pcap}"
case "$OUT" in /*) : ;; *) OUT="$(pwd)/$OUT" ;; esac

HOSTAPD="${HOSTAPD:-$SCRIPT_DIR/../krackattacks-scripts/hostapd/hostapd}"
CONF="${CONF:-$SCRIPT_DIR/../config/client.conf}"
APCONF="${APCONF:-$SCRIPT_DIR/../config/clean-ap-hostapd.conf}"
SECS="${SECS:-20}"
PSK="${PSK:-abcdefgh}"
SSID="${SSID:-testnetwork}"
IFACE_AP=wlan0
IFACE_CL=wlan1
IFACE_MON=mon0

cleanup() {
  sudo pkill -x hostapd 2>/dev/null
  sudo pkill -f "wpa_supplicant .*$IFACE_CL" 2>/dev/null
  sudo pkill -x tcpdump 2>/dev/null
  sudo iw dev "$IFACE_MON" del 2>/dev/null
  sudo rm -f "/run/wpa_supplicant/$IFACE_CL" 2>/dev/null
  sleep 1
}

[ -x "$HOSTAPD" ] || { echo "!! hostapd not executable: $HOSTAPD"; exit 2; }
[ -f "$CONF" ]    || { echo "!! client config not found: $CONF"; exit 2; }
[ -f "$APCONF" ]  || { echo "!! AP config not found: $APCONF"; exit 2; }

cleanup
sudo rfkill unblock all 2>/dev/null

sudo ip link set "$IFACE_AP" down
sudo "$HOSTAPD" "$APCONF" >/dev/null 2>&1 &
sleep 3
sudo ip addr add 192.168.100.254/24 dev "$IFACE_AP" 2>/dev/null
sudo ip link set "$IFACE_AP" up

sudo iw dev "$IFACE_AP" interface add "$IFACE_MON" type monitor
sudo ip link set "$IFACE_MON" up
sudo tcpdump -i "$IFACE_MON" -w "$OUT" >/dev/null 2>&1 &
sleep 1

sudo /usr/sbin/wpa_supplicant -D nl80211 -i "$IFACE_CL" -c "$CONF" >/dev/null 2>&1 &
sleep 4
sudo ip addr add 192.168.100.2/24 dev "$IFACE_CL" 2>/dev/null
sudo ping -I "$IFACE_CL" -c "$SECS" -i 1 192.168.100.254 >/dev/null 2>&1 &

echo "-- capturing for ${SECS}s into $OUT"
sleep "$SECS"
cleanup

echo "== EAPOL messages in the capture =="
tshark -r "$OUT" -Y eapol 2>/dev/null

echo "== decrypted protocol hierarchy (key wpa-pwd $PSK:$SSID) =="
tshark -r "$OUT" -o wlan.enable_decryption:TRUE \
  -o "uat:80211_keys:\"wpa-pwd\",\"$PSK:$SSID\"" -q -z io,phs 2>/dev/null

echo
echo "In Wireshark, add the same key under Edit > Preferences > Protocols >"
echo "IEEE 802.11 > Decryption keys: type wpa-pwd, value $PSK:$SSID."
echo "Capture written to $OUT."
