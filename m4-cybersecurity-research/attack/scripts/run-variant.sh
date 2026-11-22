#!/bin/bash
# run-variant.sh - drive the group-key-family KRACK tests (group-key handshake,
#                  group-key RSC init, and broadcast-replay prerequisite) against
#                  one wpa_supplicant client and capture the tool's verdict.
#
# Usage:
#   MODE=<flag> run-variant.sh <client-wpa_supplicant-binary> <out-prefix>
#     MODE=--replay-broadcast   prerequisite: does the client accept replayed
#                               broadcast frames at all? (run this FIRST)
#     MODE=--group              group-key-handshake reinstallation (CVE-2017-13080)
#     MODE=--gtkinit            group key installed with a zero/!incorrect RSC
#                               (CVE-2017-13079 / -13081)
#
# Why this is separate from run-attack.sh:
#   The pairwise four-way test (run-attack.sh) detects vulnerability by watching
#   the victim's *transmitted* frames for an IV/packet-number reset, which the
#   shared mac80211_hwsim datapath never exposes - so that test is read from the
#   victim's own key-install log instead. The group-key family detects
#   vulnerability differently: the tool sends the client a *replayed broadcast
#   ARP* (reused IV / low RSC) and watches for the client to REPLY to it. That
#   reply travels over the simulated medium like any frame, so for these variants
#   the tool DOES reach an on-air verdict under hwsim. This driver therefore
#   captures the tool's own verdict line, with the victim -dd -K log kept as
#   corroborating evidence.
#
#   krack-test-client.py prints its verdict with print(); run-attack.sh lost it
#   because Python block-buffers stdout when it is redirected to a file and the
#   tool is pkill'd before the buffer flushes. This driver runs the tool with
#   `python -u` (unbuffered) so each verdict line is written as it is produced.
#
# Environment (override by exporting before the call):
#   KDIR      krackattack dir with krack-test-client.py + venv + built hostapd
#             (default: <this script>/../krackattacks-scripts/krackattack)
#   CONF      victim wpa_supplicant config (default: ../config/client.conf)
#   IFACE_AP  access-point radio   (default: wlan0)
#   IFACE_CL  victim client radio  (default: wlan1)
#   DUR       seconds to let the test run after connect (default: 60; the tool
#             needs several ~2s intervals to declare a client patched)

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CLIENT_BIN="${1:?usage: MODE=<flag> run-variant.sh <client-wpa_supplicant-binary> <out-prefix>}"
OUT="${2:?usage: MODE=<flag> run-variant.sh <client-wpa_supplicant-binary> <out-prefix>}"

KDIR="${KDIR:-$SCRIPT_DIR/../krackattacks-scripts/krackattack}"
CONF="${CONF:-$SCRIPT_DIR/../config/client.conf}"
IFACE_AP="${IFACE_AP:-wlan0}"
IFACE_CL="${IFACE_CL:-wlan1}"
DUR="${DUR:-60}"
MODE="${MODE:?set MODE to one of --replay-broadcast | --group | --gtkinit}"

case "$OUT" in /*) : ;; *) OUT="$(pwd)/$OUT" ;; esac
APLOG="${OUT}.ap.log"      # hostapd + tool verdict (unbuffered)
CLLOG="${OUT}.cl.log"      # victim wpa_supplicant -dd -K

cleanup() {
  sudo pkill -f krack-test-client 2>/dev/null
  sudo pkill -x hostapd 2>/dev/null
  sudo pkill -f "wpa_supplicant .*$IFACE_CL" 2>/dev/null
  sudo pkill -f "dhclient" 2>/dev/null
  sudo pkill -f "ping -I $IFACE_CL" 2>/dev/null
  sudo rm -f "/run/wpa_supplicant/$IFACE_CL" 2>/dev/null
  sleep 1
}

echo "### CLIENT=$CLIENT_BIN OUT=$OUT MODE='$MODE' DUR=${DUR}s"
[ -x "$CLIENT_BIN" ]            || { echo "!! client binary not executable: $CLIENT_BIN"; exit 2; }
[ -f "$CONF" ]                  || { echo "!! client config not found: $CONF"; exit 2; }
[ -x "$KDIR/venv/bin/python" ]  || { echo "!! venv python not found under $KDIR (run pysetup.sh)"; exit 2; }
[ -f "$KDIR/krack-test-client.py" ] || { echo "!! krack-test-client.py not found in $KDIR"; exit 2; }

cleanup

# Fresh virtual radios every run so each run begins identically.
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1
sudo modprobe mac80211_hwsim radios=2;        sleep 2
sudo rfkill unblock all 2>/dev/null

# Start the modified-hostapd KRACK harness with UNBUFFERED python so the verdict
# line is captured even though the tool is pkill'd at cleanup.
cd "$KDIR" || exit 2
sudo PYTHONUNBUFFERED=1 ./venv/bin/python -u ./krack-test-client.py $MODE > "$APLOG" 2>&1 &

for _ in $(seq 1 40); do
  grep -q "AP-ENABLED" "$APLOG" && break
  sleep 0.5
done
if ! grep -q "AP-ENABLED" "$APLOG"; then
  echo "!! access point never enabled"; tail -5 "$APLOG"; cleanup; exit 1
fi
sleep 2
echo "-- access point up, starting victim client"

# Victim with full debug (-dd) and key logging (-K).
sudo "$CLIENT_BIN" -dd -K -D nl80211 -i "$IFACE_CL" -c "$CONF" > "$CLLOG" 2>&1 &
sleep 6

# Give the client an address and make it transmit so it is live on the medium
# and will answer the tool's broadcast ARP canaries if it is vulnerable.
sudo timeout 10 dhclient -v "$IFACE_CL" >/dev/null 2>&1 &
sleep 3
sudo ip addr add 192.168.100.2/24 dev "$IFACE_CL" 2>/dev/null
sudo ping -I "$IFACE_CL" -c "$DUR" -i 1 192.168.100.254 >/dev/null 2>&1 &

echo "-- test running for ${DUR}s"
sleep "$DUR"

cleanup

# The tool's own verdict (printed to the AP/tool log).
echo "== TOOL VERDICT ($MODE) for $OUT =="
grep -iE "this is (bad|good)|accepts replayed broadcast|reinstalls the group key|installs the group key|DOESN'T" "$APLOG" | sed 's/\x1b\[[0-9;]*m//g' | sort -u || true

# Corroborating victim-side GTK markers from the -dd -K log.
ginst=$(grep -c 'WPA: Installing GTK to the driver'                 "$CLLOG")
gguard=$(grep -c 'WPA: Not reinstalling already in-use GTK to the driver' "$CLLOG")
echo "-- victim GTK log: install=$ginst guard=$gguard"
echo "   Logs: $CLLOG (victim), $APLOG (AP + tool verdict)."
