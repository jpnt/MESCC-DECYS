#!/bin/bash
# run-variant.sh - group-key-family KRACK tests, capturing the tool's verdict.
# Usage: MODE=<flag> run-variant.sh <client-wpa_supplicant-binary> <out-prefix>
#   MODE=--replay-broadcast  does the client accept replayed broadcast frames? (run first)
#   MODE=--group             group-key-handshake reinstall (CVE-2017-13080)
#   MODE=--gtkinit           group key installed with zero/incorrect RSC (CVE-2017-13079/-13081)
# Writes <out-prefix>.ap.log (AP + verdict) and <out-prefix>.cl.log (victim).
# Env: KDIR, CONF, DUR (see README.md / REPRODUCE.md).

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CLIENT_BIN="${1:?usage: MODE=<flag> run-variant.sh <client-wpa_supplicant-binary> <out-prefix>}"
OUT="${2:?usage: MODE=<flag> run-variant.sh <client-wpa_supplicant-binary> <out-prefix>}"

KDIR="${KDIR:-$SCRIPT_DIR/../krackattacks-scripts/krackattack}"
CONF="${CONF:-$SCRIPT_DIR/../config/client.conf}"
DUR="${DUR:-60}"
MODE="${MODE:?set MODE to one of --replay-broadcast | --group | --gtkinit}"
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

echo "### CLIENT=$CLIENT_BIN OUT=$OUT MODE='$MODE' DUR=${DUR}s"
[ -x "$CLIENT_BIN" ]                || { echo "!! client binary not executable: $CLIENT_BIN"; exit 2; }
[ -f "$CONF" ]                      || { echo "!! client config not found: $CONF"; exit 2; }
[ -x "$KDIR/venv/bin/python" ]      || { echo "!! venv python not found under $KDIR (run pysetup.sh)"; exit 2; }
[ -f "$KDIR/krack-test-client.py" ] || { echo "!! krack-test-client.py not found in $KDIR"; exit 2; }

cleanup

# Fresh virtual radios so each run starts identically.
sudo modprobe -r mac80211_hwsim 2>/dev/null; sleep 1
sudo modprobe mac80211_hwsim radios=2;        sleep 2
sudo rfkill unblock all 2>/dev/null

# python -u (unbuffered) so the verdict line is written before the tool is pkill'd.
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

sudo "$CLIENT_BIN" -dd -K -D nl80211 -i "$IFACE_CL" -c "$CONF" > "$CLLOG" 2>&1 &
sleep 6

# Address the client and make it transmit so it answers the tool's broadcast ARP canaries.
sudo timeout 10 dhclient -v "$IFACE_CL" >/dev/null 2>&1 &
sleep 3
sudo ip addr add 192.168.100.2/24 dev "$IFACE_CL" 2>/dev/null
sudo ping -I "$IFACE_CL" -c "$DUR" -i 1 192.168.100.254 >/dev/null 2>&1 &

echo "-- test running for ${DUR}s"
sleep "$DUR"

cleanup

echo "== TOOL VERDICT ($MODE) for $OUT =="
grep -iE "this is (bad|good)|accepts replayed broadcast|reinstalls the group key|installs the group key|DOESN'T" "$APLOG" | sed 's/\x1b\[[0-9;]*m//g' | sort -u || true

ginst=$(grep -c 'WPA: Installing GTK to the driver'                       "$CLLOG")
gguard=$(grep -c 'WPA: Not reinstalling already in-use GTK to the driver' "$CLLOG")
echo "-- victim GTK log: install=$ginst guard=$gguard"
echo "   Logs: $CLLOG (victim), $APLOG (AP + tool verdict)."
