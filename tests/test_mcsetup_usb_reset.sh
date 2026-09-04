#!/usr/bin/env bash
# Hardware-free tests of the actual setup USB recovery functions.
# shellcheck disable=SC2317
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcsetup.sh"
extract_function() {
  awk -v signature="$1() {" '
    $0 == signature { capture = 1 }
    capture { print }
    capture && $0 == "}" { exit }
  ' "$script_path"
}
for name in confirm_setup_usb_reset remember_setup_usb_identity setup_usb_reset_helper_matches; do
  definition="$(extract_function "$name")"
  [[ "$definition" == "$name() {"* ]]
  # shellcheck disable=SC2294
  eval "$definition"
done

MESHCORE_USB_RESET_TOOL_SHA256="$(sed -n 's/^MESHCORE_USB_RESET_TOOL_SHA256="\([^"]*\)"$/\1/p' "$script_path")"
setup_usb_reset_helper_matches "${repo_root}/tools/meshcore_usb_reset.py"
echo "PASS: setup pins the actual shared USB reset helper"

call_log="$(mktemp)"
trap 'rm -f -- "$call_log"' EXIT
ensure_sudo_session() { printf '%s\n' 'ensure_sudo' >>"$call_log"; }
setup_usb_reset_helper_matches() { return "${hash_result:-0}"; }
sudo() {
  printf '%s\n' "$@" >>"$call_log"
  if [[ "${reset_result:-0}" != 0 ]]; then return "$reset_result"; fi
  printf '%s\n' '{"status":"reset","port":"/dev/ttyACM7","identity":{"usb_serial":"TEST-G2","usb_path":"1-1"}}'
}
timeout() { shift 2; "$@"; }
DEVICE_NAME=/dev/ttyACM0
SETUP_USB_RESET_HELPER=/fake/verified-helper.py
SETUP_USB_IDENTITY='{"status":"inspected","port":"/dev/ttyACM0","identity":{"usb_serial":"TEST-G2","usb_path":"1-1"}}'
saved_identity="$SETUP_USB_IDENTITY"

status=0
confirm_setup_usb_reset <<<n >/dev/null || status=$?
[[ "$status" == 1 && ! -s "$call_log" && "$DEVICE_NAME" == /dev/ttyACM0 ]]
echo "PASS: default/declined USB recovery never invokes sudo or changes the port"

confirm_setup_usb_reset <<<y >/dev/null
[[ "$DEVICE_NAME" == /dev/ttyACM7 ]]
grep -Fxq -- "$saved_identity" "$call_log"
grep -Fxq -- '--expected-identity' "$call_log"
grep -Fxq -- '--timeout' "$call_log"
[[ "$SETUP_USB_IDENTITY" == *'"status":"reset"'* ]]
echo "PASS: saved selection identity is required and the verified fresh port replaces the old one"

reset_result=1
status=0
confirm_setup_usb_reset <<<y >/dev/null 2>&1 || status=$?
[[ "$status" == 2 && "$DEVICE_NAME" == /dev/ttyACM7 ]]
echo "PASS: attempted recovery failure returns stop status, never a successful stale-port retry"

reset_result=0
hash_result=1
status=0
before="$(wc -c <"$call_log")"
confirm_setup_usb_reset <<<y >/dev/null 2>&1 || status=$?
[[ "$status" == 1 && "$(wc -c <"$call_log")" == "$before" ]]
echo "PASS: changed helper is refused before elevation"

hash_result=0
SETUP_USB_IDENTITY=''
status=0
confirm_setup_usb_reset <<<y >/dev/null 2>&1 || status=$?
[[ "$status" == 1 && "$(wc -c <"$call_log")" == "$before" ]]
echo "PASS: missing original identity cannot be recaptured from a potentially recycled tty"

python3 - "$script_path" <<'PY'
import sys
from pathlib import Path
script = Path(sys.argv[1]).read_text()
main = script[script.index("# Sync Time\n"):]
assert main.index("remember_setup_usb_identity") < main.index("refresh_detected_node_info")
assert 'echo " U) Reset USB connection (not a radio reboot)"' in script
assert 'if (( reset_status == 2 )); then return 2; fi' in script
assert 'if (( reset_status == 2 )); then exit 1; fi' in main
assert main.index("confirm_setup_usb_reset") < main.index('serial_cmd "time $host_epoch"')
PY
echo "PASS: setup captures identity before probes and offers safe recovery before clock writes"
