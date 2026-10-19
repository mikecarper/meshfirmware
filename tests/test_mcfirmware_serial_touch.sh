#!/usr/bin/env bash
# Production shell integration with fake touch/DFU/USB operations only.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT
script="$repo_root/mcfirmware.sh"
extract_function() {
	awk -v signature="$1() {" '$0 == signature { capture=1 } capture { print } capture && $0 == "}" { exit }' "$script"
}
for name in no_sudo_mode trigger_nrf52_1200_touch describe_nrf52_dfu_package wait_for_selected_nrf52_port \
	run_nrf52_dfu_package_buttonless; do
	definition="$(extract_function "$name")"
	[[ "$definition" == "$name() {"* ]]
	eval "$definition"
done
port="$tmp_dir/ttyACM0"
boot="$tmp_dir/ttyACM1"
link="$tmp_dir/selected-by-id"
touch "$port" "$boot" "$tmp_dir/app.zip"
ln -s "$port" "$link"
log="$tmp_dir/calls"
snapshot='{"identity":{"usb_serial":"SELECTED","usb_path":"PHYSICAL","vendor_id":"2886","product_id":"8044","interface":"00"}}'
USB_RESET_EXPECTED_IDENTITY="$snapshot"
MCFIRMWARE_NO_SUDO=1
preferred_flash_serial_port() { printf '%s\n' "$1"; }
nrf52_serial_port_access() { return 0; }
nrf52_selected_by_id_path() { printf '%s\n' "$link"; }
resolve_meshcore_serial_touch_tool() { printf '%s\n' "$repo_root/tools/meshcore_serial_touch.py"; }
pipx() {
	printf '%s\n' "$*" >> "$log"
	python3 - "$snapshot" "$mode" <<'PY'
import json,sys
r = {"status":"requested", "identity":json.loads(sys.argv[1])["identity"],
     "open_attempts":1, "control_attempted":True, "port_closed":True,
     "cleanup_review_required":False, "bootloader_verified":False,
     "application_bytes_written":0, "application_bytes_captured":0}
mode=sys.argv[2]
if mode=="uncertain": r["status"]="uncertain"
elif mode=="wrong_identity": r["identity"]["usb_serial"]="OTHER"
elif mode=="multiple_opens": r["open_attempts"]=2
elif mode=="cleanup": r["cleanup_review_required"]=True
elif mode=="not_closed": r["port_closed"]=False
elif mode=="false_dfu": r["bootloader_verified"]=True
elif mode=="no_controls": r["control_attempted"]=False
elif mode=="payload": r["application_bytes_written"]=1
print(json.dumps(r))
PY
}
for mode in requested uncertain; do
	: > "$log"
	trigger_nrf52_1200_touch "$port" > "$tmp_dir/stdout"
	[[ ! -s "$tmp_dir/stdout" && "$(wc -l < "$log")" -eq 1 ]]
	grep -Fq -- "--port $link --expected-identity" "$log"
	! grep -Fq -- '--owner-sudo' "$log"
done
MCFIRMWARE_NO_SUDO=0
: > "$log"
trigger_nrf52_1200_touch "$port"
grep -Fq -- '--owner-sudo' "$log"
MCFIRMWARE_NO_SUDO=1
for mode in wrong_identity multiple_opens cleanup not_closed false_dfu no_controls payload; do
	if trigger_nrf52_1200_touch "$port"; then
		echo "FAIL: unsafe touch result accepted: $mode" >&2; exit 1
	fi
done
echo 'PASS: touch uses original selection once and validates result/cleanup without claiming DFU'

# The descriptor gate must reject an application that rebooted and returned as
# the same physical USB radio, before any DFU payload is sent.
NRF52_BOARD_GUARD_PASSED=1
NRF52_SELECTED_BY_ID="$link"
NRF52_RUNTIME_SERIAL=SELECTED
NRF52_RUNTIME_PATH_STEM=PHYSICAL
nrf52_candidate_matches_identity() { return 0; }
nrf52_port_instance() { printf '%s\n' instance; }
nrf52_port_is_dfu_bootloader() { [[ "$1" == "$boot" ]]; }
serial_by_id_link_for_port() { printf '%s\n' "$link"; }
trigger_nrf52_1200_touch() { echo touch >> "$log"; }
wait_for_nrf52_bootloader_port() { printf '%s\n' "$returned"; }
run_nrfutil_dfu_serial_live_port() { echo dfu >> "$log"; }
: > "$log"
returned="$port"
if run_nrf52_dfu_package_buttonless "$tmp_dir/app.zip" "$port"; then
	echo 'FAIL: returned runtime application was accepted as a DFU bootloader' >&2; exit 1
fi
[[ "$(grep -c '^touch$' "$log")" -eq 1 ]]
! grep -q '^dfu$' "$log"
: > "$log"
returned="$boot"
run_nrf52_dfu_package_buttonless "$tmp_dir/app.zip" "$port"
[[ "$(grep -c '^touch$' "$log")" -eq 1 && "$(grep -c '^dfu$' "$log")" -eq 1 ]]
echo 'PASS: re-enumeration alone cannot authorize DFU; exact bootloader classification is required'

# Read-only selection reacquisition must keep its original stable identity and
# stop in a bounded time, without touching or trying arbitrary tty devices.
MCFIRMWARE_NRF52_SELECTION_WAIT_SECONDS=2
wait_count="$tmp_dir/waits"
: > "$wait_count"
selected_flash_serial_port() {
	if [[ "$(wc -l < "$wait_count")" -ge 1 ]]; then printf '%s\n' "$boot"; else return 1; fi
}
find_selected_nrf52_dfu_port_from_saved_identity() { [[ "$1" == "$link" ]]; return 1; }
sleep() { echo poll >> "$wait_count"; SECONDS=$((SECONDS + 1)); }
resolved="$(wait_for_selected_nrf52_port "$port")"
[[ "$resolved" == "$boot" && "$(wc -l < "$wait_count")" -eq 1 ]]
selected_flash_serial_port() { return 1; }
MCFIRMWARE_NRF52_SELECTION_WAIT_SECONDS=0
if wait_for_selected_nrf52_port "$port"; then echo 'FAIL: missing original selection accepted' >&2; exit 1; fi
echo 'PASS: disappearing original selection gets only a bounded read-only reacquisition'

python3 - "$repo_root" <<'PY'
from pathlib import Path
import hashlib,re,sys
root=Path(sys.argv[1]); source=(root/'mcfirmware.sh').read_text()
pin=re.search(r'^MESHCORE_SERIAL_TOUCH_TOOL_SHA256="([0-9a-f]{64})"$',source,re.M).group(1)
assert hashlib.sha256((root/'tools/meshcore_serial_touch.py').read_bytes().replace(b'\r\n',b'\n')).hexdigest()==pin
assert 'Application startup has not been verified' in source
body=re.search(r'^trigger_nrf52_1200_touch\(\) \{\n(.*?)^\}',source,re.M|re.S).group(1)
assert 'stty' not in body and 'exec 3' not in body
assert 'meshcore_serial_touch_tool_hash_matches "$partial_tool"' in source
assert 'dirname "$identity_helper"' in source
print('PASS: helper bytes are pinned and final DFU message does not claim application runtime')
PY
