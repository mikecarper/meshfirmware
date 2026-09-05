#!/usr/bin/env bash
# Run production recovery functions with fake USB/sudo operations; no hardware I/O.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcfirmware.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT
sudo_log="$tmp_dir/sudo.log"
DEVICE_PORT_FILE="$tmp_dir/port"
DEVICE_PORT_NAME_FILE="$tmp_dir/name"
printf '%s\n' selected-radio > "$DEVICE_PORT_NAME_FILE"

extract_function() {
	awk -v signature="$1() {" '
		$0 == signature { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
}

for function_name in no_sudo_mode reset_selected_usb_connection \
	selected_flash_serial_port refresh_usb_recovered_esptool_args \
	capture_selected_usb_reset_identity usb_reset_host_controller \
	require_safe_usb_reset_host; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "$function_name() {"* ]]
	eval "$definition"
done

expect_failure() {
	if "$@"; then
		echo "FAIL: unexpectedly succeeded: $*" >&2
		exit 1
	fi
}

uname() { printf '%s\n' Linux; }
resolve_meshcore_usb_reset_tool() { printf '%s\n' /fake/verified-helper.py; }
nrf52_selected_by_id_path() { printf '%s\n' /fake/by-id/selected-radio; }
readlink() { printf '%s\n' "${TEST_LIVE_PORT:-/dev/tty}"; }
stop_serial_locking_services() { echo 'FAIL: USB reset stopped a service' >&2; exit 88; }
terminate_serial_locking_processes() { echo 'FAIL: USB reset killed a process' >&2; exit 89; }
timeout() { shift 2; "$@"; }
sudo() {
	printf '%s\n' "$*" >> "$sudo_log"
	case "${TEST_RESET_MODE:-success}" in
		busy) echo 'Selected radio is busy' >&2; return 1 ;;
		timeout) return 124 ;;
		wrong-device)
			printf '%s\n' '{"status":"reset","port":"/dev/tty","identity":{"usb_serial":"OTHER","usb_path":"1-1"}}'
			;;
		*) printf '%s\n' '{"status":"reset","port":"/dev/tty","identity":{"usb_serial":"ABC","usb_path":"1-1"}}' ;;
	esac
}

fresh_selection() {
	MCFIRMWARE_NO_SUDO=0
	USB_RESET_FAILED=0
	USB_RESET_RECOVERED_PORT=""
	USB_RESET_EXPECTED_IDENTITY='{"status":"inspected","identity":{"usb_serial":"ABC","usb_path":"1-1"}}'
	DEVICE_PORT=/dev/ttyACM-old
	DEVICE_NAME="$DEVICE_PORT"
	TEST_RESET_MODE=success
	TEST_LIVE_PORT=/dev/tty
	printf '%s\n' "$DEVICE_PORT" > "$DEVICE_PORT_FILE"
	: > "$sudo_log"
}

fresh_selection
MCFIRMWARE_NO_SUDO=1
expect_failure reset_selected_usb_connection "$DEVICE_PORT"
[[ ! -s "$sudo_log" && "$USB_RESET_FAILED" == 0 ]]
echo 'PASS: no-sudo mode refuses USB reset without privilege attempts'

fresh_selection
USB_RESET_EXPECTED_IDENTITY=""
expect_failure reset_selected_usb_connection "$DEVICE_PORT"
[[ ! -s "$sudo_log" ]]
echo 'PASS: missing pre-probe identity refuses reset'

fresh_selection
USB_RESET_EXPECTED_IDENTITY='{"status":"inspected","host_controller":"dwc_otg","identity":{"usb_serial":"ABC","usb_path":"1-1"}}'
expect_failure reset_selected_usb_connection "$DEVICE_PORT"
[[ ! -s "$sudo_log" && "$USB_RESET_FAILED" == 0 ]]
echo 'PASS: unsafe Raspberry Pi controller is rejected before sudo or USB I/O'

fresh_selection
reset_selected_usb_connection "$DEVICE_PORT" > "$tmp_dir/stdout"
[[ ! -s "$tmp_dir/stdout" ]]
[[ "$DEVICE_PORT" == /dev/tty && "$(<"$DEVICE_PORT_FILE")" == /dev/tty ]]
[[ "$(<"$DEVICE_PORT_NAME_FILE")" == selected-radio ]]
[[ "$USB_RESET_RECOVERED_PORT" == /dev/tty && "$USB_RESET_FAILED" == 0 ]]
grep -Fq -- '--port /dev/tty --timeout 10 --expected-identity' "$sudo_log"
echo 'PASS: exact returned port replaces stale tty without replacing stable identity'
echo 'PASS: recovery chatter never contaminates stdout'

attempt_args=(--port /dev/ttyACM-old --before no-reset read-mac)
refresh_usb_recovered_esptool_args attempt_args
[[ "${attempt_args[1]}" == /dev/tty ]]
[[ -z "$USB_RESET_RECOVERED_PORT" ]]
# A subsequent valid application-to-ROM handoff must keep its fresh port.
attempt_args=(--port /dev/ttyACM-ROM read-mac)
refresh_usb_recovered_esptool_args attempt_args
[[ "${attempt_args[1]}" == /dev/ttyACM-ROM ]]
USB_RESET_RECOVERED_PORT=/dev/tty
attempt_args=(--port=/dev/ttyACM-old read-mac)
refresh_usb_recovered_esptool_args attempt_args
[[ "${attempt_args[0]}" == --port=/dev/tty ]]
USB_RESET_RECOVERED_PORT=/dev/tty
attempt_args=(read-mac)
expect_failure refresh_usb_recovered_esptool_args attempt_args
echo 'PASS: retry arguments follow the saved identity instead of the old tty'
echo 'PASS: consumed USB recovery cannot overwrite a later ROM handoff port'

for failure_mode in busy timeout wrong-device; do
	fresh_selection
	TEST_RESET_MODE="$failure_mode"
	expect_failure reset_selected_usb_connection "$DEVICE_PORT"
	[[ "$USB_RESET_FAILED" == 1 && -z "$USB_RESET_RECOVERED_PORT" ]]
	[[ "$(<"$DEVICE_PORT_FILE")" == /dev/ttyACM-old ]]
	expect_failure selected_flash_serial_port /dev/ttyACM-old
done
echo 'PASS: busy, timeout, and wrong-device results all block stale-port flashing'

fresh_selection
TEST_LIVE_PORT=/dev/ttyACM-wrong
# The stable identity no longer exists; no ioctl is attempted.
expect_failure reset_selected_usb_connection "$DEVICE_PORT"
[[ ! -s "$sudo_log" ]]
echo 'PASS: a missing saved USB device is never replaced with the old tty'

python3 - "$script_path" <<'PY'
import pathlib
import re
import sys
import hashlib

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
assert '3) reset USB connection (not a radio reboot), then retry' in source
assert 'Reset USB connection before probing (not a radio reboot)? [y/N]' in source
assert source.count('prepare_selected_usb_connection "$detected_dev" || return 1') == 2
assert 'partial_tool="$(mktemp "${cached_tool}.partial.XXXXXX")"' in source
assert '|| ! meshcore_usb_reset_tool_hash_matches "$partial_tool"' in source
pin = re.search(r'^MESHCORE_USB_RESET_TOOL_SHA256="([0-9a-f]{64})"$', source, re.M).group(1)
helper = pathlib.Path(sys.argv[1]).parent / 'tools' / 'meshcore_usb_reset.py'
assert hashlib.sha256(helper.read_bytes().replace(b'\r\n', b'\n')).hexdigest() == pin
prepare = re.search(r'^prepare_selected_usb_connection\(\) \{\n(.*?)^\}', source, re.M | re.S).group(1)
assert prepare.rstrip().endswith('USB_RESET_RECOVERED_PORT=""')
for name in ('probe_esptool', 'probe_esptool_mac'):
    body = re.search(r'^' + name + r'\(\) \{\n(.*?)^\}', source, re.M | re.S).group(1)
    assert 'invoke_esptool "$@"' not in body, name + ' retains stale retry arguments'
    assert body.count('refresh_usb_recovered_esptool_args attempt_args') == 2
print('PASS: chooser, manual recovery, pinned download and probe retry wiring')
PY
