#!/usr/bin/env bash
# Test-fixture globals are consumed by production functions evaluated below.
# shellcheck disable=SC2034
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcfirmware.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

extract_function() {
	local function_name=$1
	awk -v signature="${function_name}() {" '
		$0 == signature { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
}

for function_name in probe_esptool probe_esptool_mac prepare_esp32_flash_session; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

invoke_status=37
invoke_log="${tmp_dir}/invoke-log"
invoke_esptool() {
	printf '%s\n' "$*" >>"$invoke_log"
	printf '%s\n' 'Permission denied opening serial port'
	return "$invoke_status"
}
esptool_output_port_busy() { return 1; }
recover_busy_serial_port() { return 1; }
no_sudo_mode() { return 0; }
esptool_output_needs_reset() { return 1; }
auto_reset_serial_port() { return 1; }
manual_reboot_choice() { return 1; }
print_esptool_recovery_hint() { return 0; }
sudo() {
	echo "FAIL: no-sudo probe invoked sudo" >&2
	return 1
}

probe_status=0
if probe_esptool --port /dev/ttyUSB0 read-mac 2>"${tmp_dir}/probe-error"; then
	echo "FAIL: failed generic esptool probe returned success" >&2
	exit 1
else
	probe_status=$?
fi
[[ "$probe_status" -eq 37 ]] || {
	echo "FAIL: generic probe returned $probe_status instead of 37" >&2
	exit 1
}
grep -Fq 'No-sudo mode cannot change access to /dev/ttyUSB0.' "${tmp_dir}/probe-error"
echo "PASS: generic esptool probe preserves its command failure status"

invoke_status=42
erase_or_write_calls=0
run_esptool() {
	erase_or_write_calls=$((erase_or_write_calls + 1))
}
flash_status=0
if probe_esptool_mac --port /dev/ttyUSB0 read-mac 2>"${tmp_dir}/mac-error"; then
	run_esptool erase-flash
	run_esptool write-flash
else
	flash_status=$?
fi
[[ "$flash_status" -eq 42 ]] || {
	echo "FAIL: MAC probe returned $flash_status instead of 42" >&2
	exit 1
}
[[ "$erase_or_write_calls" -eq 0 ]] || {
	echo "FAIL: erase/write followed a failed no-sudo MAC probe" >&2
	exit 1
}
grep -Fq 'No-sudo mode cannot change access to /dev/ttyUSB0.' "${tmp_dir}/mac-error"
[[ "$(wc -l <"$invoke_log")" -eq 2 ]] || {
	echo "FAIL: no-sudo probes unexpectedly retried esptool" >&2
	exit 1
}
echo "PASS: failed no-sudo MAC probe cannot reach erase or write"

# Exercise the ordinary UART branch of the production session preparation.
# It must use esptool's normal DTR/RTS reset at a real communication baud, then
# stop the caller before erase/write when the reset probe does not answer.
uart_port="${tmp_dir}/ttyUSB0"
touch "$uart_port"
DEVICE_PORT_FILE="${tmp_dir}/device-port"
DEVICE_PORT_NAME_FILE="${tmp_dir}/device-port-name"
DOWNLOAD_DIR="$tmp_dir"
CURRENT_BAK="${DOWNLOAD_DIR}/CURRENT.BAK"
touch "$CURRENT_BAK"
DEVICE_PORT="$uart_port"
BOOTLOADER_PROBE_PORT=""
BOOTLOADER_PROBE_ACTIVE=0
ESPTOOL_CMD="pipx run esptool"
NORESET="no-reset"
DEFAULTRESET="default-reset"
READMAC="read-mac"

preferred_flash_serial_port() { printf '%s\n' "$1"; }
save_selected_serial_port() {
	DEVICE_PORT="$1"
	printf '%s\n' "$1" >"$DEVICE_PORT_FILE"
}
serial_by_id_link_for_port() { return 1; }
udev_device_property() {
	case "$2" in
		ID_SERIAL_SHORT) printf '%s\n' UART-TEST ;;
		ID_PATH) printf '%s\n' pci-test-usb-0:1:1.0 ;;
	esac
}
nrf52_usb_path_stem() { printf '%s\n' "$1"; }
nrf52_port_instance() { printf '%s\n' instance-uart; }
esp32_port_uses_native_usb() { return 1; }
raw_esptool_mac_probe() { return 1; }
uart_probe_args=""
probe_esptool_mac() {
	uart_probe_args="$*"
	return 43
}

erase_or_write_calls=0
prepare_status=0
if prepare_esp32_flash_session "$uart_port" "SenseCAP Indicator" \
	>"${tmp_dir}/prepare-output" 2>"${tmp_dir}/prepare-error"; then
	run_esptool erase-flash
	run_esptool write-flash
else
	prepare_status=$?
fi
[[ "$prepare_status" -ne 0 ]] || {
	echo "FAIL: failed ordinary UART preparation returned success" >&2
	exit 1
}
[[ "$uart_probe_args" == "--port $uart_port --before default-reset --after no-reset --baud 115200 read-mac" ]] || {
	echo "FAIL: ordinary UART probe arguments were '$uart_probe_args'" >&2
	exit 1
}
[[ "$erase_or_write_calls" -eq 0 ]] || {
	echo "FAIL: erase/write followed failed ordinary UART preparation" >&2
	exit 1
}
grep -Fq 'ESP chip did not confirm bootloader mode' "${tmp_dir}/prepare-error"
echo "PASS: ordinary UART uses default DTR/RTS reset and fails closed"
