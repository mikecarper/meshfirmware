#!/usr/bin/env bash
# Test-fixture globals are consumed by production functions evaluated below.
# shellcheck disable=SC2034,SC2218
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

for function_name in \
	probe_esptool probe_esptool_mac selected_flash_serial_port \
	prepare_esp32_flash_session \
	esp32_esptool_args_are_destructive run_esp32_session_esptool \
	autodetect_device; do
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
uart_link="${tmp_dir}/usb-UART_TEST-if00"
ln -s "$uart_port" "$uart_link"
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
ESP32_OPERATION_BEFORE="$NORESET"
READMAC="read-mac"

preferred_flash_serial_port() { printf '%s\n' "$1"; }
save_selected_serial_port() {
	DEVICE_PORT="$1"
	printf '%s\n' "$1" >"$DEVICE_PORT_FILE"
}
serial_by_id_link_for_port() {
	[[ "$1" == "$uart_port" ]] || return 1
	printf '%s\n' "$uart_link"
}
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
# The production function is deliberately replaced later for the independent
# native-autodetect failure fixture.
# shellcheck disable=SC2218
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

# A successful UART probe does not guarantee that the bridge remains attached
# to the ROM after esptool closes it. Every subsequent operation must therefore
# repeat default-reset, while a native USB handoff stays on no-reset.
probe_esptool_mac() {
	uart_probe_args="$*"
	return 0
}
touch "$CURRENT_BAK"
# shellcheck disable=SC2218
prepare_esp32_flash_session "$uart_port" "SenseCAP Indicator" \
	>"${tmp_dir}/prepare-success-output"
[[ "$ESP32_OPERATION_BEFORE" == "default-reset" ]] || {
	echo "FAIL: successful UART preparation selected '$ESP32_OPERATION_BEFORE'" >&2
	exit 1
}

operation_log="${tmp_dir}/operation-log"
run_esptool() {
	printf '%s\n' "$*" >>"$operation_log"
}
esp32_verified_destructive_port() { printf '%s\n' "$1"; }
run_esp32_session_esptool "$uart_port" \
	--after no-reset --baud 115200 erase-flash
run_esp32_session_esptool "$uart_port" \
	--after hard-reset --baud 115200 write-flash 0x0000 firmware.bin
grep -Fxq -- "--port $uart_port --before default-reset --after no-reset --baud 115200 erase-flash" \
	"$operation_log"
grep -Fxq -- "--port $uart_port --before default-reset --after hard-reset --baud 115200 write-flash 0x0000 firmware.bin" \
	"$operation_log"

ESP32_OPERATION_BEFORE="no-reset"
run_esp32_session_esptool /dev/ttyACM4 \
	--after no-reset --baud 115200 read-flash 0x8000 0x1000 partitions.bin
grep -Fxq -- '--port /dev/ttyACM4 --before no-reset --after no-reset --baud 115200 read-flash 0x8000 0x1000 partitions.bin' \
	"$operation_log"
echo "PASS: UART repeats default-reset while reads remain at the qualified safe baud"

# A known native Espressif VID cannot safely fall through to the nRF52 touch
# and UF2 path merely because its ROM handoff/probe failed.
native_port="${tmp_dir}/ttyACM-native"
touch "$native_port"
printf '%s\n' "$native_port" >"$DEVICE_PORT_FILE"
_jq1() { return 0; }
choose_serial() { printf '%s\n' "$native_port" >"$DEVICE_PORT_FILE"; }
selected_flash_serial_port() { printf '%s\n' "$1"; }
save_selected_serial_port() { return 0; }
nrf52_usb_path_stem() { printf '%s\n' "$1"; }
udev_device_property() {
	case "$2" in
		ID_VENDOR_ID) printf '%s\n' 303a ;;
		ID_SERIAL_SHORT) printf '%s\n' NATIVE-TEST ;;
		ID_PATH) printf '%s\n' pci-test-usb-0:2:1.0 ;;
	esac
}
get_espcmd() {
	NORESET="no-reset"
	DEFAULTRESET="default-reset"
	READMAC="read-mac"
}
prepare_esp32_flash_session() { return 55; }
nrf_fallback_calls=0
scan_and_maybe_mount() {
	nrf_fallback_calls=$((nrf_fallback_calls + 1))
	return 1
}
autodetect_status=0
if autodetect_device >"${tmp_dir}/native-autodetect.out" \
	2>"${tmp_dir}/native-autodetect.err"; then
	echo "FAIL: failed native ESP32 preparation fell through as nRF52" >&2
	exit 1
else
	autodetect_status=$?
fi
[[ "$autodetect_status" -ne 0 ]]
[[ "$nrf_fallback_calls" -eq 0 ]]
grep -Fq 'refusing to treat it as nRF52' "${tmp_dir}/native-autodetect.err"
echo "PASS: failed native ESP32 preparation cannot fall through to nRF52"

# autodetect_device is called from a conditional, so every safety-critical
# operation inside it must propagate failure explicitly rather than relying on
# the script's global errexit setting.
choose_serial() { return 56; }
if autodetect_device >"${tmp_dir}/no-selection.out" \
	2>"${tmp_dir}/no-selection.err"; then
	echo "FAIL: hardware autodetection continued after serial selection failed" >&2
	exit 1
fi
grep -Fq 'No serial device was selected' "${tmp_dir}/no-selection.err"
echo "PASS: autodetection propagates serial-selection failure"

choose_serial() { printf '%s\n' "$native_port" >"$DEVICE_PORT_FILE"; }
selected_flash_serial_port() { printf '%s\n' "$1"; }
prepare_esp32_flash_session() {
	BOOTLOADER_PROBE_PORT="$1"
	BOOTLOADER_PROBE_ACTIVE=1
	return 0
}
esp32_verified_destructive_port() { printf '%s\n' "$1"; }
run_mode="failure"
autodetect_read_log="${tmp_dir}/autodetect-read.log"
run_esp32_session_esptool() {
	local output_file="${!#}"
	printf '%s\n' "$*" >>"$autodetect_read_log"
	case "$run_mode" in
		failure) return 66 ;;
		no-write) return 0 ;;
		complete)
			truncate -s 458752 "$output_file"
			return 0
			;;
	esac
}
detect_result="heltec v4"
detect_log="${tmp_dir}/detect.log"
detect_device_from_fw() {
	printf '%s\n' "$1" >>"$detect_log"
	printf '%s\n' "$detect_result"
}
restore_log="${tmp_dir}/restore.log"
restore_port_after_bootloader_probe() {
	printf '%s\n' restore >>"$restore_log"
	BOOTLOADER_PROBE_ACTIVE=0
	BOOTLOADER_PROBE_PORT=""
}
esp32_port_is_rom_usb_jtag() { return 1; }
finish_status=0
finish_esp32_flash_session() { return "$finish_status"; }
raw_probe_calls=0
raw_esptool_mac_probe() {
	raw_probe_calls=$((raw_probe_calls + 1))
	return 0
}
READFLASH="read-flash"
HARDRESET="hard-reset"
DOWNLOAD_DIR="$tmp_dir"

truncate -s 458752 "$DOWNLOAD_DIR/CURRENT.BAK"
run_mode="failure"
if autodetect_device >"${tmp_dir}/read-failure.out" \
	2>"${tmp_dir}/read-failure.err"; then
	echo "FAIL: failed autodetect read reused a stale CURRENT.BAK" >&2
	exit 1
fi
[[ ! -e "$DOWNLOAD_DIR/CURRENT.BAK" ]]
[[ ! -e "$detect_log" ]]
grep -Fq 'Could not read the ESP32 application' "${tmp_dir}/read-failure.err"
grep -Fxq -- \
	"$native_port --after no-reset --baud 115200 read-flash 0x10000 0x70000 $DOWNLOAD_DIR/CURRENT.BAK" \
	"$autodetect_read_log"
echo "PASS: failed ESP32 autodetect read cannot reuse a stale backup"

truncate -s 458752 "$DOWNLOAD_DIR/CURRENT.BAK"
run_mode="no-write"
if autodetect_device >"${tmp_dir}/empty-read.out" \
	2>"${tmp_dir}/empty-read.err"; then
	echo "FAIL: zero-exit autodetect read without output was accepted" >&2
	exit 1
fi
[[ ! -e "$DOWNLOAD_DIR/CURRENT.BAK" ]]
[[ ! -e "$detect_log" ]]
grep -Fq 'returned 0 of 458752 bytes' "${tmp_dir}/empty-read.err"
echo "PASS: ESP32 autodetect requires a complete fresh read"

run_mode="complete"
detect_result="unknown"
if autodetect_device >"${tmp_dir}/unknown-device.out" \
	2>"${tmp_dir}/unknown-device.err"; then
	echo "FAIL: unknown firmware identity completed autodetection" >&2
	exit 1
fi
grep -Fq 'did not contain a usable hardware identity' \
	"${tmp_dir}/unknown-device.err"
echo "PASS: unknown ESP32 firmware identity fails autodetection"

detect_result="heltec v4"
finish_status=71
esp32_port_is_rom_usb_jtag() { return 0; }
if autodetect_device >"${tmp_dir}/finish-failure.out" \
	2>"${tmp_dir}/finish-failure.err"; then
	echo "FAIL: failed native ESP32 finish completed autodetection" >&2
	exit 1
fi
echo "PASS: native ESP32 autodetect finish failure propagates"

finish_status=0
esp32_port_is_rom_usb_jtag() { return 1; }
udev_device_property() {
	case "$2" in
		ID_VENDOR_ID) printf '%s\n' 10c4 ;;
		ID_SERIAL_SHORT) printf '%s\n' UART-AUTODETECT ;;
		ID_PATH) printf '%s\n' pci-test-usb-0:2:1.0 ;;
	esac
}
raw_probe_calls=0
ESP32_FLASH_EXPECTED_MAC="d83bda7523ac"
raw_esptool_mac_probe() {
	raw_probe_calls=$((raw_probe_calls + 1))
	[[ -z "$ESP32_FLASH_EXPECTED_MAC" ]] || return 80
	(( raw_probe_calls == 1 ))
}
if autodetect_device >"${tmp_dir}/uart-reset-failure.out" \
	2>"${tmp_dir}/uart-reset-failure.err"; then
	echo "FAIL: failed UART ESP32 reset completed autodetection" >&2
	exit 1
fi
[[ "$raw_probe_calls" -eq 2 ]]
grep -Fq 'did not confirm its autodetect session reset' \
	"${tmp_dir}/uart-reset-failure.err"
echo "PASS: UART ESP32 autodetect starts a fresh MAC session and propagates reset failure"
