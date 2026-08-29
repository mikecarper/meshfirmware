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

for function_name in \
	record_esp32_chip_from_esptool_output esp32_probe_output_has_mac \
	run_esp32_session_esptool esp32_write_after_mode \
	finish_esp32_flash_session; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

ESP32_SESSION_IS_S3=0
esp32_probe_output_has_mac $'Chip type: ESP32-S3 (QFN56)\nMAC: 44:1b:f6:00:00:01'
[[ "$ESP32_SESSION_IS_S3" -eq 1 ]]
ESP32_SESSION_IS_S3=0
esp32_probe_output_has_mac $'Chip is ESP32-S3 (revision v0.2)\nMAC: 44:1b:f6:00:00:02'
[[ "$ESP32_SESSION_IS_S3" -eq 1 ]]
ESP32_SESSION_IS_S3=0
esp32_probe_output_has_mac $'Chip type: ESP32-C3\nMAC: 44:1b:f6:00:00:03'
[[ "$ESP32_SESSION_IS_S3" -eq 0 ]]
echo "PASS: esptool output identifies only ESP32-S3 sessions"

uart_port="${tmp_dir}/ttyUSB0"
native_port="${tmp_dir}/ttyACM0"
expected_runtime_port="${tmp_dir}/ttyACM1"
touch "$uart_port" "$native_port" "$expected_runtime_port"

NORESET="no-reset"
HARDRESET="hard-reset"
WATCHDOGRESET="watchdog-reset"
READMAC="read-mac"
ESP32_PROBE_TIMEOUT_SECONDS=12
ESP32_FLASH_SELECTED_BY_ID="${tmp_dir}/by-id-v4"
ESP32_FLASH_EXPECTED_SERIAL="441BF6000001"
ESP32_FLASH_EXPECTED_PATH_STEM="usb-test"
DEVICE_PORT=""

esp32_port_is_rom_usb_jtag() { [[ "$1" == "$native_port" ]]; }
nrf52_port_instance() { printf 'instance-%s\n' "$(basename "$1")"; }
wait_for_nrf52_bootloader_port() { printf '%s\n' "$expected_runtime_port"; }
save_selected_serial_port() { DEVICE_PORT="$1"; }

operation_log="${tmp_dir}/operation-log"
run_esptool() { printf '%s\n' "$*" >>"$operation_log"; }
invoke_log="${tmp_dir}/invoke-log"
invoke_esptool_timeout() { printf '%s\n' "$*" >>"$invoke_log"; }

ESP32_SESSION_IS_S3=1
ESP32_OPERATION_BEFORE="default-reset"
[[ "$(esp32_write_after_mode "$uart_port")" == "no-reset" ]]
finish_esp32_flash_session "$uart_port" >"${tmp_dir}/uart-finish-output"
grep -Fxq -- "--port $uart_port --before default-reset --after watchdog-reset run" \
	"$operation_log"
[[ ! -e "$invoke_log" ]] || {
	echo "FAIL: S3 UART finish used the legacy hard-reset command" >&2
	exit 1
}
grep -Fq 'operation complete; exiting the stub with a watchdog reset' \
	"${tmp_dir}/uart-finish-output"
echo "PASS: ESP32-S3 UART exits the stub with watchdog-reset run"

: >"$operation_log"
ESP32_OPERATION_BEFORE="no-reset"
DEVICE_PORT=""
[[ "$(esp32_write_after_mode "$native_port")" == "no-reset" ]]
finish_esp32_flash_session "$native_port" >"${tmp_dir}/native-s3-finish-output"
grep -Fxq -- "--port $native_port --before no-reset --after watchdog-reset run" \
	"$operation_log"
[[ "$DEVICE_PORT" == "$expected_runtime_port" ]] || {
	echo "FAIL: native S3 watchdog reset did not follow the runtime USB identity" >&2
	exit 1
}
echo "PASS: native ESP32-S3 uses watchdog reset and follows re-enumeration"

: >"$operation_log"
: >"$invoke_log"
ESP32_SESSION_IS_S3=0
ESP32_OPERATION_BEFORE="default-reset"
[[ "$(esp32_write_after_mode "$uart_port")" == "hard-reset" ]]
finish_esp32_flash_session "$uart_port"
[[ ! -s "$operation_log" && ! -s "$invoke_log" ]] || {
	echo "FAIL: non-S3 UART behavior changed" >&2
	exit 1
}

ESP32_OPERATION_BEFORE="no-reset"
[[ "$(esp32_write_after_mode "$native_port")" == "no-reset" ]]
finish_esp32_flash_session "$native_port" >"${tmp_dir}/native-other-finish-output"
grep -Fxq -- "12s --port $native_port --before no-reset --after hard-reset read-mac" \
	"$invoke_log"
echo "PASS: non-S3 UART and native USB retain their prior reset behavior"

[[ "$(rg -c 'ESP32_WRITE_AFTER="\$\(esp32_write_after_mode "\$DEVICE_PORT"\)"' "$script_path")" -eq 2 ]] || {
	echo "FAIL: an ESP32 write/update path bypasses the S3 finish policy" >&2
	exit 1
}
echo "PASS: both merged and update writes defer reset to the session finish policy"
