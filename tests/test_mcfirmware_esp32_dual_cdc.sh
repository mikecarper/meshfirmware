#!/usr/bin/env bash
# Test-fixture globals are consumed by the production function evaluated below.
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
	prepare_esp32_flash_session finish_esp32_flash_session \
	auto_reset_serial_port; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate the function extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

logging_port="${tmp_dir}/ttyACM5"
primary_port="${tmp_dir}/ttyACM4"
rom_port="${tmp_dir}/ttyACM6"
touch "$logging_port" "$primary_port" "$rom_port"

DEVICE_PORT_FILE="${tmp_dir}/device-port"
DEVICE_PORT_NAME_FILE="${tmp_dir}/device-port-name"
DOWNLOAD_DIR="$tmp_dir"
ESPTOOL_CMD="esptool"
NORESET="no-reset"
READMAC="read-mac"
BOOTLOADER_PROBE_PORT=""
BOOTLOADER_PROBE_ACTIVE=0
DEVICE_PORT="$logging_port"
touch "${DOWNLOAD_DIR}/CURRENT.BAK"

preferred_flash_serial_port() {
	[[ "$1" == "$logging_port" ]] && printf '%s\n' "$primary_port" \
		|| printf '%s\n' "$1"
}

save_selected_serial_port() {
	DEVICE_PORT="$1"
	printf '%s\n' "$1" > "$DEVICE_PORT_FILE"
}

serial_by_id_link_for_port() {
	printf '/dev/serial/by-id/mock-%s\n' "$(basename "$1")"
}

udev_device_property() {
	local port=$1 property=$2
	case "$property" in
		ID_SERIAL_SHORT)
			[[ "$port" == "$rom_port" ]] \
				&& printf '%s\n' '44:1B:F6:6A:E8:44' \
				|| printf '%s\n' '441BF66AE844'
			;;
		ID_PATH) printf '%s\n' 'pci-0000:00:14.0-usb-0:2:1.0' ;;
	esac
}

nrf52_usb_path_stem() { printf '%s\n' "$1"; }
nrf52_port_instance() { printf 'instance-%s\n' "$(basename "$1")"; }
serial_port_has_secondary_cdc() { [[ "$1" == "$primary_port" ]]; }
esp32_port_uses_native_usb() { [[ "$1" == "$primary_port" || "$1" == "$rom_port" ]]; }

touched_port=""
trigger_nrf52_1200_touch() {
	touched_port="$1"
}

wait_for_nrf52_bootloader_port() {
	printf '%s\n' "$rom_port"
}

probed_port=""
raw_esptool_mac_probe() {
	local previous=""
	for arg in "$@"; do
		if [[ "$previous" == "--port" ]]; then
			probed_port="$arg"
		fi
		previous="$arg"
	done
	[[ "$probed_port" == "$rom_port" ]]
}

stop_serial_locking_services() { return 1; }
probe_esptool_mac() { return 1; }

prepare_esp32_flash_session "$logging_port" "Heltec V4"

[[ "$touched_port" == "$primary_port" ]] || {
	echo "FAIL: ESP32 touch used '$touched_port' instead of primary '$primary_port'" >&2
	exit 1
}
[[ "$probed_port" == "$rom_port" ]] || {
	echo "FAIL: ESP32 ROM probe used '$probed_port' instead of '$rom_port'" >&2
	exit 1
}
[[ "$DEVICE_PORT" == "$rom_port" && "$(<"$DEVICE_PORT_FILE")" == "$rom_port" ]] || {
	echo "FAIL: selected ESP32 port was not updated after re-enumeration" >&2
	exit 1
}
[[ "$BOOTLOADER_PROBE_PORT" == "$rom_port" && "$BOOTLOADER_PROBE_ACTIVE" -eq 1 ]] || {
	echo "FAIL: ESP32 bootloader cleanup identity was not updated" >&2
	exit 1
}
[[ ! -e "${DOWNLOAD_DIR}/CURRENT.BAK" ]] || {
	echo "FAIL: stale ESP32 backup marker was not removed" >&2
	exit 1
}

echo "PASS: ESP32 dual CDC flashing follows interface 00 into the ROM tty"

esp32_port_is_rom_usb_jtag() { [[ "$1" == "$rom_port" ]]; }
finish_invocation=""
invoke_esptool_timeout() {
	finish_invocation="$*"
}
wait_for_nrf52_bootloader_port() {
	printf '%s\n' "$primary_port"
}
ESP32_PROBE_TIMEOUT_SECONDS=9
HARDRESET="hard-reset"
READMAC="read-mac"

finish_esp32_flash_session "$rom_port"

expected_finish="9s --port $rom_port --before no-reset --after hard-reset read-mac"
[[ "$finish_invocation" == "$expected_finish" ]] || {
	echo "FAIL: guarded ESP32 finish invocation was '$finish_invocation'" >&2
	exit 1
}
[[ "$DEVICE_PORT" == "$primary_port" && "$(<"$DEVICE_PORT_FILE")" == "$primary_port" ]] || {
	echo "FAIL: ESP32 runtime port was not selected after the safe hard reset" >&2
	exit 1
}
echo "PASS: ESP32 ROM exit uses guarded hard reset and follows runtime USB identity"

native_reset_output="${tmp_dir}/native-reset-output"
if auto_reset_serial_port "$rom_port" 2>"$native_reset_output"; then
	echo "FAIL: raw DTR/RTS fallback was allowed on native ESP32 USB" >&2
	exit 1
fi
grep -Fq 'Skipping raw DTR/RTS recovery on native ESP32 USB port' "$native_reset_output"
echo "PASS: unsafe generic DTR/RTS recovery is refused on native ESP32 USB"
