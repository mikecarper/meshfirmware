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
	selected_flash_serial_port prepare_esp32_flash_session finish_esp32_flash_session \
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
by_id_dir="${tmp_dir}/by-id"
mkdir -p "$by_id_dir"
primary_link="${by_id_dir}/mock-ttyACM4"
rom_link="${by_id_dir}/mock-ttyACM6"
ln -s "$primary_port" "$primary_link"
ln -s "$rom_port" "$rom_link"

DEVICE_PORT_FILE="${tmp_dir}/device-port"
DEVICE_PORT_NAME_FILE="${tmp_dir}/device-port-name"
DOWNLOAD_DIR="$tmp_dir"
ESPTOOL_CMD="esptool"
NORESET="no-reset"
USBRESET="usb-reset"
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
	case "$1" in
		"$primary_port") printf '%s\n' "$primary_link" ;;
		"$rom_port") printf '%s\n' "$rom_link" ;;
		*) return 1 ;;
	esac
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
rom_ready=0
trigger_nrf52_1200_touch() {
	touched_port="$1"
	rom_ready=1
}

expected_rom_port="$primary_port"
wait_original_instance_file="${tmp_dir}/wait-original-instance"
wait_for_nrf52_bootloader_port() {
	printf '%s' "$5" >"$wait_original_instance_file"
	printf '%s\n' "$expected_rom_port"
}

find_reenumerated_nrf52_port() {
	printf '%s\n' "$primary_port"
}

probed_port=""
usb_reset_invocation=""
usb_reset_succeeds=1
raw_esptool_mac_probe() {
	local previous="" before=""
	for arg in "$@"; do
		if [[ "$previous" == "--port" ]]; then
			probed_port="$arg"
		fi
		if [[ "$previous" == "--before" ]]; then
			before="$arg"
		fi
		previous="$arg"
	done
	if [[ "$before" == "$USBRESET" ]]; then
		usb_reset_invocation="$*"
		if (( usb_reset_succeeds )); then
			rom_ready=1
			return 0
		fi
		return 1
	fi
	(( rom_ready )) && [[ "$probed_port" == "$expected_rom_port" ]]
}

stop_serial_locking_services() { return 1; }
probe_esptool_mac() { return 1; }
prepare_serial_port_for_flash() { return 0; }

prepare_esp32_flash_session "$logging_port" "Heltec V4"

expected_reset="--port $primary_link --before usb-reset --after no-reset --baud 115200 read-mac"
[[ "$usb_reset_invocation" == "$expected_reset" ]] || {
	echo "FAIL: ESP32 USB reset was '$usb_reset_invocation'" >&2
	exit 1
}
[[ -z "$touched_port" ]] || {
	echo "FAIL: successful ESP32 USB reset was followed by a 1200-baud touch" >&2
	exit 1
}
[[ "$probed_port" == "$primary_port" ]] || {
	echo "FAIL: same-tty ESP32 ROM probe used '$probed_port' instead of '$primary_port'" >&2
	exit 1
}
[[ "$DEVICE_PORT" == "$primary_port" && "$(<"$DEVICE_PORT_FILE")" == "$primary_port" ]] || {
	echo "FAIL: selected ESP32 port changed after a same-tty USB reset" >&2
	exit 1
}
[[ "$BOOTLOADER_PROBE_PORT" == "$primary_port" && "$BOOTLOADER_PROBE_ACTIVE" -eq 1 ]] || {
	echo "FAIL: ESP32 bootloader cleanup identity was not updated" >&2
	exit 1
}
[[ "$ESP32_OPERATION_BEFORE" == "$NORESET" ]] || {
	echo "FAIL: native ESP32 session selected '$ESP32_OPERATION_BEFORE' instead of no-reset" >&2
	exit 1
}
[[ "$ESP32_NATIVE_ROM_READY" -eq 1 ]] || {
	echo "FAIL: successful native USB reset did not mark the ROM session ready" >&2
	exit 1
}
[[ ! -s "$wait_original_instance_file" ]] || {
	echo "FAIL: proven ESP32 USB reset still required a tty instance change" >&2
	exit 1
}
[[ ! -e "${DOWNLOAD_DIR}/CURRENT.BAK" ]] || {
	echo "FAIL: stale ESP32 backup marker was not removed" >&2
	exit 1
}

echo "PASS: ESP32 native USB reset uses the selected interface-00 by-id identity"

# If USB reset is unavailable or does not answer, retain the guarded legacy
# touch as a fallback, but only after matching the same physical USB identity.
DEVICE_PORT="$logging_port"
BOOTLOADER_PROBE_PORT=""
BOOTLOADER_PROBE_ACTIVE=0
touched_port=""
probed_port=""
usb_reset_succeeds=0
expected_rom_port="$rom_port"
rom_ready=0
touch "${DOWNLOAD_DIR}/CURRENT.BAK"

prepare_esp32_flash_session "$logging_port" "Heltec V4"

[[ "$touched_port" == "$primary_port" ]] || {
	echo "FAIL: ESP32 fallback touch used '$touched_port' instead of primary '$primary_port'" >&2
	exit 1
}
[[ "$probed_port" == "$rom_port" ]] || {
	echo "FAIL: fallback ESP32 ROM probe used '$probed_port' instead of '$rom_port'" >&2
	exit 1
}
[[ "$DEVICE_PORT" == "$rom_port" && "$(<"$DEVICE_PORT_FILE")" == "$rom_port" ]] || {
	echo "FAIL: fallback ESP32 port was not updated after re-enumeration" >&2
	exit 1
}
[[ "$ESP32_OPERATION_BEFORE" == "$NORESET" ]] || {
	echo "FAIL: re-enumerated native ESP32 session did not retain no-reset" >&2
	exit 1
}
[[ "$ESP32_NATIVE_ROM_READY" -eq 1 ]] || {
	echo "FAIL: matched fallback ROM session was not marked ready" >&2
	exit 1
}
echo "PASS: ESP32 native USB reset safely falls back to the matched primary CDC port"

esp32_port_is_rom_usb_jtag() { [[ "$1" == "$rom_port" ]]; }
esp32_verified_destructive_port() { printf '%s\n' "$1"; }
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
