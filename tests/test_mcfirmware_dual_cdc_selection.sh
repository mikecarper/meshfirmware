#!/usr/bin/env bash
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
	normalize_usb_serial_identity nrf52_usb_path_stem \
	serial_ports_share_usb_device serial_port_has_secondary_cdc \
	preferred_flash_serial_link preferred_flash_serial_port \
	nrf52_selected_by_id_path nrf52_candidate_identity_rank \
	trigger_nrf52_1200_touch; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

by_id_dir="${tmp_dir}/by-id"
mkdir -p "$by_id_dir"
primary_port="${tmp_dir}/ttyACM0"
logging_port="${tmp_dir}/ttyACM4"
other_port="${tmp_dir}/ttyACM7"
conflict_port="${tmp_dir}/ttyACM8"
rom_port="${tmp_dir}/ttyACM9"
touch "$primary_port" "$logging_port" "$other_port" "$conflict_port" "$rom_port"

primary_link="${by_id_dir}/usb-RAK4631_TEST-if00"
logging_link="${by_id_dir}/usb-RAK4631_TEST-if02"
other_link="${by_id_dir}/usb-OTHER_TEST-if02"
conflict_link="${by_id_dir}/usb-CONFLICT-if04"
ln -s "$primary_port" "$primary_link"
ln -s "$logging_port" "$logging_link"
ln -s "$other_port" "$other_link"
ln -s "$conflict_port" "$conflict_link"

export NRF52_SERIAL_BY_ID_DIR="$by_id_dir"
declare -A mock_properties=(
	["${primary_port}|ID_PATH"]="pci-0000:00:14.0-usb-0:2:1.0"
	["${primary_port}|ID_SERIAL_SHORT"]="TEST"
	["${primary_port}|ID_USB_INTERFACE_NUM"]="00"
	["${logging_port}|ID_PATH"]="pci-0000:00:14.0-usb-0:2:1.2"
	["${logging_port}|ID_SERIAL_SHORT"]="TEST"
	["${logging_port}|ID_USB_INTERFACE_NUM"]="02"
	["${other_port}|ID_PATH"]="pci-0000:00:14.0-usb-0:9:1.2"
	["${other_port}|ID_SERIAL_SHORT"]="TEST"
	["${other_port}|ID_USB_INTERFACE_NUM"]="02"
	["${conflict_port}|ID_PATH"]="pci-0000:00:14.0-usb-0:2:1.4"
	["${conflict_port}|ID_SERIAL_SHORT"]="CONFLICT"
	["${conflict_port}|ID_USB_INTERFACE_NUM"]="04"
	["${rom_port}|ID_PATH"]="pci-0000:00:14.0-usb-0:3:1.0"
	["${rom_port}|ID_SERIAL_SHORT"]="44:1B:F6:6A:E8:44"
	["${rom_port}|ID_USB_INTERFACE_NUM"]="00"
)

udev_device_property() {
	local port=$1
	local property=$2
	printf '%s\n' "${mock_properties["${port}|${property}"]-}"
}

expect_equal() {
	local description=$1
	local expected=$2
	local actual=$3
	if [[ "$actual" != "$expected" ]]; then
		echo "FAIL: ${description}: expected '${expected}', got '${actual}'" >&2
		exit 1
	fi
	echo "PASS: ${description}"
}

expect_equal "interface 02 resolves to its interface 00 sibling" \
	"$primary_link" "$(preferred_flash_serial_link "$logging_link")"
expect_equal "interface 00 remains selected" \
	"$primary_link" "$(preferred_flash_serial_link "$primary_link")"
expect_equal "a lone nonzero interface is not redirected by cloned serial text" \
	"$other_link" "$(preferred_flash_serial_link "$other_link")"
expect_equal "a conflicting serial is not redirected even on the same USB path" \
	"$conflict_link" "$(preferred_flash_serial_link "$conflict_link")"
expect_equal "resolved tty for interface 02 is the primary tty" \
	"$primary_port" "$(preferred_flash_serial_port "$logging_port")"

serial_port_has_secondary_cdc "$primary_port" || {
	echo "FAIL: primary interface did not detect its secondary CDC sibling" >&2
	exit 1
}
echo "PASS: primary interface detects its secondary CDC sibling"

expect_equal "ESP32 app and ROM serial formatting normalizes identically" \
	"441bf66ae844" "$(normalize_usb_serial_identity '44:1B:F6:6A:E8:44')"

DEVICE_PORT_FILE="${tmp_dir}/device-port"
DEVICE_PORT_NAME_FILE="${tmp_dir}/device-port-name"
printf '%s\n' "$logging_port" > "$DEVICE_PORT_FILE"
basename "$logging_link" > "$DEVICE_PORT_NAME_FILE"
# Read by the extracted production function.
# shellcheck disable=SC2034
DEVICE_PORT="$logging_port"
expect_equal "a cached interface 02 selection is repaired" \
	"$primary_link" "$(nrf52_selected_by_id_path)"

primary_rank="$(nrf52_candidate_identity_rank "$primary_port" "$primary_link" \
	"$logging_link" TEST pci-0000:00:14.0-usb-0:2)"
logging_rank="$(nrf52_candidate_identity_rank "$logging_port" "$logging_link" \
	"$logging_link" TEST pci-0000:00:14.0-usb-0:2)"
if (( primary_rank <= logging_rank )); then
	echo "FAIL: interface 00 rank ${primary_rank} did not beat interface 02 rank ${logging_rank}" >&2
	exit 1
fi
echo "PASS: re-enumeration prefers interface 00 (${primary_rank} > ${logging_rank})"

esp_rom_rank="$(nrf52_candidate_identity_rank "$rom_port" "" "" \
	441BF66AE844 pci-0000:00:14.0-usb-0:2)"
expect_equal "ESP32 ROM matches the app serial despite punctuation and path change" \
	"210" "$esp_rom_rank"

nrf52_serial_port_access() { return 0; }
mock_bash_calls=0
bash() {
	mock_bash_calls=$((mock_bash_calls + 1))
	return 0
}

if trigger_nrf52_1200_touch "$logging_port"; then
	echo "FAIL: secondary logging CDC accepted a DFU touch" >&2
	exit 1
fi
[[ "$mock_bash_calls" -eq 0 ]] || {
	echo "FAIL: secondary logging CDC reached the 1200-baud command" >&2
	exit 1
}
echo "PASS: secondary logging CDC is rejected before the 1200-baud command"

trigger_nrf52_1200_touch "$primary_port"
[[ "$mock_bash_calls" -eq 1 ]] || {
	echo "FAIL: primary CDC did not execute exactly one 1200-baud command" >&2
	exit 1
}
echo "PASS: primary CDC accepts the 1200-baud DFU touch"
