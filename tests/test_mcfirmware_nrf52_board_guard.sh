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
	rak_board_family_from_text rak_board_family_label \
	nrf52_firmware_rak_family nrf52_board_override_token \
	nrf52_confirm_board_override nrf52_validate_rak_board_pair; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

ensure_command() {
	command -v "$1" >/dev/null 2>&1
}

make_package() {
	local output=$1
	local marker=$2
	local fixture_dir="${tmp_dir}/fixture"

	mkdir -p "$fixture_dir"
	printf 'MeshCore fixture\n%s\n' "$marker" >"${fixture_dir}/firmware.bin"
	(
		cd "$fixture_dir"
		zip -q -FS "$output" firmware.bin
	)
}

expect_status() {
	local description=$1
	local expected=$2
	shift 2
	local status

	if "$@"; then
		status=0
	else
		status=$?
	fi
	if [[ "$status" -ne "$expected" ]]; then
		echo "FAIL: ${description}: expected status ${expected}, got ${status}" >&2
		exit 1
	fi
	echo "PASS: ${description}"
}

tag_package="${tmp_dir}/RAK_WisMesh_Tag_companion.zip"
rak3401_package="${tmp_dir}/RAK_3401_companion.zip"
unknown_package="${tmp_dir}/mystery.zip"
misleading_package="${tmp_dir}/RAK_3401_mislabelled.zip"
rak3401_full_package="${tmp_dir}/RAK_3401_companion_full.zip"
tag_full_package="${tmp_dir}/RAK_WisMesh_Tag_companion_full.zip"
make_package "$tag_package" $'WisCore RAK4631 Board\nRAK WisMesh Tag\nWISMESHTAG_OTA'
make_package "$rak3401_package" $'WisCore RAK3401 Board\nRAK 3401\nRAK3401_OTA'
make_package "$unknown_package" 'Unknown nRF52 board'
make_package "$rak3401_full_package" $'WisCore RAK3401 Board\nRAK3401_OTA\nRAK_4631_companion_radio_usb\nRAK_WisMesh_Tag_sensor'
make_package "$tag_full_package" $'WisCore RAK4631 Board\nWISMESHTAG_OTA\nRAK_3401_companion_radio_usb'
cp -- "$tag_package" "$misleading_package"

[[ "$(rak_board_family_from_text 'RAK 3401')" == "rak3401" ]]
[[ "$(rak_board_family_from_text 'WisCore RAK4631 Board')" == "rak4631" ]]
[[ "$(rak_board_family_from_text 'RAK WisMesh Tag')" == "rak4631" ]]
[[ "$(rak_board_family_from_text 'RAK3401 and RAK4631')" == "ambiguous" ]]
[[ -z "$(rak_board_family_from_text 'Heltec V4')" ]]
echo "PASS: RAK board-family text markers are classified"

[[ "$(nrf52_firmware_rak_family "$tag_package")" == "rak4631" ]]
[[ "$(nrf52_firmware_rak_family "$rak3401_package")" == "rak3401" ]]
[[ "$(nrf52_firmware_rak_family "$rak3401_full_package")" == "rak3401" ]]
[[ "$(nrf52_firmware_rak_family "$tag_full_package")" == "rak4631" ]]
[[ -z "$(nrf52_firmware_rak_family "$unknown_package")" ]]
echo "PASS: board-owned payload identity ignores Full Companion's other target names"

mock_board="RAK WisMesh Tag"
declare -A mock_properties=(
	[ID_MODEL]="WisCore_RAK4631_Board"
	[ID_SERIAL]="RAKwireless_WisCore_RAK4631_Board_TEST"
	[ID_SERIAL_SHORT]="TEST"
)

read_board_with_retry() {
	printf '%s' "$mock_board"
}

udev_device_property() {
	local _port=$1
	local property=$2
	printf '%s' "${mock_properties[$property]-}"
}

DEVICE_PORT_NAME_FILE="${tmp_dir}/selected-by-id"
printf '%s\n' 'usb-RAKwireless_WisCore_RAK4631_Board_TEST-if00' >"$DEVICE_PORT_NAME_FILE"
export MCFIRMWARE_BOARD_GUARD_TTY="${tmp_dir}/missing-tty"
unset MCFIRMWARE_BOARD_OVERRIDE || true

expect_status "matching WisMesh Tag payload proceeds automatically" 0 \
	nrf52_validate_rak_board_pair "$tag_package" /dev/mock "RAK WisMesh Tag"

mock_board="RAK 3401"
mock_properties[ID_MODEL]="WisCore_RAK3401_Board"
mock_properties[ID_SERIAL]="RAKwireless_WisCore_RAK3401_Board_TEST"
printf '%s\n' 'usb-RAKwireless_WisCore_RAK3401_Board_TEST-if00' >"$DEVICE_PORT_NAME_FILE"
expect_status "matching RAK3401 payload proceeds automatically" 0 \
	nrf52_validate_rak_board_pair "$rak3401_package" /dev/mock "RAK 3401"

mock_board="RAK WisMesh Tag"
mock_properties[ID_MODEL]="WisCore_RAK4631_Board"
mock_properties[ID_SERIAL]="RAKwireless_WisCore_RAK4631_Board_TEST"
printf '%s\n' 'usb-RAKwireless_WisCore_RAK4631_Board_TEST-if00' >"$DEVICE_PORT_NAME_FILE"
expect_status "RAK3401 payload on a RAK4631 Tag cancels by default" 1 \
	nrf52_validate_rak_board_pair "$rak3401_package" /dev/mock "CustomFirmware"

export MCFIRMWARE_BOARD_OVERRIDE="wrong-token"
expect_status "a generic or incorrect override is rejected" 1 \
	nrf52_validate_rak_board_pair "$rak3401_package" /dev/mock "CustomFirmware"

export MCFIRMWARE_BOARD_OVERRIDE="rak3401-to-rak4631"
expect_status "the exact mismatch token allows deliberate intervention" 0 \
	nrf52_validate_rak_board_pair "$rak3401_package" /dev/mock "CustomFirmware"

unset MCFIRMWARE_BOARD_OVERRIDE
expect_status "a misleading RAK3401 filename around a RAK4631 payload cancels" 1 \
	nrf52_validate_rak_board_pair "$misleading_package" /dev/mock "CustomFirmware"
expect_status "an unverified payload on a known RAK target cancels" 1 \
	nrf52_validate_rak_board_pair "$unknown_package" /dev/mock "CustomFirmware"

mock_board="Heltec V4"
mock_properties[ID_MODEL]="Heltec_V4"
mock_properties[ID_SERIAL]="Heltec_V4_TEST"
printf '%s\n' 'usb-Heltec_V4_TEST-if00' >"$DEVICE_PORT_NAME_FILE"
expect_status "unrelated nRF52 boards retain their existing automatic path" 0 \
	nrf52_validate_rak_board_pair "$unknown_package" /dev/mock "CustomFirmware"

# The dollar signs are intentionally literal production-script text.
# shellcheck disable=SC2016
guard_line="$(grep -n 'nrf52_validate_rak_board_pair "\$DOWNLOADED_FILE"' "$script_path" | tail -n1 | cut -d: -f1)"
# shellcheck disable=SC2016
identity_bind_line="$(grep -n 'NRF52_RUNTIME_PORT="\$(selected_flash_serial_port "\$DEVICE_PORT")"' "$script_path" | tail -n1 | cut -d: -f1)"
# shellcheck disable=SC2016
identity_apply_line="$(grep -n 'DEVICE_PORT="\$NRF52_RUNTIME_PORT"' "$script_path" | head -n1 | cut -d: -f1)"
# shellcheck disable=SC2016
action_line="$(grep -n 'if \[\[ "\$TYPE" == "flash-update"' "$script_path" | tail -n1 | cut -d: -f1)"
if [[ -z "$identity_bind_line" || -z "$identity_apply_line" || -z "$guard_line" \
	|| "$identity_bind_line" -ge "$identity_apply_line" \
	|| "$identity_apply_line" -ge "$guard_line" ]]; then
	echo "FAIL: nRF52 board validation can run before the saved USB identity is rebound" >&2
	exit 1
fi
echo "PASS: nRF52 board validation uses the live saved USB identity"
if [[ -z "$guard_line" || -z "$action_line" || "$guard_line" -ge "$action_line" ]]; then
	echo "FAIL: board guard is not positioned before nRF52 erase/action handling" >&2
	exit 1
fi
echo "PASS: board validation runs before any nRF52 erase/action handling"

dfu_guard_line="$(awk '
	$0 == "run_nrf52_dfu_package_buttonless() {" { capture = 1 }
	capture && /NRF52_BOARD_GUARD_PASSED/ { print NR; exit }
' "$script_path")"
first_dfu_line="$(awk '
	$0 == "run_nrf52_dfu_package_buttonless() {" { capture = 1 }
	capture && /run_nrfutil_dfu_serial_live_port/ { print NR; exit }
' "$script_path")"
if [[ -z "$dfu_guard_line" || -z "$first_dfu_line" || "$dfu_guard_line" -ge "$first_dfu_line" ]]; then
	echo "FAIL: low-level nRF52 DFU path is not gated by the board check" >&2
	exit 1
fi
echo "PASS: low-level nRF52 DFU refuses calls that bypass the board check"

echo "PASS: mcfirmware nRF52 RAK board guard is fail-safe with an exact override"
