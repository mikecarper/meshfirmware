#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcfirmware.sh"

# Exercise the classifier from mcfirmware.sh itself without sourcing/running
# the interactive flasher. Its hardware-facing dependencies are replaced by
# deterministic mocks below.
classifier="$({
	awk '
		$0 == "nrf52_port_is_dfu_bootloader() {" { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
})"
[[ "$classifier" == nrf52_port_is_dfu_bootloader* ]] || {
	echo "failed to extract nrf52_port_is_dfu_bootloader" >&2
	exit 1
}
# Deliberately evaluate the function extracted from the production script.
# shellcheck disable=SC2294
eval "$classifier"

declare -A mock_properties=()
mock_identity_match=1

udev_device_property() {
	local _port=$1
	local property=$2
	printf '%s\n' "${mock_properties[$property]-}"
}

nrf52_candidate_matches_identity() {
	[[ "$mock_identity_match" -eq 1 ]]
}

nrf52_uf2_mount_matches_identity() {
	return 1
}

reset_usb_properties() {
	mock_properties=(
		[ID_BUS]="usb"
		[ID_USB_INTERFACES]=":020201:0a0000:"
		[ID_MODEL]="XIAO_nRF52840"
	)
	mock_identity_match=1
}

assert_classifier() {
	local description=$1
	local expected=$2
	local selected="/dev/serial/by-id/usb-XIAO_B35E-if00"
	local status

	if nrf52_port_is_dfu_bootloader "/dev/ttyACM0" "$selected" "$selected" \
		"B35E" "pci-0000:00:14.0-usb-0:1"; then
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

reset_usb_properties
mock_properties[ID_VENDOR_ID]="2886"
mock_properties[ID_MODEL_ID]="0044"
assert_classifier "exact selected XIAO serial-only DFU 2886:0044 is accepted" 0

reset_usb_properties
mock_properties[ID_VENDOR_ID]="2886"
mock_properties[ID_MODEL_ID]="0045"
assert_classifier "exact selected XIAO Sense serial-only DFU 2886:0045 is accepted" 0

reset_usb_properties
mock_properties[ID_VENDOR_ID]="2886"
mock_properties[ID_MODEL_ID]="8044"
assert_classifier "XIAO MeshCore application 2886:8044 is rejected" 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="303a"
mock_properties[ID_MODEL_ID]="1001"
mock_properties[ID_MODEL]="USB_JTAG_serial_debug_unit"
assert_classifier "Espressif USB serial device is rejected" 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="2886"
mock_properties[ID_MODEL_ID]="0044"
mock_identity_match=0
assert_classifier "XIAO DFU VID:PID with identity mismatch is rejected" 1
