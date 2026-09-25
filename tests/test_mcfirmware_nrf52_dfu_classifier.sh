#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcfirmware.sh"

extract_function() {
	local function_name=$1
	awk -v signature="${function_name}() {" '
		$0 == signature { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
}

# Exercise the classifier from mcfirmware.sh itself without sourcing/running
# the interactive flasher. Its hardware-facing dependencies are replaced by
# deterministic mocks below.
for function_name in normalize_usb_serial_identity nrf52_usb_path_stem \
	nrf52_post_erase_identity_proof nrf52_port_is_dfu_bootloader; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate the function extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

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
		[ID_SERIAL_SHORT]="B35E"
		[ID_PATH]="pci-0000:00:14.0-usb-0:1:1.0"
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

assert_changed_link_classifier() {
	local description=$1
	local expected=$2
	local verified_post_erase_identity=$3
	local selected="/dev/serial/by-id/usb-selected-runtime-if00"
	local changed_link="/dev/serial/by-id/usb-post-erase-DFU-if00"
	local status

	if nrf52_port_is_dfu_bootloader "/dev/ttyACM0" "$changed_link" "$selected" \
		"B35E" "pci-0000:00:14.0-usb-0:1" "$verified_post_erase_identity"; then
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

assert_unmatched_override_classifier() {
	local description=$1
	local selected="/dev/serial/by-id/usb-selected-runtime-if00"
	local status

	if nrf52_port_is_dfu_bootloader "/dev/ttyACM0" "" "$selected" \
		"B35E" "pci-0000:00:14.0-usb-0:1" 0 1; then
		status=0
	else
		status=$?
	fi
	if [[ "$status" -ne 0 ]]; then
		echo "FAIL: ${description}: explicit override returned status ${status}" >&2
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
mock_properties[ID_MODEL_ID]="0057"
assert_classifier "exact selected T1000-E serial-only DFU 2886:0057 is accepted" 0
assert_changed_link_classifier "T1000-E DFU link change is rejected outside verified post-erase flow" 1 0
assert_changed_link_classifier "T1000-E DFU link change is accepted after verified post-erase identity resolution" 0 1
mock_identity_match=0
assert_classifier "T1000-E DFU PID with identity mismatch is rejected" 1
assert_changed_link_classifier "T1000-E changed-link DFU with identity mismatch is rejected after post-erase resolution" 1 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="2886"
mock_properties[ID_MODEL_ID]="1667"
assert_classifier "exact selected Wio Tracker L1 bootloader 2886:1667 is accepted" 0
mock_properties[ID_MODEL_ID]="1668"
assert_classifier "unlisted Seeed PID 2886:1668 is rejected" 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="002a"
mock_properties[ID_MODEL]="WisCore_RAK3401_Board"
assert_classifier "exact selected RAK3401 serial DFU 239a:002a is accepted" 0
assert_changed_link_classifier "RAK3401 DFU link change is rejected outside verified post-erase flow" 1 0
assert_changed_link_classifier "RAK3401 DFU link change is accepted after verified post-erase identity resolution" 0 1
mock_identity_match=0
assert_classifier "RAK3401 DFU PID with identity mismatch is rejected" 1
assert_changed_link_classifier "RAK3401 changed-link DFU with identity mismatch is rejected after post-erase resolution" 1 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="802a"
mock_properties[ID_MODEL]="WisCore_RAK3401_Board"
assert_classifier "RAK3401 application-style PID 239a:802a is rejected" 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="0029"
mock_properties[ID_MODEL]="Heltec_Mesh_Node_T1"
assert_classifier "exact selected Heltec Mesh Node T1 serial DFU 239a:0029 is accepted" 0
assert_changed_link_classifier "Heltec Mesh Node T1 DFU link change is rejected outside verified post-erase flow" 1 0
assert_changed_link_classifier "Heltec Mesh Node T1 DFU link change is accepted after verified post-erase identity resolution" 0 1
mock_identity_match=0
assert_classifier "Heltec Mesh Node T1 DFU PID with identity mismatch is rejected" 1
assert_changed_link_classifier "Heltec Mesh Node T1 changed-link DFU with identity mismatch is rejected after post-erase resolution" 1 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="8029"
mock_properties[ID_MODEL]="Heltec_Mesh_Node_T1"
assert_classifier "Heltec Mesh Node T1 application-style PID 239a:8029 is rejected" 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="002b"
mock_properties[ID_MODEL]="Heltec_Mesh_Node_T1"
assert_classifier "unlisted Heltec-family PID 239a:002b is rejected" 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="00b3"
assert_classifier "exact selected ProMicro/Keepteen bootloader 239a:00b3 is accepted" 0
mock_properties[ID_MODEL_ID]="00da"
assert_classifier "exact selected T-Echo Lite/ThinkNode bootloader 239a:00da is accepted" 0
mock_properties[ID_MODEL_ID]="00b4"
assert_classifier "unlisted Adafruit-family PID 239a:00b4 is rejected" 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="1234"
mock_properties[ID_MODEL_ID]="5678"
mock_properties[ID_MODEL]="Unknown_nRF52_endpoint"
mock_identity_match=0
assert_classifier "unknown DFU endpoint with an identity mismatch is rejected by default" 1
assert_unmatched_override_classifier "explicit recovery override accepts an otherwise unmatched unknown DFU endpoint"

reset_usb_properties
mock_properties[ID_VENDOR_ID]="2886"
mock_properties[ID_MODEL_ID]="8044"
assert_classifier "XIAO MeshCore application 2886:8044 is rejected" 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="0071"
mock_properties[ID_MODEL]="HT-n5262"
assert_classifier "exact selected MeshTower V2 serial-only DFU 239a:0071 is accepted" 0

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="002a"
mock_properties[ID_MODEL]="WisBlock_RAK3401"
assert_classifier "exact selected RAK3401 serial-only DFU 239a:002a is accepted" 0

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="0029"
mock_properties[ID_MODEL]="Heltec_Mesh_Node_T1_OTAFIX"
assert_classifier "exact selected Heltec T1 OTAFIX 239a:0029 is accepted" 0

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="802a"
mock_properties[ID_MODEL]="WisBlock_RAK3401"
assert_classifier "nearby RAK product 239a:802a is rejected" 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="8029"
mock_properties[ID_MODEL]="Heltec_Mesh_Node_T1_OTAFIX"
assert_classifier "nearby Heltec product 239a:8029 is rejected" 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="002b"
mock_properties[ID_MODEL]="unknown"
assert_classifier "unlisted 239a:002b is rejected" 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="4405"
mock_properties[ID_MODEL]="HT-n5262"
assert_classifier "MeshTower V2 application 239a:4405 is rejected" 1

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

reset_usb_properties
mock_properties[ID_VENDOR_ID]="2886"
mock_properties[ID_MODEL_ID]="0057"
mock_identity_match=0
assert_classifier "T1000-E DFU VID:PID with identity mismatch is rejected" 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="002a"
mock_identity_match=0
assert_classifier "RAK3401 DFU VID:PID with identity mismatch is rejected" 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="0029"
mock_identity_match=0
assert_classifier "Heltec T1 DFU VID:PID with identity mismatch is rejected" 1

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="002a"
mock_properties[ID_MODEL]="WisBlock_RAK3401_BOOT"
mock_properties[ID_SERIAL_SHORT]="RAK3401-TEST"
mock_identity_match=1
mock_properties[ID_PATH]="pci-0000:00:14.0-usb-0:1:2.1"
if ! nrf52_port_is_dfu_bootloader /dev/ttyACM7 '' \
	/dev/serial/by-id/usb-RAK3401-runtime-if00 RAK3401TEST \
	pci-0000:00:14.0-usb-0:1 1; then
	echo "FAIL: post-erase RAK3401 DFU proof was not accepted" >&2
	exit 1
fi
echo "PASS: post-erase app install accepts an exact DFU endpoint with serial and path proof"

if nrf52_port_is_dfu_bootloader /dev/ttyACM7 '' \
	/dev/serial/by-id/usb-RAK3401-runtime-if00 RAK3401TEST \
	pci-0000:00:14.0-usb-0:1; then
	echo "FAIL: ordinary no-by-id DFU classification was accepted" >&2
	exit 1
fi
echo "PASS: ordinary DFU classification still requires the selected by-id link"

mock_properties[ID_PATH]="pci-0000:00:14.0-usb-0:2:9.1"
if nrf52_port_is_dfu_bootloader /dev/ttyACM7 '' \
	/dev/serial/by-id/usb-RAK3401-runtime-if00 RAK3401TEST \
	pci-0000:00:14.0-usb-0:1 1; then
	echo "FAIL: post-erase proof accepted a changed USB path" >&2
	exit 1
fi
echo "PASS: post-erase app install rejects a path mismatch"

reset_usb_properties
mock_properties[ID_VENDOR_ID]="239a"
mock_properties[ID_MODEL_ID]="0029"
mock_properties[ID_MODEL]="Heltec_Mesh_Node_T1_OTAFIX"
mock_properties[ID_SERIAL_SHORT]="T1-TEST"
mock_identity_match=1
mock_properties[ID_PATH]="pci-0000:00:14.0-usb-0:3:2.1"
if nrf52_port_is_dfu_bootloader /dev/ttyACM7 '' \
	/dev/serial/by-id/usb-Heltec-T1-runtime-if00 T1TEST \
	pci-0000:00:14.0-usb-0:3; then
	echo "FAIL: ordinary T1 changed-link DFU classification was accepted" >&2
	exit 1
fi
echo "PASS: ordinary T1 changed-link DFU classification is rejected"

if ! nrf52_port_is_dfu_bootloader /dev/ttyACM7 '' \
	/dev/serial/by-id/usb-Heltec-T1-runtime-if00 T1TEST \
	pci-0000:00:14.0-usb-0:3 1; then
	echo "FAIL: verified post-erase T1 DFU proof was not accepted" >&2
	exit 1
fi
echo "PASS: verified post-erase T1 changed-link DFU classification is accepted"
