#!/usr/bin/env bash
# Production classifier with metadata-only fixtures; no USB ports are opened.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
definition="$(awk '
	$0 == "esp32_port_uses_native_usb() {" { capture = 1 }
	capture { print }
	capture && $0 == "}" { exit }
' "${repo_root}/mcfirmware.sh")"
[[ "$definition" == 'esp32_port_uses_native_usb() {'* ]]
# shellcheck disable=SC2294
eval "$definition"

fixture_vendor=2886
fixture_product=0059
fixture_secondary=1
selected_port=/dev/ttyACM-fixture

udev_device_property() {
	[[ "$1" == "$selected_port" ]] || return 99
	case "$2" in
		ID_VENDOR_ID) printf '%s\n' "$fixture_vendor" ;;
		ID_MODEL_ID) printf '%s\n' "$fixture_product" ;;
		*) return 98 ;;
	esac
}
serial_port_has_secondary_cdc() {
	[[ "$1" == "$selected_port" ]] || return 96
	return "$fixture_secondary"
}

esp32_port_uses_native_usb "$selected_port"
echo 'PASS: exact stock XIAO S3 single CDC routes to descriptor-qualified native preparation'
for fixture_product in 0044 0045 0057 0058 1667 8044 ffff; do
	if esp32_port_uses_native_usb "$selected_port"; then
		echo "FAIL: Seeed PID $fixture_product classified as ESP32 TinyUSB" >&2
		exit 1
	fi
done
fixture_vendor=239a
fixture_product=0059
if esp32_port_uses_native_usb "$selected_port"; then
	echo 'FAIL: unrelated vendor using the same PID classified as native ESP32' >&2
	exit 1
fi
echo 'PASS: nRF52, unknown PID and unrelated VID remain excluded'

fixture_vendor=303a
esp32_port_uses_native_usb "$selected_port"
fixture_vendor=1234
fixture_secondary=0
esp32_port_uses_native_usb "$selected_port"
fixture_secondary=1
if esp32_port_uses_native_usb "$selected_port"; then
	echo 'FAIL: unrelated single CDC became native ESP32' >&2
	exit 1
fi
echo 'PASS: existing Espressif and board-specific dual CDC classification is preserved'
