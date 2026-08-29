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
	normalize_id contains_word is_good_tail pick_matching_device \
	extract_name_from_firmware detect_device_from_fw; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

esp_image="${tmp_dir}/heltec-v4.bin"
pio_image="${tmp_dir}/pio-only.bin"
combined_image="${tmp_dir}/combined.bin"
unknown_image="${tmp_dir}/unknown.bin"

# The memory suffix is part of the real V4 USB product string. The old loose
# matcher returned "MB PSRAM" because those happened to be the nearest words
# before the manufacturer string.
printf 'prefix\0heltec_wifi_lora_32 v4 (16 MB FLASH, 2 MB PSRAM)\0Espressif Systems\0suffix' \
	>"$esp_image"
printf 'prefix\0.pio/libdeps/heltec_v4_3_companion_radio_full_femoff/library/file.cpp\0' \
	>"$pio_image"
printf 'prefix\0heltec_wifi_lora_32 v4 (16 MB FLASH, 2 MB PSRAM)\0Espressif Systems\0.pio/libdeps/heltec_v4_3_companion_radio_full_femoff/library/file.cpp\0' \
	>"$combined_image"
printf 'no embedded board identity here\0' >"$unknown_image"

[[ "$(extract_name_from_firmware "$esp_image")" == "heltec_wifi_lora_32 v4" ]]
[[ "$(detect_device_from_fw "$esp_image")" == "heltec_wifi_lora_32 v4" ]]
echo "PASS: ESP32 USB product is extracted without the flash/PSRAM suffix"

[[ "$(detect_device_from_fw "$pio_image")" == \
	"heltec_v4_3_companion_radio_full_femoff" ]]
echo "PASS: PlatformIO environment remains the fallback board identity"

[[ "$(detect_device_from_fw "$combined_image")" == \
	"heltec_v4_3_companion_radio_full_femoff" ]]
echo "PASS: exact PlatformIO target takes precedence over a generic USB product"

VENDORLIST="elecrow|heltec|lilygo|seeed|seed|studio|rak|wireless|wisblock|wismesh|raspberry|pi|pico|waveshare|promicro|uniteng|sensecap|wio|xiao"
RADIOLIST="sx1262|sx126x|sx1276|sx127x"
devices=(
	"Heltec v3"
	"Heltec v4"
	"Heltec v4 + Expansion Kit (Touch)"
	"Heltec v4 R8"
	"A newly inserted board"
	"UnitEng Station G2"
)
pick_matching_device "$(detect_device_from_fw "$esp_image")" devices
[[ "$MATCH" == "Heltec v4" && "$MATCH_IDX" -eq 2 ]]
echo "PASS: generic V4 USB product selects the base Heltec v4 entry"

for r8_observer_target in \
	"heltec_v4_r8_repeater_observer_mqtt" \
	"heltec_v4_r8_room_server_observer_mqtt" \
	"heltec_v4_r8_tft_repeater_observer_mqtt" \
	"heltec_v4_r8_tft_portrait_repeater_observer_mqtt" \
	"heltec_v4_r8_tft_room_server_observer_mqtt" \
	"heltec_v4_r8_tft_portrait_room_server_observer_mqtt"; do
	pick_matching_device "$r8_observer_target" devices
	[[ "$MATCH" == "Heltec v4 R8" && "$MATCH_IDX" -eq 4 ]]
done
echo "PASS: all R8 observer identities outrank the base Heltec v4 entry"

pick_matching_device "usb-Station_G2x" devices
[[ "$MATCH" == "UnitEng Station G2" && "$MATCH_IDX" -eq 6 ]]
echo "PASS: Station G2 fallback follows its current menu position"

# These names previously selected an earlier generic menu entry because the
# matcher returned on its first one-word tail match. Exact names must always
# select themselves regardless of menu order.
specific_devices=(
	"GAT-IoT GAT562 Tracker"
	"Generic E22"
	"Heltec MeshSolar / MeshTower"
	"Heltec MeshTower V2"
	"Heltec Wireless Tracker"
	"Heltec Wireless Tracker v1.1"
	"Heltec Wireless Tracker v2"
	"Heltec v4"
	"Heltec v4 + Expansion Kit (Touch)"
	"Heltec v4 R8"
	"Ikoka Handheld nRF E22 30 dBm"
)
for expected_device in \
	"Heltec MeshTower V2" \
	"Heltec Wireless Tracker" \
	"Heltec Wireless Tracker v1.1" \
	"Heltec Wireless Tracker v2" \
	"Heltec v4 + Expansion Kit (Touch)" \
	"Heltec v4 R8" \
	"Ikoka Handheld nRF E22 30 dBm"; do
	pick_matching_device "$expected_device" specific_devices
	[[ "$MATCH" == "$expected_device" ]]
done
echo "PASS: exact board names outrank earlier generic tail matches"

[[ "$(detect_device_from_fw "$unknown_image")" == "unknown" ]]
echo "PASS: unrelated strings are not presented as a board identity"
