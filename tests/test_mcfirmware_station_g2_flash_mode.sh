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

for function_name in esp32_image_flash_mode esp32_validate_image_for_device; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

qio_image="${tmp_dir}/station-g2-qio.bin"
dio_image="${tmp_dir}/station-g2-dio.bin"
printf '\351\001\000\000' >"$qio_image"
printf '\351\001\002\000' >"$dio_image"

[[ "$(esp32_image_flash_mode "$qio_image")" == "qio" ]]
[[ "$(esp32_image_flash_mode "$dio_image")" == "dio" ]]
echo "PASS: ESP image flash-mode byte is decoded"

if esp32_validate_image_for_device "UnitEng Station G2" "$qio_image" merged \
	2>"${tmp_dir}/qio-error"; then
	echo "FAIL: Station G2 QIO merged image was accepted" >&2
	exit 1
fi
grep -Fq 'Station G2 firmware must use DIO flash mode' "${tmp_dir}/qio-error"
echo "PASS: Station G2 QIO merged image is refused"

if esp32_validate_image_for_device "Station_G2" "$qio_image" app-only \
	2>"${tmp_dir}/qio-app-error"; then
	echo "FAIL: Station G2 QIO app-only image was accepted" >&2
	exit 1
fi
echo "PASS: Station G2 QIO app-only image is refused"

esp32_validate_image_for_device "UnitEng Station G2" "$dio_image" merged \
	>"${tmp_dir}/dio-output"
grep -Fq 'DIO flash mode confirmed' "${tmp_dir}/dio-output"
echo "PASS: Station G2 DIO image is accepted"

esp32_validate_image_for_device "Heltec V4" "$qio_image" merged
echo "PASS: Station G2-specific guard does not reject other ESP32 hardware"
