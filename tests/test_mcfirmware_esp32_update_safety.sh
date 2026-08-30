#!/usr/bin/env bash
# Fixture globals and function overrides are consumed by production functions
# evaluated below.
# shellcheck disable=SC2034,SC2218,SC2317
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

for function_name in read_esp32_app_partitions \
	esp32_firmware_fits_app_partition esp32_device_image_present_at_offset \
	esp32_update_flash_offsets; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

firmware="${tmp_dir}/firmware.bin"
printf 'small fixture' >"$firmware"
NORESET="no-reset"
READFLASH="read-flash"

run_esp32_session_esptool() { return 41; }
if read_esp32_app_partitions /dev/mock \
	>"${tmp_dir}/table-probe.out" 2>"${tmp_dir}/table-probe.err"; then
	echo "FAIL: failed partition transport returned success" >&2
	exit 1
fi
grep -Fq 'refusing an unchecked app update' "${tmp_dir}/table-probe.err"
echo "PASS: partition-table transport failure returns failure"

probe_status=0
if esp32_device_image_present_at_offset /dev/mock 0x110000 \
	>"${tmp_dir}/slot-probe.out" 2>"${tmp_dir}/slot-probe.err"; then
	echo "FAIL: failed slot read was classified as an app image" >&2
	exit 1
else
	probe_status=$?
fi
[[ "$probe_status" -eq 2 ]]
grep -Fq 'could not inspect ESP32 app partition' "${tmp_dir}/slot-probe.err"
echo "PASS: app-slot transport failure has a distinct fail-closed status"

run_esp32_session_esptool() { return 0; }
if read_esp32_app_partitions /dev/mock \
	>"${tmp_dir}/short-table.out" 2>"${tmp_dir}/short-table.err"; then
	echo "FAIL: a zero-exit empty partition-table read was accepted" >&2
	exit 1
fi
grep -Fq 'returned 0 of 4096 bytes' "${tmp_dir}/short-table.err"

probe_status=0
if esp32_device_image_present_at_offset /dev/mock 0x110000 \
	>"${tmp_dir}/short-slot.out" 2>"${tmp_dir}/short-slot.err"; then
	echo "FAIL: a zero-exit empty slot read was accepted" >&2
	exit 1
else
	probe_status=$?
fi
[[ "$probe_status" -eq 2 ]]
grep -Fq 'returned 0 of 4 bytes' "${tmp_dir}/short-slot.err"
echo "PASS: zero-exit truncated ESP32 reads fail closed"

run_esp32_session_esptool() {
	local output_file="${!#}"
	printf '\377\377\377\377' >"$output_file"
}
if esp32_device_image_present_at_offset /dev/mock 0x110000; then
	echo "FAIL: a valid four-byte empty slot was classified as an app image" >&2
	exit 1
else
	probe_status=$?
fi
[[ "$probe_status" -eq 1 ]]
echo "PASS: a complete empty slot remains distinguishable from a failed read"

read_esp32_app_partitions() { return 42; }
if esp32_update_flash_offsets /dev/mock "$firmware" \
	>"${tmp_dir}/partition-read.out" 2>"${tmp_dir}/partition-read.err"; then
	echo "FAIL: failed partition-table read fell back to an unchecked offset" >&2
	exit 1
fi
[[ ! -s "${tmp_dir}/partition-read.out" ]]
echo "PASS: partition-table read failure cannot fall back to 0x10000"

read_esp32_app_partitions() { printf '%s\n' 'not-a-partition'; }
if esp32_update_flash_offsets /dev/mock "$firmware" \
	>"${tmp_dir}/invalid-table.out" 2>"${tmp_dir}/invalid-table.err"; then
	echo "FAIL: a table with no valid app entries was accepted" >&2
	exit 1
fi
grep -Fq 'no valid app partitions were parsed' "${tmp_dir}/invalid-table.err"
echo "PASS: an unparseable app-partition list fails closed"

read_esp32_app_partitions() {
	printf '%s\n' $'0x10000\t0x100000' $'0x110000\t0x100000'
}
esp32_device_image_present_at_offset() { return 2; }
if esp32_update_flash_offsets /dev/mock "$firmware" \
	>"${tmp_dir}/secondary-fail.out" 2>"${tmp_dir}/secondary-fail.err"; then
	echo "FAIL: a failed secondary-slot probe allowed a partial update" >&2
	exit 1
fi
grep -Fq 'refusing a partial update' "${tmp_dir}/secondary-fail.err"
echo "PASS: secondary app-slot read failure refuses a partial update"

esp32_device_image_present_at_offset() { return 1; }
offsets="$(esp32_update_flash_offsets /dev/mock "$firmware" 2>"${tmp_dir}/empty-secondary.err")"
[[ "$offsets" == "0x10000" ]]
grep -Fq 'contains no app image; skipping that slot' "${tmp_dir}/empty-secondary.err"
echo "PASS: a successfully read empty secondary slot remains skippable"
