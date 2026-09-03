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

for function_name in parse_esp32_app_partitions \
	esp32_prepare_merged_ota_mirror read_esp32_app_partitions \
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

partition_fixture="${tmp_dir}/partitions.bin"
python3 - "$partition_fixture" <<'PY'
import struct
import sys

output = bytearray(b"\xff" * 0x1000)
entries = [
    (0x01, 0x02, 0x9000, 0x5000, "nvs"),
    (0x00, 0x10, 0x10000, 0x280000, "app0"),
    (0x00, 0x11, 0x400000, 0x280000, "app1"),
    (0x00, 0x20, 0x680000, 0x10000, "test"),
]
for index, (part_type, subtype, offset, size, label) in enumerate(entries):
    label_bytes = label.encode("ascii").ljust(16, b"\0")
    output[index * 32:(index + 1) * 32] = struct.pack(
        "<HBBII16sI", 0x50AA, part_type, subtype, offset, size, label_bytes, 0
    )
open(sys.argv[1], "wb").write(output)
PY

parsed_partitions="$(parse_esp32_app_partitions "$partition_fixture")"
[[ "$parsed_partitions" == $'0x10000\t0x280000\t0x10\n0x400000\t0x280000\t0x11\n0x680000\t0x10000\t0x20' ]]
echo "PASS: ESP32 partition parsing preserves OTA subtypes"

make_merged_fixture() {
	local output_file=$1
	local primary_size=$2
	local secondary_size=$3
	local app_size=$4
	python3 - "$output_file" "$primary_size" "$secondary_size" "$app_size" <<'PY'
import struct
import sys

output_path = sys.argv[1]
primary_size, secondary_size, app_size = map(lambda value: int(value, 0), sys.argv[2:])
primary_offset = 0x10000
secondary_offset = 0x40000
data = bytearray(b"\xff" * (primary_offset + app_size))
entries = [
    (0x01, 0x02, 0x9000, 0x5000, "nvs"),
    (0x00, 0x10, primary_offset, primary_size, "app0"),
    (0x00, 0x11, secondary_offset, secondary_size, "app1"),
]
for index, (part_type, subtype, offset, size, label) in enumerate(entries):
    label_bytes = label.encode("ascii").ljust(16, b"\0")
    data[0x8000 + index * 32:0x8000 + (index + 1) * 32] = struct.pack(
        "<HBBII16sI", 0x50AA, part_type, subtype, offset, size, label_bytes, 0
    )
app = bytearray((index % 251 for index in range(app_size)))
app[0:4] = b"\xe9\x01\x02\x00"
data[primary_offset:] = app
open(output_path, "wb").write(data)
PY
}

merged_fixture="${tmp_dir}/firmware-merged.bin"
mirrored_app="${tmp_dir}/mirrored-app.bin"
make_merged_fixture "$merged_fixture" 0x20000 0x20000 0x18000
mirror_offsets="$(esp32_prepare_merged_ota_mirror "$merged_fixture" "$mirrored_app")"
[[ "$mirror_offsets" == "0x40000" ]]
cmp -n 0x18000 -i 0x10000:0 "$merged_fixture" "$mirrored_app"
[[ "$(stat -c '%s' "$mirrored_app")" -eq $((0x18000)) ]]
echo "PASS: merged ESP32 app is extracted and assigned to the secondary OTA slot"

oversized_merged="${tmp_dir}/oversized-merged.bin"
oversized_mirror="${tmp_dir}/oversized-mirror.bin"
make_merged_fixture "$oversized_merged" 0x20000 0x10000 0x18000
if esp32_prepare_merged_ota_mirror "$oversized_merged" "$oversized_mirror" \
	>"${tmp_dir}/oversized-merged.out" 2>"${tmp_dir}/oversized-merged.err"; then
	echo "FAIL: an extracted app larger than the secondary OTA slot was accepted" >&2
	exit 1
fi
[[ ! -s "${tmp_dir}/oversized-merged.out" ]]
[[ ! -s "$oversized_mirror" ]]
grep -Fq 'OTA slot at 0x40000 is only 65536 bytes (0x10000)' \
	"${tmp_dir}/oversized-merged.err"
echo "PASS: merged ESP32 mirroring rejects an undersized OTA slot"

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
	printf '%s\n' $'0x10000\t0x100000\t0x0' $'0x110000\t0x100000\t0x20'
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

read_esp32_app_partitions() {
	# Deliberately report ota_1 first to prove ota_0 remains the primary write.
	printf '%s\n' \
		$'0x680000\t0x10000\t0x20' \
		$'0x400000\t0x280000\t0x11' \
		$'0x10000\t0x280000\t0x10'
}
esp32_device_image_present_at_offset() {
	echo "OTA slot population probe must not be called" >&2
	return 2
}
offsets="$(esp32_update_flash_offsets /dev/mock "$firmware" 2>"${tmp_dir}/ota-slots.err")"
[[ "$offsets" == $'0x10000\n0x400000' ]]
grep -Fq 'empty OTA slots are mirrored too' "${tmp_dir}/ota-slots.err"
if grep -Fq 'population probe' "${tmp_dir}/ota-slots.err"; then
	echo "FAIL: OTA slot selection still probed whether the secondary was populated" >&2
	exit 1
fi
echo "PASS: app-only ESP32 updates select every OTA slot even when blank"

read_esp32_app_partitions() {
	printf '%s\n' $'0x10000\t0x1000\t0x0' $'0x400000\t0x1000\t0x11'
}
offsets="$(esp32_update_flash_offsets /dev/mock "$firmware" 2>"${tmp_dir}/missing-ota0.err")"
[[ "$offsets" == "0x400000" ]]
grep -Fq 'OTA slots but no ota_0 subtype; using 0x400000' \
	"${tmp_dir}/missing-ota0.err"
echo "PASS: a table without ota_0 still selects an OTA slot instead of factory"

read_esp32_app_partitions() {
	printf '%s\n' $'0x10000\t0x1000\t0x10' $'0x400000\t0x4\t0x11'
}
if esp32_update_flash_offsets /dev/mock "$firmware" \
	>"${tmp_dir}/undersized-slot.out" 2>"${tmp_dir}/undersized-slot.err"; then
	echo "FAIL: an app-only image larger than an OTA slot was accepted" >&2
	exit 1
fi
[[ ! -s "${tmp_dir}/undersized-slot.out" ]]
grep -Fq 'app partition at 0x400000 is only 4 bytes (0x4)' \
	"${tmp_dir}/undersized-slot.err"
echo "PASS: app-only ESP32 updates fail before writing an undersized OTA slot"
