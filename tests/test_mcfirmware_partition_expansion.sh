#!/usr/bin/env bash
# Shell fixtures intentionally override production dependencies below.
# shellcheck disable=SC2034,SC2317
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="$repo_root/mcfirmware.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

extract_function() {
	awk -v signature="$1() {" '
		$0 == signature { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
}
for name in meshcore_partition_expansion_tool_hash_matches \
	remove_esp32_expansion_scratch esp32_partition_expansion_plan_fields \
	parse_esp32_expansion_nvs_partition \
	esp32_require_planned_firmware_hash esp32_wait_partition_expansion_rom \
	esp32_read_partition_expansion_region esp32_prepare_partition_expansion_if_needed \
	parse_esp32_ota_data_partition; do
	definition="$(extract_function "$name")"
	[[ "$definition" == "$name() {"* ]] || { echo "Could not extract $name" >&2; exit 1; }
	# Exercise the real production definitions without executing main/startup.
	# shellcheck disable=SC2294
	eval "$definition"
done

FIRMWARE_ROOT="$tmp_dir/cache"
PWD_SCRIPT="$tmp_dir/flasher"
MESHFIRMWARE_PARTITION_PACKAGE=""
MESHFIRMWARE_USB_MIGRATION_SET=""
ESP32_PARTITION_EXPANSION_SCRATCH=""
ESP32_FLASH_EXPECTED_MAC=001122334455
ESP32_FLASH_SELECTED_BY_ID=/dev/serial/by-id/mock-radio
ESP32_FLASH_EXPECTED_SERIAL=001122334455
ESP32_FLASH_EXPECTED_PATH_STEM=mock-usb-path
ESP32_OPERATION_BEFORE=no-reset
NORESET=no-reset
READFLASH=read-flash
WRITEFLASH=write-flash
FLASHID=flash-id
READMAC=read-mac
EXECUTION_MODE=run
ESP32_SAFE_BAUD=115200
BOOTLOADER_PROBE_ACTIVE=1
BOOTLOADER_PROBE_PORT=/dev/mock
ESP32_NATIVE_ROM_READY=1
DEVICE_PORT=/dev/mock
helper_file="$tmp_dir/helper.py"
firmware_file="$tmp_dir/final.bin"
fixture_bridge_file="$tmp_dir/bridge.bin"
target_table_file="$tmp_dir/target.bin"
fixture_plan_file="$tmp_dir/plan.json"
operation_log="$tmp_dir/operations.log"
choice_file="$tmp_dir/choice.txt"
table_fixture="$tmp_dir/old-table.bin"
MESHFIRMWARE_TTY="$choice_file"
printf x >"$helper_file"
printf 'final app fixture' >"$firmware_file"
fixture_firmware_hash="$(sha256sum "$firmware_file")"
fixture_firmware_hash="${fixture_firmware_hash%% *}"
printf 'bridge app fixture' >"$fixture_bridge_file"
printf x >"$target_table_file"
printf '{}' >"$fixture_plan_file"
command python3 - "$table_fixture" <<'PY'
import struct, sys
d = bytearray(b'\xff' * 4096)
for i, (kind, subtype, offset, size, name) in enumerate([
    (1, 2, 0x9000, 0x5000, 'nvs'),
    (1, 0, 0xe000, 0x2000, 'otadata'),
    (0, 0x10, 0x10000, 0x140000, 'app0'),
    (0, 0x11, 0x150000, 0x140000, 'app1'),
]):
    d[i*32:(i+1)*32] = struct.pack('<HBBII16sI', 0x50aa, kind, subtype,
                                offset, size, name.encode(), 0)
open(sys.argv[1], 'wb').write(d)
PY

plan_needed=true
plan_resume=false
plan_failure=0
begin_failure=0
verify_failure=0
write_failure=0
read_failure=0
short_read=0
fixture_native_usb=0
plan_chip=0
plan_usb_safe=true
uart_failure=0
uart_python_failure=0
uart_wrong_mac=0
uart_restored=true
probe_failure=0
probe_failures_left=0
identity_missing=0
new_mac=001122334455
prepare_failure=0

python3() {
	if [[ "${1:-}" != "$helper_file" ]]; then
		command python3 "$@"
		return
	fi
	shift
	case "${1:-}" in
		plan)
			printf 'plan %s\n' "$*" >>"$operation_log"
			(( ! plan_failure )) || return 1
			if [[ "$plan_needed" == false ]]; then printf '{"ok":true,"needed":false,"firmware_sha256":"%s"}\n' "$fixture_firmware_hash"; return; fi
			local automatic=true uart=false
			if [[ "$plan_chip" == 0 ]]; then automatic=false; uart=true; fi
			printf '{"ok":true,"needed":true,"resume":%s,"firmware_sha256":"%s","usb_safe":%s,"chip":%s,"automatic_rom_return":%s,"uart_completion_status":%s,"bridge_file":"%s","target_table_file":"%s","plan_file":"%s","nvs_offset":36864,"nvs_size":20480,"ota_offset":57344,"ota_size":8192}\n' \
				"$plan_resume" "$fixture_firmware_hash" "$plan_usb_safe" "$plan_chip" "$automatic" "$uart" "$fixture_bridge_file" "$target_table_file" "$fixture_plan_file"
			;;
		begin)
			printf 'begin\n' >>"$operation_log"
			(( ! begin_failure )) || return 1
			printf '{"ok":true,"started":true}\n'
			;;
		verify)
			printf 'verify %s\n' "$*" >>"$operation_log"
			(( ! verify_failure )) || return 1
			printf '{"ok":true,"app_offsets":[65536,6619136]}\n'
			;;
		wait-uart)
			printf 'uart-settled %s\n' "$*" >>"$operation_log"
			(( ! uart_failure )) || return 1
			local mac=001122334455
			if (( uart_wrong_mac )); then mac=aabbccddeeff; fi
			printf '{"ok":true,"settled":true,"restored":%s,"device_mac":"%s"}\n' "$uart_restored" "$mac"
			;;
		*) return 1 ;;
	esac
}

resolve_meshcore_partition_expansion_tool() { printf '%s\n' "$helper_file"; }
resolve_meshcore_partition_uart_python() {
	printf 'uart-python-preflight\n' >>"$operation_log"
	(( ! uart_python_failure )) || return 1
	printf 'python3\n'
}
esp32_port_uses_native_usb() { (( fixture_native_usb )); }
esp32_verified_destructive_port() {
	printf 'identity %s\n' "$*" >>"$operation_log"
	printf '%s\n' "$1"
}
run_esp32_session_esptool() {
	local item last="${!#}" previous="" operation="" read_offset="" read_length=""
	printf 'esptool %s\n' "$*" >>"$operation_log"
	for item in "$@"; do
		if [[ "$previous" == "$READFLASH" ]]; then read_offset="$item"; fi
		if [[ "$previous" == "$read_offset" && -n "$read_offset" ]]; then read_length="$item"; fi
		case "$item" in "$FLASHID"|"$READFLASH"|"$WRITEFLASH") operation="$item" ;; esac
		previous="$item"
	done
	case "$operation" in
		"$FLASHID") printf 'Detected flash size: 16MB\n' ;;
		"$WRITEFLASH") (( ! write_failure )) ;;
		"$READFLASH")
			(( ! read_failure )) || return 1
			if (( short_read )); then printf x >"$last"; return; fi
			if [[ "$read_offset" == 0x8000 ]]; then
				cp -- "$table_fixture" "$last"
			else
				truncate -s "$((read_length))" "$last"
			fi
			;;
		*) return 1 ;;
	esac
}
esp32_update_flash_offsets() { printf '0x150000\n0x10000\n'; }
esp32_write_after_mode() { printf 'no-reset\n'; }
finish_esp32_flash_session() { printf 'finish %s\n' "$*" >>"$operation_log"; }
sleep() { printf 'wait %s\n' "$1" >>"$operation_log"; SECONDS=$((SECONDS + 90)); }
find_reenumerated_nrf52_port() {
	printf 'physical-match %s\n' "$*" >>"$operation_log"
	(( ! identity_missing )) || return 1
	printf '/dev/same-radio\n'
}
raw_esptool_mac_probe() {
	printf 'rom-probe %s\n' "$*" >>"$operation_log"
	(( ! probe_failure )) || return 1
	if (( probe_failures_left )); then probe_failures_left=$((probe_failures_left - 1)); return 1; fi
	ESP32_FLASH_EXPECTED_MAC="$new_mac"
}
save_selected_serial_port() { printf 'save %s\n' "$*" >>"$operation_log"; }
prepare_esp32_flash_session() {
	printf 'prepare %s\n' "$*" >>"$operation_log"
	ESP32_FLASH_EXPECTED_MAC="$new_mac"
	DEVICE_PORT=/dev/same-radio
	(( ! prepare_failure ))
}

reset_case() {
	remove_esp32_expansion_scratch
	: >"$operation_log"
	printf 'y\n' >"$choice_file"
	ESP32_FLASH_EXPECTED_MAC=001122334455
	DEVICE_PORT=/dev/mock
	EXECUTION_MODE=run
	plan_needed=true
	plan_resume=false
	plan_failure=0
	begin_failure=0
	verify_failure=0
	write_failure=0
	read_failure=0
	short_read=0
	fixture_native_usb=0
	plan_chip=0
	plan_usb_safe=true
	uart_failure=0
	uart_python_failure=0
	uart_wrong_mac=0
	uart_restored=true
	probe_failure=0
	probe_failures_left=0
	identity_missing=0
	new_mac=001122334455
	prepare_failure=0
	MESHFIRMWARE_PARTITION_PACKAGE=""
	MESHFIRMWARE_USB_MIGRATION_SET=""
}
must_fail() {
	if esp32_prepare_partition_expansion_if_needed /dev/mock "$firmware_file" 'Mock ESP32' \
		>"$tmp_dir/result.out" 2>"$tmp_dir/result.err"; then
		echo "Unexpected partition expansion success" >&2
		exit 1
	fi
}

reset_case
EXECUTION_MODE=echo
esp32_prepare_partition_expansion_if_needed /dev/mock "$firmware_file" 'Mock ESP32' >/dev/null
[[ ! -s "$operation_log" ]]
echo 'PASS: echo-only never probes, downloads, begins or writes expansion'

reset_case
plan_needed=false
esp32_prepare_partition_expansion_if_needed /dev/mock "$firmware_file" 'Mock ESP32' >/dev/null
grep -Fq -- '--otadata' "$operation_log"
grep -Fq -- '--nvs' "$operation_log"
! grep -Eq '^begin$|write-flash|^finish |^verify ' "$operation_log"
[[ -z "$ESP32_PARTITION_EXPANSION_SCRATCH" ]]
echo 'PASS: fitting images use actual layout, capacity and OTA metadata but never boot the bridge'

reset_case
plan_needed=false
mkdir -p "$PWD_SCRIPT/tools"
printf 'local USB set fixture' >"$PWD_SCRIPT/tools/meshcore-usb-partition-bridges.zip"
MESHFIRMWARE_PARTITION_PACKAGE="$tmp_dir/exact-full-migration.zip"
esp32_prepare_partition_expansion_if_needed /dev/mock "$firmware_file" 'Mock ESP32' >/dev/null
grep -Fq -- "--usb-set $PWD_SCRIPT/tools/meshcore-usb-partition-bridges.zip" "$operation_log"
grep -Fq -- "--package $MESHFIRMWARE_PARTITION_PACKAGE" "$operation_log"
echo 'PASS: script-local standalone USB set and exact Full package overrides reach the helper'

reset_case
plan_needed=false
MESHFIRMWARE_USB_MIGRATION_SET="$tmp_dir/explicit-usb-set.zip"
esp32_prepare_partition_expansion_if_needed /dev/mock "$firmware_file" 'Mock ESP32' >/dev/null
grep -Fq -- "--usb-set $MESHFIRMWARE_USB_MIGRATION_SET" "$operation_log"
! grep -Fq -- "--usb-set $PWD_SCRIPT/tools/meshcore-usb-partition-bridges.zip" "$operation_log"
rm -f -- "$PWD_SCRIPT/tools/meshcore-usb-partition-bridges.zip"
echo 'PASS: explicit USB-set environment overrides the bundled local set'

reset_case
plan_needed=false
table_without_nvs="$tmp_dir/factory-no-nvs.bin"
command python3 - "$table_without_nvs" <<'PY'
import struct, sys
d = bytearray(b'\xff' * 4096)
struct.pack_into('<HBBII16sI', d, 0, 0x50aa, 0, 0, 0x10000, 0x200000, b'factory', 0)
open(sys.argv[1], 'wb').write(d)
PY
table_with_nvs="$table_fixture"
table_fixture="$table_without_nvs"
esp32_prepare_partition_expansion_if_needed /dev/mock "$firmware_file" 'Mock ESP32' >/dev/null
! grep -Fq -- '--nvs' "$operation_log"
! grep -Fq -- '--otadata' "$operation_log"
! grep -Eq '^begin$|write-flash|^finish ' "$operation_log"
table_fixture="$table_with_nvs"
echo 'PASS: no-NVS factory layouts reach ordinary app-fit validation without invented NVS reads'

reset_case
printf 'n\n' >"$choice_file"
must_fail
! grep -Eq '^begin$|write-flash|^finish |^verify ' "$operation_log"
echo 'PASS: denied expansion leaves helper and final firmware unwritten'

reset_case
esp32_prepare_partition_expansion_if_needed /dev/mock "$firmware_file" 'Mock ESP32' \
	>"$tmp_dir/result.out" 2>"$tmp_dir/result.err"
grep -Fq -- "write-flash 0x150000 $fixture_bridge_file" "$operation_log"
grep -Fq -- "write-flash 0x10000 $fixture_bridge_file" "$operation_log"
grep -Fq 'finish /dev/mock partition-expansion' "$operation_log"
grep -Fq 'uart-settled wait-uart --port /dev/same-radio --device-mac 001122334455 --timeout 180' "$operation_log"
grep -Fq "verify verify --plan $fixture_plan_file" "$operation_log"
! grep -Fq -- "$firmware_file" <(grep 'write-flash' "$operation_log")
[[ "$ESP32_FLASH_EXPECTED_MAC" == 001122334455 && "$DEVICE_PORT" == /dev/same-radio ]]
command python3 - "$operation_log" <<'PY'
import pathlib, sys
s = pathlib.Path(sys.argv[1]).read_text()
assert s.index('\nbegin\n') < s.index('write-flash 0x150000')
assert s.index('uart-python-preflight') < s.index('\nbegin\n')
assert s.index('write-flash 0x150000') < s.index('write-flash 0x10000')
assert s.index('finish /dev/mock partition-expansion') < s.index('physical-match')
assert s.index('physical-match') < s.index('uart-settled') < s.index('prepare ')
assert s.index('prepare ') < s.index('verify verify')
assert 'erase-flash' not in s
PY
echo 'PASS: UART helper phases are inactive-first, status-settled before reset, and raw-proof verified'

reset_case
plan_chip=9
probe_failures_left=1
esp32_prepare_partition_expansion_if_needed /dev/mock "$firmware_file" 'Mock ESP32' >/dev/null
grep -Fq 'rom-probe --port /dev/same-radio --before no-reset --after no-reset --baud 115200 read-mac' "$operation_log"
! grep -Eq '^prepare |^uart-settled |manual-match|usb-reset|default-reset' "$operation_log"
[[ "$ESP32_NATIVE_ROM_READY" == 1 && "$ESP32_SESSION_IS_S3" == 1 ]]
command python3 - "$operation_log" <<'PY'
import pathlib, sys
s = pathlib.Path(sys.argv[1]).read_text()
assert s.index('finish /dev/mock partition-expansion') < s.index('rom-probe')
assert s.index('rom-probe') < s.index('save /dev/same-radio') < s.index('verify verify')
PY
echo 'PASS: native USB waits for automatic ROM return with only no-reset same-MAC probes'

reset_case
plan_chip=5
esp32_prepare_partition_expansion_if_needed /dev/mock "$firmware_file" 'Mock ESP32' >/dev/null
[[ "$ESP32_NATIVE_ROM_READY" == 1 && "$ESP32_SESSION_IS_S3" == 0 ]]
! grep -Eq '^prepare |^uart-settled ' "$operation_log"
echo 'PASS: C3 automatic ROM return does not inherit S3 reset semantics'

reset_case
plan_resume=true
esp32_prepare_partition_expansion_if_needed /dev/mock "$firmware_file" 'Mock ESP32' >/dev/null
grep -Fq 'verify verify' "$operation_log"
! grep -Eq '^begin$|write-flash|^finish |^wait |^prepare ' "$operation_log"
echo 'PASS: interrupted target-layout migration verifies state without rewriting or resetting the bridge'

reset_case
plan_failure=1
must_fail
! grep -Eq '^begin$|write-flash|^finish |^verify ' "$operation_log"
echo 'PASS: invalid geometry, capacity, package or pending-plan refusal cannot write firmware'

reset_case
begin_failure=1
must_fail
! grep -Eq 'write-flash|^finish |^verify ' "$operation_log"
echo 'PASS: failed persisted recovery record refuses the first helper write'

reset_case
write_failure=1
must_fail
! grep -Eq '^finish |^verify ' "$operation_log"
echo 'PASS: failed helper write never boots or authorizes final firmware'

reset_case
new_mac=aabbccddeeff
must_fail
grep -Fq 'chip MAC changed' "$tmp_dir/result.err"
[[ "$ESP32_FLASH_EXPECTED_MAC" == 001122334455 ]]
! grep -Eq '^verify ' "$operation_log"
echo 'PASS: post-bridge chip swap refuses final firmware and restores the original MAC gate'

reset_case
prepare_failure=1
new_mac=aabbccddeeff
must_fail
[[ "$ESP32_FLASH_EXPECTED_MAC" == 001122334455 ]]
! grep -Eq '^verify ' "$operation_log"
echo 'PASS: failed new ROM preparation cannot leave cleanup bound to a replacement chip'

reset_case
verify_failure=1
must_fail
grep -Fq 'saved-state recovery did not verify' "$tmp_dir/result.err"
! grep -Fq -- "$firmware_file" <(grep 'write-flash' "$operation_log")
echo 'PASS: unverified NVS/table/OTA recovery refuses the selected final app'

reset_case
short_read=1
must_fail
grep -Fq 'returned 1 of 4096 bytes' "$tmp_dir/result.err"
! grep -Eq '^plan |^begin$|write-flash' "$operation_log"
echo 'PASS: truncated proof reads cannot trigger expansion'

reset_case
plan_chip=9
identity_missing=1
must_fail
grep -Fq 'No reset or final write was attempted' "$tmp_dir/result.err"
! grep -Eq '^prepare |^verify ' "$operation_log"
echo 'PASS: absent native USB times out without manual BOOT, reset, or guessing another radio'

reset_case
plan_chip=9
probe_failure=1
must_fail
! grep -Eq '^prepare |^verify ' "$operation_log"
echo 'PASS: USB endpoint presence without a no-reset ROM MAC answer never authorizes reset or final write'

reset_case
plan_chip=9
new_mac=aabbccddeeff
must_fail
[[ "$ESP32_FLASH_EXPECTED_MAC" == 001122334455 ]]
! grep -Eq '^prepare |^verify ' "$operation_log"
echo 'PASS: native USB ROM chip swap retains the original MAC gate'

reset_case
uart_failure=1
must_fail
! grep -Eq '^prepare |^verify ' "$operation_log"
echo 'PASS: missing UART settled status refuses host reset'

reset_case
uart_python_failure=1
must_fail
grep -Fq 'completion dependencies are unavailable' "$tmp_dir/result.err"
! grep -Eq '^begin$|write-flash|^finish |^prepare |^verify ' "$operation_log"
echo 'PASS: missing pyserial environment is refused before beginning or writing the UART bridge'

reset_case
uart_wrong_mac=1
must_fail
! grep -Eq '^prepare |^verify ' "$operation_log"
echo 'PASS: wrong-MAC UART settled status refuses host reset'

reset_case
uart_restored=false
verify_failure=1
must_fail
grep -Fq 'prepare ' "$operation_log"
grep -Fq 'verify verify' "$operation_log"
echo 'PASS: settled failure allows safe UART ROM return but raw restoration proof blocks final app'

reset_case
plan_usb_safe=false
must_fail
! grep -Eq '^begin$|write-flash|^finish ' "$operation_log"
echo 'PASS: an old Wi-Fi-only package is not accepted as a USB-safe bridge'

reset_case
plan_needed=false
esp32_prepare_partition_expansion_if_needed /dev/mock "$firmware_file" 'Mock ESP32' >/dev/null
printf 'changed final app' >>"$firmware_file"
if esp32_require_planned_firmware_hash "$firmware_file" 2>"$tmp_dir/result.err"; then
	echo 'Changed final firmware unexpectedly passed its planned hash' >&2; exit 1
fi
grep -Fq 'changed after partition planning' "$tmp_dir/result.err"
printf 'final app fixture' >"$firmware_file"
echo 'PASS: final firmware is rehashed against the plan before writing'

reset_case
command python3 - "$script_path" <<'PY'
import pathlib, sys
s = pathlib.Path(sys.argv[1]).read_text()
main = s[s.index('# MAIN'):]
update = main[main.index('echo "  serial preparation and identity-safe native USB handoff"',
                         main.index('else\n\t\techo "  serial preparation')):]
echo_gate = update.index('if [[ "$EXECUTION_MODE" == "echo" ]]')
expansion = update.index('esp32_prepare_partition_expansion_if_needed')
offsets = update.index('ESP32_UPDATE_OFFSETS_OUTPUT=""')
assert echo_gate < expansion < offsets
assert update.index('esp32_require_planned_firmware_hash', offsets) < update.index('run_esp32_session_esptool', offsets)
assert 'hold BOOT, tap RESET' not in s[s.index('esp32_prepare_partition_expansion_if_needed() {'):s.index('esp32_device_image_present_at_offset() {')]
finish = s[s.index('finish_esp32_flash_session() {'):s.index('\nprobe_esptool() {')]
assert finish.index('finish_kind" == partition-expansion') > finish.index('watchdog-resetting')
assert finish.index('finish_kind" == partition-expansion') < finish.index('if (( native_usb )); then\n\t\t# The identity-bound')
assert 'FLASHID="flash-id"' in s and 'FLASHID="flash_id"' in s
print('PASS: main keeps backup/echo gate before expansion, final offsets after proof, and safe bridge finish')
PY
