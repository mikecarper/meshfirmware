#!/usr/bin/env bash
# Hardware-free integration of the real post-reset waiter and selection saver.
# shellcheck disable=SC2034
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
for function_name in normalize_usb_serial_identity nrf52_usb_path_stem \
	nrf52_candidate_identity_rank nrf52_candidate_matches_identity \
	serial_by_id_link_for_port save_selected_serial_port \
	wait_for_esp32_primary_usb_port_after_reset \
	esp32_port_is_rom_usb_jtag esp32_require_native_s3_watchdog_reset \
	finish_esp32_flash_session restore_port_after_bootloader_probe; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "$function_name() {"* ]] || {
		echo "FAIL: could not extract $function_name" >&2
		exit 1
	}
	# Deliberately evaluate only functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

original_port="$tmp_dir/ttyACM0"
returned_port="$tmp_dir/ttyACM1"
other_port="$tmp_dir/ttyACM2"
by_id_dir="$tmp_dir/by-id"
properties_dir="$tmp_dir/properties"
mkdir "$by_id_dir" "$properties_dir"
touch "$original_port" "$returned_port" "$other_port"
NRF52_SERIAL_BY_ID_DIR="$by_id_dir"
selected_by_id="$by_id_dir/usb-Espressif_original-if00"
expected_serial='30:ed:a0:38:f7:ac'
expected_path_stem='pci-test-usb-0:4'
fixture_port_file="$tmp_dir/candidate"
finder_log="$tmp_dir/finder.log"
lookup_log="$tmp_dir/lookup.log"
tool_log="$tmp_dir/tools.log"
sleep_log="$tmp_dir/sleep.log"
create_link_on_sleep="$tmp_dir/create-link"
remove_link_on_property="$tmp_dir/remove-property"
remove_link_on_lookup="$tmp_dir/remove-lookup"
reassign_link_on_property="$tmp_dir/reassign-property"
output_file="$tmp_dir/output"
error_file="$tmp_dir/error"

write_properties() {
	local port=$1 serial=$2 path=$3
	printf '%s\n' "$serial" >"$properties_dir/$(basename "$port").ID_SERIAL_SHORT"
	printf '%s\n' "$path" >"$properties_dir/$(basename "$port").ID_PATH"
	printf '00\n' >"$properties_dir/$(basename "$port").ID_USB_INTERFACE_NUM"
}
udev_device_property() {
	local port=$1 property=$2
	if [[ "$property" == ID_SERIAL_SHORT && -f "$remove_link_on_property" ]]; then
		rm -f -- "$fixture_link" "$remove_link_on_property"
	fi
	if [[ "$property" == ID_SERIAL_SHORT && -f "$reassign_link_on_property" ]]; then
		ln -sfn -- "$other_port" "$fixture_link"
		rm -f -- "$reassign_link_on_property"
	fi
	case "$property" in
		ID_VENDOR_ID) printf '303a\n' ;;
		ID_MODEL_ID) printf '1001\n' ;;
		ID_MODEL) printf 'USB_JTAG_serial_debug_unit\n' ;;
		*) cat "$properties_dir/$(basename "$port").$property" ;;
	esac
}
readlink() {
	local result target="${*: -1}"
	printf '%s\n' "$target" >>"$lookup_log"
	result="$(command readlink "$@")" || return $?
	if [[ "$target" == "$fixture_link" && -f "$remove_link_on_lookup" ]]; then
		rm -f -- "$fixture_link" "$remove_link_on_lookup"
	fi
	printf '%s\n' "$result"
}
find_reenumerated_nrf52_port() {
	printf '%s\n' "$*" >>"$finder_log"
	[[ "$1" == "$original_port" && "$2" == "$selected_by_id" \
		&& "$3" == "$expected_serial" && "$4" == "$expected_path_stem" && -z "$5" ]] || return 1
	case "$fixture_mode" in
		ambiguous) return 2 ;;
		missing-device) return 1 ;;
		*) cat "$fixture_port_file" ;;
	esac
}
sleep() {
	printf '%s\n' "$*" >>"$sleep_log"
	# A fixture-local Bash clock makes bounded failures immediate, not busy loops.
	SECONDS=$((SECONDS + 1))
	if [[ -f "$create_link_on_sleep" ]]; then
		ln -sfn -- "$fixture_candidate" "$fixture_link"
		rm -f -- "$create_link_on_sleep"
	fi
}
unexpected_tool() {
	printf 'UNEXPECTED %s\n' "$*" >>"$tool_log"
	return 1
}
invoke_esptool_timeout() { unexpected_tool "$@"; }
run_esp32_session_esptool() { unexpected_tool "$@"; }
run_esptool() { unexpected_tool "$@"; }
selected_flash_serial_port() { printf '%s\n' "$original_port"; }
esp32_verified_destructive_port() { printf '%s\n' "$original_port"; }

reset_fixture() {
	rm -f -- "$by_id_dir"/* "$create_link_on_sleep" "$remove_link_on_property" \
		"$remove_link_on_lookup" "$reassign_link_on_property"
	fixture_mode=unique
	fixture_candidate="$returned_port"
	fixture_link="$by_id_dir/usb-MeshCore_returned-if00"
	printf '%s\n' "$fixture_candidate" >"$fixture_port_file"
	DEVICE_PORT_FILE="$tmp_dir/cached-port"
	DEVICE_PORT_NAME_FILE="$tmp_dir/cached-name"
	DEVICE_PORT="$original_port"
	printf '%s\n' "$original_port" >"$DEVICE_PORT_FILE"
	basename "$selected_by_id" >"$DEVICE_PORT_NAME_FILE"
	write_properties "$original_port" "$expected_serial" "$expected_path_stem:1.0"
	write_properties "$returned_port" "$expected_serial" "$expected_path_stem:1.0"
	write_properties "$other_port" '11:22:33:44:55:66' 'pci-test-usb-0:9:1.0'
	: >"$finder_log"; : >"$lookup_log"; : >"$tool_log"; : >"$sleep_log"
	ESP32_FLASH_REENUMERATE_TIMEOUT_SECONDS=0
	ESP32_FLASH_REENUMERATE_POLL_SECONDS=0.01
	SECONDS=0
}
assert_saved() {
	[[ "$DEVICE_PORT" == "$fixture_candidate" \
		&& "$(cat "$DEVICE_PORT_FILE")" == "$fixture_candidate" \
		&& "$(cat "$DEVICE_PORT_NAME_FILE")" == "$(basename "$fixture_link")" ]]
	[[ ! -s "$tool_log" ]]
}
assert_unchanged() {
	[[ "$DEVICE_PORT" == "$original_port" \
		&& "$(cat "$DEVICE_PORT_FILE")" == "$original_port" \
		&& "$(cat "$DEVICE_PORT_NAME_FILE")" == "$(basename "$selected_by_id")" ]]
	[[ ! -s "$tool_log" ]]
}
wait_for_return() {
	wait_for_esp32_primary_usb_port_after_reset "$original_port" "$selected_by_id" \
		"$expected_serial" "$expected_path_stem"
}
assert_wait_refuses() {
	if wait_for_return >"$output_file" 2>"$error_file"; then
		echo "FAIL: $1 unexpectedly accepted a post-reset USB selection" >&2
		exit 1
	fi
	assert_unchanged
	[[ ! -s "$output_file" ]]
	grep -Fq 'Application startup remains unverified; no additional reset or flash was attempted' "$error_file"
	echo "PASS: $1 stays blocked without changing cached selection or issuing tools"
}

reset_fixture
ESP32_FLASH_REENUMERATE_TIMEOUT_SECONDS=2
touch "$create_link_on_sleep"
wait_for_return >"$output_file" 2>"$error_file"
assert_saved
[[ "$(wc -l <"$finder_log")" -ge 2 && "$(wc -l <"$sleep_log")" -eq 1 ]]
! grep -Fq 'refusing tty-only' "$error_file"
echo 'PASS: a renumbered matching tty waits for its delayed by-id link before saving'

reset_fixture
fixture_candidate="$original_port"
fixture_link="$selected_by_id"
printf '%s\n' "$fixture_candidate" >"$fixture_port_file"
ln -s -- "$fixture_candidate" "$fixture_link"
wait_for_return >"$output_file" 2>"$error_file"
assert_saved
[[ ! -s "$sleep_log" ]]
echo 'PASS: an unchanged qualified endpoint is accepted without requiring tty renumbering'

reset_fixture
ln -s -- "$fixture_candidate" "$fixture_link"
write_properties "$fixture_candidate" '30EDA038F7AC' 'pci-test-usb-0:9:1.0'
wait_for_return >"$output_file" 2>"$error_file"
assert_saved
echo 'PASS: the same normalized USB serial can survive a VM physical-path change'

reset_fixture
ESP32_FLASH_REENUMERATE_TIMEOUT_SECONDS=2
ln -s -- "$fixture_candidate" "$fixture_link"
touch "$remove_link_on_property" "$create_link_on_sleep"
wait_for_return >"$output_file" 2>"$error_file"
assert_saved
[[ "$(wc -l <"$finder_log")" -ge 2 && "$(wc -l <"$sleep_log")" -eq 1 ]]
echo 'PASS: a link disappearing during validation can settle within the original deadline'

reset_fixture
assert_wait_refuses 'a bare tty whose stable by-id identity never appears'

reset_fixture
fixture_mode=missing-device
assert_wait_refuses 'a missing post-reset device'

reset_fixture
fixture_mode=ambiguous
ln -s -- "$fixture_candidate" "$fixture_link"
assert_wait_refuses 'ambiguous physical-device discovery'
[[ ! -s "$lookup_log" ]]

reset_fixture
ln -s -- "$fixture_candidate" "$fixture_link"
ln -s -- "$fixture_candidate" "$by_id_dir/usb-duplicate-if00"
assert_wait_refuses 'multiple by-id aliases for one tty'

for event in "$remove_link_on_property" "$remove_link_on_lookup" "$reassign_link_on_property"; do
	reset_fixture
	ln -s -- "$fixture_candidate" "$fixture_link"
	touch "$event"
	assert_wait_refuses "a stable link disappearing or changing during validation ($(basename "$event"))"
done

reset_fixture
fixture_link="$selected_by_id"
ln -s -- "$fixture_candidate" "$fixture_link"
write_properties "$fixture_candidate" 'AA:BB:CC:DD:EE:FF' 'pci-test-usb-0:9:1.0'
assert_wait_refuses 'a reused exact by-id name with contradictory USB serial evidence'

reset_fixture
ln -s -- "$fixture_candidate" "$fixture_link"
if save_selected_serial_port "$fixture_candidate" '' '' '' >"$output_file" 2>"$error_file"; then
	echo 'FAIL: explicit empty expected identity became an unchecked legacy save' >&2
	exit 1
fi
assert_unchanged
echo 'PASS: explicit empty identity arguments cannot bypass post-reset identity checks'

reset_fixture
ln -s -- "$fixture_candidate" "$fixture_link"
DEVICE_PORT_FILE="$tmp_dir/nonexistent-directory/cached-port"
if wait_for_return >"$output_file" 2>"$error_file"; then
	echo 'FAIL: a failed cache write was reported as a successful USB handoff' >&2
	exit 1
fi
[[ "$DEVICE_PORT" == "$original_port" && ! -s "$sleep_log" && ! -s "$tool_log" ]]
grep -Fq 'Could not save the ESP32 USB selection cache after reset' "$error_file"
echo 'PASS: cache-write failures are reported immediately without a new reset or retry loop'

# Finally exercise the production finish function, not a mocked waiter/saver.
invoke_esptool_timeout() {
	printf '%s\n' "$*" >>"$tool_log"
	[[ "$BOOTLOADER_PROBE_ACTIVE" == 0 && -z "$BOOTLOADER_PROBE_PORT" \
		&& "$ESP32_NATIVE_ROM_READY" == 1 ]]
}
NORESET=no-reset
HARDRESET=hard-reset
WATCHDOGRESET=watchdog-reset
READMAC=read-mac
ESP32_SESSION_IS_S3=1
ESP32_FLASH_SELECTED_BY_ID="$selected_by_id"
ESP32_FLASH_EXPECTED_SERIAL="$expected_serial"
ESP32_FLASH_EXPECTED_PATH_STEM="$expected_path_stem"
for completion in delayed missing; do
	reset_fixture
	ESP32_FLASH_REENUMERATE_TIMEOUT_SECONDS=2
	BOOTLOADER_PROBE_ACTIVE=1
	BOOTLOADER_PROBE_PORT="$original_port"
	ESP32_NATIVE_ROM_READY=1
	if [[ "$completion" == delayed ]]; then
		touch "$create_link_on_sleep"
		finish_esp32_flash_session "$original_port" >"$output_file" 2>"$error_file"
		[[ "$DEVICE_PORT" == "$fixture_candidate" \
			&& "$(cat "$DEVICE_PORT_FILE")" == "$fixture_candidate" \
			&& "$(cat "$DEVICE_PORT_NAME_FILE")" == "$(basename "$fixture_link")" ]]
		grep -Fq "Matched ESP32 physical USB port after reset: $fixture_candidate" "$output_file"
	else
		if finish_esp32_flash_session "$original_port" >"$output_file" 2>"$error_file"; then
			echo 'FAIL: finish accepted a raw tty without a stable by-id link' >&2
			exit 1
		fi
		[[ "$DEVICE_PORT" == "$original_port" \
			&& "$(cat "$DEVICE_PORT_FILE")" == "$original_port" \
			&& "$(cat "$DEVICE_PORT_NAME_FILE")" == "$(basename "$selected_by_id")" ]]
	fi
	[[ "$BOOTLOADER_PROBE_ACTIVE" == 0 && -z "$BOOTLOADER_PROBE_PORT" \
		&& "$ESP32_NATIVE_ROM_READY" == 0 ]]
	restore_port_after_bootloader_probe
	[[ "$(wc -l <"$tool_log")" -eq 1 ]]
	grep -Fxq "12s --port $original_port --before no-reset --after watchdog-reset write-mem 0x6000812c 0x0 0x1" "$tool_log"
	echo "PASS: production S3 finish ($completion) sends exactly one qualified reset and no later ROM commands"
done

echo 'ESP32 post-reset stable identity integration: OK'
