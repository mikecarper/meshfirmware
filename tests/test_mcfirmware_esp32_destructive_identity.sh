#!/usr/bin/env bash
# Fixture globals and function overrides are consumed by production functions
# evaluated below.
# shellcheck disable=SC2034,SC2317
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

for function_name in restore_port_after_bootloader_probe \
	record_esp32_chip_from_esptool_output \
	esp32_mac_from_esptool_output esp32_record_and_verify_probe_output \
	raw_esptool_mac_probe esp32_esptool_args_are_destructive \
	esp32_esptool_output_confirms_destructive_success \
	esp32_verified_destructive_port esp32_prepare_esptool_attempt \
	esptool_port_argument run_esptool run_esp32_session_esptool; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

ESP32_SESSION_IS_S3=0
ESP32_FLASH_EXPECTED_MAC=""
esp32_record_and_verify_probe_output $'Chip type: ESP32-S3\nMAC: 44:1b:f6:6a:e8:44'
[[ "$ESP32_FLASH_EXPECTED_MAC" == "441bf66ae844" ]]
[[ "$ESP32_SESSION_IS_S3" -eq 1 ]]
esp32_record_and_verify_probe_output 'MAC: 44:1B:F6:6A:E8:44'
if esp32_record_and_verify_probe_output 'MAC: d8:3b:da:75:23:ac' \
	>"${tmp_dir}/mismatch.out" 2>"${tmp_dir}/mismatch.err"; then
	echo "FAIL: a changed ESP32 chip MAC was accepted" >&2
	exit 1
fi
grep -Fq 'ESP32 chip identity changed' "${tmp_dir}/mismatch.err"
echo "PASS: ESP32 probes bind and enforce the chip MAC"

stale_port="${tmp_dir}/ttyACM2"
expected_live_port="${tmp_dir}/ttyACM7"
swapped_live_port="${tmp_dir}/ttyACM9"
touch "$stale_port" "$expected_live_port" "$swapped_live_port"
NORESET="no-reset"
READMAC="read-mac"
ESP32_OPERATION_BEFORE="$NORESET"
ESP32_PROBE_TIMEOUT_SECONDS=8
DEVICE_PORT="$stale_port"
probe_mac="44:1b:f6:6a:e8:44"
probe_log="${tmp_dir}/probe.log"
operation_log="${tmp_dir}/operation.log"
save_log="${tmp_dir}/save.log"
retry_marker="${tmp_dir}/retry.marker"
retry_mode=0
false_success_mode=0
selection_mode="stable"
selection_marker="${tmp_dir}/selection.marker"

selected_flash_serial_port() {
	if [[ "$selection_mode" == "post-probe-swap" ]]; then
		if [[ ! -e "$selection_marker" ]]; then
			: >"$selection_marker"
			printf '%s\n' "$expected_live_port"
		else
			printf '%s\n' "$swapped_live_port"
		fi
		return 0
	fi
	printf '%s\n' "$expected_live_port"
}
invoke_esptool_timeout() {
	printf '%s\n' "$*" >>"$probe_log"
	if (( retry_mode )) && [[ -e "$retry_marker" ]]; then
		printf '%s\n' 'MAC: d8:3b:da:75:23:ac'
	else
		printf 'Chip type: ESP32-S3\nMAC: %s\n' "$probe_mac"
	fi
}
save_selected_serial_port() {
	DEVICE_PORT="$1"
	printf '%s\n' "$1" >>"$save_log"
}
invoke_esptool() {
	printf '%s\n' "$*" >>"$operation_log"
	if (( retry_mode )) && [[ ! -e "$retry_marker" ]]; then
		: >"$retry_marker"
		printf '%s\n' 'Device or resource busy'
		return 37
	fi
	if (( false_success_mode == 1 )); then
		printf '%s\n' 'esptool.py v5 simulated incomplete output'
		return 0
	fi
	if (( false_success_mode == 2 )); then
		printf '%s\n' 'A fatal error occurred: simulated conflicting result'
	fi
	case " $* " in
		*" erase-flash "*|*" erase_flash "*)
			printf '%s\n' 'Flash memory erased successfully in 1.0 seconds.'
			;;
		*" erase-region "*|*" erase_region "*)
			printf '%s\n' 'Flash memory region erased successfully in 1.0 seconds.'
			;;
		*" write-flash "*|*" write_flash "*)
			printf '%s\n' 'Hash of data verified.'
			;;
	esac
}
esptool_output_port_busy() { grep -qi 'Device or resource busy' <<<"$1"; }
recover_busy_serial_port() { return 0; }
esptool_output_needs_reset() { return 1; }
no_sudo_mode() { return 0; }
auto_reset_serial_port() { return 1; }
manual_reboot_choice() { return 1; }
print_esptool_recovery_hint() { return 0; }

run_esp32_session_esptool "$stale_port" --after no-reset erase-flash
run_esp32_session_esptool "$stale_port" --after no-reset write-flash 0x0 firmware.bin
[[ "$(wc -l <"$probe_log")" -eq 2 ]]
[[ "$(wc -l <"$operation_log")" -eq 2 ]]
[[ ! -e "$save_log" ]]
grep -Fxq -- "8s --port $expected_live_port --before no-reset --after no-reset --baud 115200 read-mac" "$probe_log"
grep -Fxq -- "--port $expected_live_port --before no-reset --after no-reset erase-flash" "$operation_log"
grep -Fxq -- "--port $expected_live_port --before no-reset --after no-reset write-flash 0x0 firmware.bin" "$operation_log"
[[ "$DEVICE_PORT" == "$expected_live_port" ]]
echo "PASS: every destructive ESP32 command re-resolves by-id, probes MAC, and does not rebind identity"

run_esp32_session_esptool "$stale_port" --after no-reset read-flash 0x0 4 read.bin
[[ "$(wc -l <"$probe_log")" -eq 2 ]]
grep -Fxq -- "--port $stale_port --before no-reset --after no-reset read-flash 0x0 4 read.bin" "$operation_log"
echo "PASS: non-destructive ESP32 reads do not recursively invoke the destructive gate"

retry_mode=1
rm -f "$retry_marker"
before_count="$(wc -l <"$operation_log")"
if run_esp32_session_esptool "$stale_port" --after no-reset erase-flash \
	>"${tmp_dir}/retry.out" 2>"${tmp_dir}/retry.err"; then
	echo "FAIL: a retry continued after the selected ESP32 MAC changed" >&2
	exit 1
fi
[[ "$(wc -l <"$operation_log")" -eq $((before_count + 1)) ]]
grep -Fq 'did not pass its MAC identity probe immediately before' "${tmp_dir}/retry.err"
retry_mode=0
echo "PASS: each internal destructive retry repeats the by-id and MAC gate"

false_success_mode=1
before_count="$(wc -l <"$operation_log")"
while IFS='|' read -r command expected_error; do
	read -r -a command_args <<<"$command"
	if run_esp32_session_esptool "$stale_port" --after no-reset "${command_args[@]}" \
		>"${tmp_dir}/false-success.out" 2>"${tmp_dir}/false-success.err"; then
		echo "FAIL: ${command_args[0]} accepted a zero exit without completion evidence" >&2
		exit 1
	fi
	grep -Fq "$expected_error" "${tmp_dir}/false-success.err"
done <<'EOF'
erase-flash|did not confirm the chip erase
erase-region 0x0 4096|did not confirm the region erase
write-flash 0x0 firmware.bin|did not confirm flash data verification
EOF
[[ "$(wc -l <"$operation_log")" -eq $((before_count + 3)) ]]
false_success_mode=0
echo "PASS: zero-exit destructive esptool commands require completion evidence"

false_success_mode=2
before_count="$(wc -l <"$operation_log")"
if run_esp32_session_esptool "$stale_port" --after no-reset write-flash 0x0 firmware.bin \
	>"${tmp_dir}/conflicting-success.out" 2>"${tmp_dir}/conflicting-success.err"; then
	echo "FAIL: esptool fatal output was accepted alongside a completion marker" >&2
	exit 1
fi
[[ "$(wc -l <"$operation_log")" -eq $((before_count + 1)) ]]
grep -Fq 'reported a fatal error' "${tmp_dir}/conflicting-success.err"
false_success_mode=0
echo "PASS: fatal esptool output overrides a conflicting completion marker"

selection_mode="post-probe-swap"
rm -f "$selection_marker"
before_count="$(wc -l <"$operation_log")"
if run_esp32_session_esptool "$stale_port" --after no-reset erase-flash \
	>"${tmp_dir}/post-probe-swap.out" 2>"${tmp_dir}/post-probe-swap.err"; then
	echo "FAIL: a by-id change after the MAC probe reached erase-flash" >&2
	exit 1
fi
[[ "$(wc -l <"$operation_log")" -eq "$before_count" ]]
grep -Fq 'changed ports after its MAC probe' "${tmp_dir}/post-probe-swap.err"
selection_mode="stable"
echo "PASS: a by-id change after the MAC probe blocks the destructive invocation"

probe_mac="d8:3b:da:75:23:ac"
before_count="$(wc -l <"$operation_log")"
if run_esp32_session_esptool "$stale_port" --after no-reset write-flash 0x0 firmware.bin \
	>"${tmp_dir}/blocked.out" 2>"${tmp_dir}/blocked.err"; then
	echo "FAIL: changed ESP32 MAC reached write-flash" >&2
	exit 1
fi
[[ "$(wc -l <"$operation_log")" -eq "$before_count" ]]
grep -Fq 'did not pass its MAC identity probe immediately before' "${tmp_dir}/blocked.err"
echo "PASS: a MAC mismatch blocks the destructive esptool invocation"

selected_flash_serial_port() { return 1; }
if run_esp32_session_esptool "$stale_port" --after no-reset erase-flash \
	>"${tmp_dir}/missing.out" 2>"${tmp_dir}/missing.err"; then
	echo "FAIL: missing stable USB identity reached erase-flash" >&2
	exit 1
fi
[[ "$(wc -l <"$operation_log")" -eq "$before_count" ]]
echo "PASS: a missing saved by-id blocks the destructive esptool invocation"

cleanup_reset_log="${tmp_dir}/cleanup-reset.log"
esp32_verified_destructive_port() { return 1; }
invoke_esptool_timeout() { printf '%s\n' "$*" >>"$cleanup_reset_log"; }
BOOTLOADER_PROBE_ACTIVE=1
BOOTLOADER_PROBE_PORT="$stale_port"
restore_port_after_bootloader_probe 2>"${tmp_dir}/cleanup-blocked.err"
[[ ! -e "$cleanup_reset_log" ]]
[[ "$BOOTLOADER_PROBE_ACTIVE" -eq 0 && -z "$BOOTLOADER_PROBE_PORT" ]]
grep -Fq 'selected USB identity could not be reverified' "${tmp_dir}/cleanup-blocked.err"

safe_cleanup_port="${tmp_dir}/ttyACM-cleanup"
touch "$safe_cleanup_port"
esp32_verified_destructive_port() { printf '%s\n' "$safe_cleanup_port"; }
BOOTLOADER_PROBE_ACTIVE=1
BOOTLOADER_PROBE_PORT="$stale_port"
restore_port_after_bootloader_probe 2>"${tmp_dir}/cleanup-allowed.err"
grep -Fxq -- "8s --port $safe_cleanup_port --before no-reset --after hard-reset read-mac" \
	"$cleanup_reset_log"
[[ "$BOOTLOADER_PROBE_ACTIVE" -eq 0 && -z "$BOOTLOADER_PROBE_PORT" ]]
echo "PASS: ESP32 cleanup reset also requires the live verified USB identity"
