#!/usr/bin/env bash
# Exercise identity-gated chunk recovery after a native USB write disconnect.
# Fixture globals are consumed by production functions evaluated below.
# shellcheck disable=SC2034
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

for function_name in esptool_port_argument \
	esp32_esptool_output_confirms_destructive_success \
	esptool_output_transport_interrupted esp32_replace_after_mode \
	esp32_recover_interrupted_transport esp32_run_chunked_write_recovery \
	run_esptool; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

source_image="${tmp_dir}/firmware.bin"
truncate -s 50000 "$source_image"
operation_log="${tmp_dir}/operations.log"
recovery_log="${tmp_dir}/recoveries.log"
chunk_retry_marker="${tmp_dir}/chunk-retry.marker"
live_port="${tmp_dir}/ttyACM4"
fixture_live_port="$live_port"
touch "$live_port"

NORESET="no-reset"
USBRESET="usb-reset"
READMAC="read-mac"
DEVICE_PORT="$live_port"
ESP32_NATIVE_ROM_READY=1
ESP32_FLASH_SELECTED_BY_ID=""
ESP32_FLASH_RECOVERY_ATTEMPTS=3
ESP32_FLASH_RECOVERY_CHUNK_BYTES=16384

selected_flash_serial_port() { printf '%s\n' "$fixture_live_port"; }
esp32_port_uses_native_usb() { return 0; }
raw_esptool_mac_probe() {
	printf '%s\n' "$*" >>"$recovery_log"
	return 0
}
esp32_prepare_esptool_attempt() {
	local args_name=$1
	local port_name=$2
	shift 2
	local -n prepared_args_ref="$args_name"
	local -n prepared_port_ref="$port_name"
	prepared_args_ref=("$@")
	prepared_port_ref="$(esptool_port_argument "$@")"
}

invoke_esptool() {
	local previous="" arg after="" offset="" file="" command_seen=0
	for arg in "$@"; do
		if [[ "$previous" == "--after" ]]; then
			after="$arg"
		fi
		case "$arg" in
			--after=*) after="${arg#--after=}" ;;
			write-flash|write_flash) command_seen=1 ;;
			*)
				if (( command_seen )) && [[ -z "$offset" ]]; then
					offset="$arg"
				elif (( command_seen )) && [[ -z "$file" ]]; then
					file="$arg"
				fi
				;;
		esac
		previous="$arg"
	done

	if [[ "$file" == "$source_image" ]]; then
		printf '%s\n' 'A fatal error occurred: No more data to read from the serial port.'
		return 37
	fi

	printf '%s|%s|%s\n' "$offset" "$(stat -c %s "$file")" "$after" >>"$operation_log"
	if [[ "$offset" == "0x10000" && ! -e "$chunk_retry_marker" ]]; then
		: >"$chunk_retry_marker"
		printf '%s\n' 'A fatal error occurred: device reports readiness to read but returned no data'
		return 38
	fi
	printf '%s\n' 'Hash of data verified.'
}

esptool_output_port_busy() { return 1; }
esptool_output_needs_reset() { return 1; }
no_sudo_mode() { return 0; }
auto_reset_serial_port() { return 1; }
manual_reboot_choice() { return 1; }
print_esptool_recovery_hint() { return 0; }

run_esptool --port "$live_port" --before no-reset --after watchdog-reset \
	--baud 115200 write-flash 0x10000 "$source_image" \
	>"${tmp_dir}/recovery.out" 2>"${tmp_dir}/recovery.err"

grep -Fq 'retrying in 16384-byte verified chunks' "${tmp_dir}/recovery.out"
grep -Fq 'chunked recovery completed' "${tmp_dir}/recovery.out"
[[ "$(wc -l <"$operation_log")" -eq 5 ]]
[[ "$(sed -n '1p' "$operation_log")" == '0x10000|16384|no-reset' ]]
[[ "$(sed -n '2p' "$operation_log")" == '0x10000|16384|no-reset' ]]
[[ "$(sed -n '3p' "$operation_log")" == '0x14000|16384|no-reset' ]]
[[ "$(sed -n '4p' "$operation_log")" == '0x18000|16384|no-reset' ]]
[[ "$(sed -n '5p' "$operation_log")" == '0x1c000|848|watchdog-reset' ]]
[[ "$(wc -l <"$recovery_log")" -eq 2 ]]
while IFS= read -r recovery; do
	[[ "$recovery" == *"--before usb-reset --after no-reset --baud 115200 read-mac"* ]]
done <"$recovery_log"

esptool_output_transport_interrupted \
	'A fatal error occurred: No more data to read from the serial port.'
esptool_output_transport_interrupted \
	'A serial exception error occurred: device reports readiness to read but returned no data'
if esptool_output_transport_interrupted 'A fatal error occurred: invalid image header'; then
	echo "FAIL: a non-transport flash error was classified as recoverable" >&2
	exit 1
fi

echo "PASS: interrupted ESP32 writes recover in identity-gated verified chunks"
