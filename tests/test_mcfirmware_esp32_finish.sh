#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

definition="$(sed -n '/^finish_esp32_flash_session() {/,/^}/p' "$repo_root/mcfirmware.sh")"
[[ "$definition" == 'finish_esp32_flash_session() {'* ]]
eval "$definition"
definition="$(sed -n '/^esp32_require_native_s3_watchdog_reset() {/,/^}/p' "$repo_root/mcfirmware.sh")"
[[ "$definition" == 'esp32_require_native_s3_watchdog_reset() {'* ]]
eval "$definition"
definition="$(sed -n '/^esp32_port_is_rom_usb_jtag() {/,/^}/p' "$repo_root/mcfirmware.sh")"
[[ "$definition" == 'esp32_port_is_rom_usb_jtag() {'* ]]
eval "$definition"
definition="$(sed -n '/^restore_port_after_bootloader_probe() {/,/^}/p' "$repo_root/mcfirmware.sh")"
[[ "$definition" == 'restore_port_after_bootloader_probe() {'* ]]
eval "$definition"

rom_port="$tmp_dir/rom-port"
fixture_runtime_port="$tmp_dir/runtime-port"
touch "$rom_port" "$fixture_runtime_port"
DEVICE_PORT="$rom_port"
HARDRESET=hard-reset
WATCHDOGRESET=watchdog-reset
NORESET=no-reset
READMAC=read-mac
ESP32_SESSION_IS_S3=1
ESP32_FLASH_SELECTED_BY_ID=usb-esp32
ESP32_FLASH_EXPECTED_SERIAL=CC8DA2E96F34
ESP32_FLASH_EXPECTED_PATH_STEM=usb-esp32
BOOTLOADER_PROBE_ACTIVE=1
BOOTLOADER_PROBE_PORT="$rom_port"
ESP32_NATIVE_ROM_READY=1

selected_flash_serial_port() {
	[[ "${selected_identity_ok:-1}" == 1 ]] || return 1
	printf '%s\n' "$rom_port"
}
# HWCDC application and ROM share these fixed hardware descriptors. Exercise
# the real production classifier instead of assigning mode by fixture tty name.
udev_device_property() {
	case "$2" in
		ID_VENDOR_ID) printf '%s\n' '303a' ;;
		ID_MODEL_ID) printf '%s\n' '1001' ;;
		ID_MODEL) printf '%s\n' 'USB_JTAG_serial_debug_unit' ;;
		*) return 1 ;;
	esac
}
nrf52_port_instance() { printf '%s\n' '1-1:1.0'; }
esp32_verified_destructive_port() { printf '%s\n' "$rom_port"; }
run_esp32_session_esptool() {
	printf '%s\n' "$*" >> "$tmp_dir/unexpected-retry.log"
	return 1
}
invoke_esptool_timeout() {
	printf '%s\n' "$*" >> "$tmp_dir/esptool.log"
	# The proven ROM marker exists only for this command's safe serial open;
	# exit cleanup is already disarmed in case reset races a USB error.
	[[ "$ESP32_NATIVE_ROM_READY" == 1 && "$BOOTLOADER_PROBE_ACTIVE" == 0 \
		&& -z "$BOOTLOADER_PROBE_PORT" ]] || return 1
	[[ "${reset_ok:-1}" == 1 ]]
}
wait_for_nrf52_bootloader_port() {
	printf '%s\n' "$*" >> "$tmp_dir/wait.log"
	# Only a successful verified reset may relax the inode-change demand.
	[[ -z "$5" ]] || return 1
	[[ "${runtime_ok:-1}" == 1 ]] || return 1
	if [[ "${same_endpoint:-0}" == 1 ]]; then
		printf '%s\n' "$rom_port"
		return 0
	fi
	printf '%s\n' "$fixture_runtime_port"
}
save_selected_serial_port() {
	printf '%s\n' "$1" >> "$tmp_dir/saved.log"
}

finish_esp32_flash_session "$rom_port" > "$tmp_dir/output.log"
[[ "$(cat "$tmp_dir/esptool.log")" == "12s --port $rom_port --before no-reset --after watchdog-reset write-mem 0x6000812c 0x0 0x1" ]]
[[ "$(cat "$tmp_dir/saved.log")" == "$fixture_runtime_port" ]]
[[ "$BOOTLOADER_PROBE_ACTIVE" == 0 && -z "$BOOTLOADER_PROBE_PORT" \
	&& "$ESP32_NATIVE_ROM_READY" == 0 ]]
grep -Fq 'Application boot is not confirmed by USB descriptors' "$tmp_dir/output.log"
echo 'PASS: identical USB/JTAG application descriptors are not rejected as ROM proof'

reset_ok=0
BOOTLOADER_PROBE_ACTIVE=1
BOOTLOADER_PROBE_PORT="$rom_port"
ESP32_NATIVE_ROM_READY=1
: > "$tmp_dir/wait.log"
: > "$tmp_dir/esptool.log"
if finish_esp32_flash_session "$rom_port" >/dev/null 2>&1; then
	echo 'ESP32 finish passed after mask write/watchdog reset failed' >&2
	exit 1
fi
[[ "$BOOTLOADER_PROBE_ACTIVE" == 0 && -z "$BOOTLOADER_PROBE_PORT" \
	&& "$ESP32_NATIVE_ROM_READY" == 0 ]]
[[ ! -s "$tmp_dir/wait.log" ]]
restore_port_after_bootloader_probe
[[ "$(wc -l < "$tmp_dir/esptool.log")" == 1 ]]
[[ ! -e "$tmp_dir/unexpected-retry.log" ]]
echo 'PASS: ambiguous mask write/watchdog reset failure cannot trigger automatic SLIP cleanup'

reset_ok=1
runtime_ok=0
BOOTLOADER_PROBE_ACTIVE=1
BOOTLOADER_PROBE_PORT="$rom_port"
ESP32_NATIVE_ROM_READY=1
: > "$tmp_dir/esptool.log"
if finish_esp32_flash_session "$rom_port" >/dev/null 2>&1; then
	echo 'ESP32 finish passed without runtime USB identity' >&2
	exit 1
fi
[[ "$BOOTLOADER_PROBE_ACTIVE" == 0 && -z "$BOOTLOADER_PROBE_PORT" \
	&& "$ESP32_NATIVE_ROM_READY" == 0 ]]
[[ "$(cat "$tmp_dir/esptool.log")" == "12s --port $rom_port --before no-reset --after watchdog-reset write-mem 0x6000812c 0x0 0x1" ]]
restore_port_after_bootloader_probe
[[ "$(wc -l < "$tmp_dir/esptool.log")" == 1 ]]
[[ ! -e "$tmp_dir/unexpected-retry.log" ]]
echo 'PASS: failed post-reset USB wait cannot leave a ROM cleanup session active'
runtime_ok=1
same_endpoint=1
BOOTLOADER_PROBE_ACTIVE=1
BOOTLOADER_PROBE_PORT="$rom_port"
ESP32_NATIVE_ROM_READY=1
: > "$tmp_dir/esptool.log"
: > "$tmp_dir/saved.log"
finish_esp32_flash_session "$rom_port" > "$tmp_dir/same-endpoint-output.log"
[[ "$(cat "$tmp_dir/esptool.log")" == "12s --port $rom_port --before no-reset --after watchdog-reset write-mem 0x6000812c 0x0 0x1" ]]
[[ "$(cat "$tmp_dir/saved.log")" == "$rom_port" ]]
grep -Fq "Matched ESP32 physical USB port after reset: $rom_port" \
	"$tmp_dir/same-endpoint-output.log"
grep -Fq 'Application boot is not confirmed by USB descriptors' \
	"$tmp_dir/same-endpoint-output.log"
echo 'PASS: same tty and hardware descriptor remain valid physical identity, not application proof'

NORESET=no_reset
WATCHDOGRESET=watchdog_reset
: > "$tmp_dir/esptool.log"
: > "$tmp_dir/wait.log"
if finish_esp32_flash_session "$rom_port" >"$tmp_dir/old-esptool.out" 2>"$tmp_dir/old-esptool.err"; then
	echo 'ESP32 native S3 finish accepted esptool 4 without watchdog support' >&2
	exit 1
fi
[[ ! -s "$tmp_dir/esptool.log" && ! -s "$tmp_dir/wait.log" ]]
grep -Fq 'requires esptool 5 or newer' "$tmp_dir/old-esptool.err"
echo 'PASS: native S3 esptool 4 fails before an unsupported mask-write/reset operation'
NORESET=no-reset
WATCHDOGRESET=watchdog-reset

selected_identity_ok=0
: > "$tmp_dir/esptool.log"
if finish_esp32_flash_session "$rom_port" >/dev/null 2>&1; then
	echo 'ESP32 finish accepted a missing or mismatched selected identity' >&2
	exit 1
fi
[[ ! -s "$tmp_dir/esptool.log" ]]
echo 'ESP32 qualified reset and physical USB identity verification: OK'
