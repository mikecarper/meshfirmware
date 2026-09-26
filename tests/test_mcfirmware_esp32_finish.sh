#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

definition="$(sed -n '/^finish_esp32_flash_session() {/,/^}/p' "$repo_root/mcfirmware.sh")"
[[ "$definition" == 'finish_esp32_flash_session() {'* ]]
eval "$definition"

rom_port="$tmp_dir/rom-port"
fixture_runtime_port="$tmp_dir/runtime-port"
touch "$rom_port" "$fixture_runtime_port"
DEVICE_PORT="$rom_port"
HARDRESET=hard-reset
NORESET=no-reset
READMAC=read-mac
ESP32_SESSION_IS_S3=1
ESP32_FLASH_SELECTED_BY_ID=usb-esp32
ESP32_FLASH_EXPECTED_SERIAL=CC8DA2E96F34
ESP32_FLASH_EXPECTED_PATH_STEM=usb-esp32

selected_flash_serial_port() { printf '%s\n' "$rom_port"; }
esp32_port_is_rom_usb_jtag() { [[ "$1" == "$rom_port" ]]; }
nrf52_port_instance() { printf '%s\n' '1-1:1.0'; }
esp32_verified_destructive_port() { printf '%s\n' "$rom_port"; }
run_esp32_session_esptool() {
	printf '%s\n' "$*" >> "$tmp_dir/esptool.log"
	[[ "${reset_ok:-1}" == 1 ]]
}
wait_for_nrf52_bootloader_port() {
	printf '%s\n' "$*" >> "$tmp_dir/wait.log"
	[[ "${runtime_ok:-1}" == 1 ]] || return 1
	if [[ "${still_rom:-0}" == 1 ]]; then
		printf '%s\n' "$rom_port"
		return 0
	fi
	printf '%s\n' "$fixture_runtime_port"
}
save_selected_serial_port() {
	printf '%s\n' "$1" >> "$tmp_dir/saved.log"
}

finish_esp32_flash_session "$rom_port" > "$tmp_dir/output.log"
[[ "$(cat "$tmp_dir/esptool.log")" == "$rom_port --after hard-reset run" ]]
[[ "$(cat "$tmp_dir/saved.log")" == "$fixture_runtime_port" ]]

reset_ok=0
if finish_esp32_flash_session "$rom_port" >/dev/null 2>&1; then
	echo 'ESP32 finish passed after hard reset failed' >&2
	exit 1
fi

reset_ok=1
runtime_ok=0
if finish_esp32_flash_session "$rom_port" >/dev/null 2>&1; then
	echo 'ESP32 finish passed without runtime USB identity' >&2
	exit 1
fi
runtime_ok=1
still_rom=1
if finish_esp32_flash_session "$rom_port" >/dev/null 2>&1; then
	echo 'ESP32 finish passed when the ROM port never became an application port' >&2
	exit 1
fi
echo 'ESP32 hard reset and runtime identity verification: OK'
