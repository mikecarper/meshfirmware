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
	record_locked_service stop_service_names stop_serial_locking_services \
	stop_active_serial_probe_services recover_busy_serial_port \
	restart_locked_services refresh_usb_recovered_esptool_args \
	esptool_output_port_busy probe_esptool; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate the function extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

stale_port="${tmp_dir}/ttyACM0"
expected_live_port="${tmp_dir}/ttyACM1"
touch "$expected_live_port"
DEVICE_PORT_NAME_FILE="${tmp_dir}/device-port-name"
printf '%s\n' 'usb-selected-radio-if00' > "$DEVICE_PORT_NAME_FILE"
USB_RESET_RECOVERED_PORT=""
LOCKEDSERVICE=""
systemctl_log="${tmp_dir}/systemctl.log"
esptool_log="${tmp_dir}/esptool.log"

selected_flash_serial_port() {
	printf '%s\n' "$expected_live_port"
}

get_locked_service() {
	return 0
}

terminate_serial_locking_processes() {
	return 1
}

no_sudo_mode() {
	return 1
}

systemctl() {
	if [[ "${1:-}" == "is-active" ]]; then
		[[ "${3:-}" == "ModemManager.service" ]]
		return
	fi
	printf '%s\n' "$*" >> "$systemctl_log"
}

sudo() {
	"$@"
}

sleep() {
	return 0
}

invoke_esptool() {
	printf '%s\n' "$*" >> "$esptool_log"
	if [[ " $* " == *" --port $stale_port "* ]]; then
		echo "A fatal error occurred: Could not open $stale_port, the port is busy or doesn't exist."
		return 1
	fi
	[[ " $* " == *" --port $expected_live_port "* ]]
}

print_esptool_recovery_hint() {
	return 0
}

probe_esptool --port "$stale_port" read-mac

grep -Fxq -- "--port $stale_port read-mac" "$esptool_log"
grep -Fxq -- "--port $expected_live_port read-mac" "$esptool_log"
grep -Fxq -- "stop ModemManager.service" "$systemctl_log"
[[ "$LOCKEDSERVICE" == "ModemManager.service" ]]

restart_locked_services
grep -Fxq -- "start ModemManager.service" "$systemctl_log"
[[ -z "$LOCKEDSERVICE" ]]

echo "PASS: busy-port recovery follows USB identity and restores the probing service"
