#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcfirmware.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT
sudo_log="${tmp_dir}/sudo.log"
touch "$sudo_log"

extract_function() {
	local function_name=$1
	awk -v signature="${function_name}() {" '
		$0 == signature { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
}

for function_name in \
	no_sudo_mode ensure_sudo_session start_sudo_keepalive \
	initialize_privilege_mode configure_usb_autosuspend \
	install_packages ensure_command nrf52_serial_port_access \
	stop_serial_locking_services terminate_serial_locking_processes; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

expect_status() {
	local description=$1
	local expected=$2
	shift 2
	local status
	if "$@"; then
		status=0
	else
		status=$?
	fi
	if [[ "$status" -ne "$expected" ]]; then
		echo "FAIL: ${description}: expected status ${expected}, got ${status}" >&2
		exit 1
	fi
}

sudo() {
	printf '%s\n' "$*" >> "$sudo_log"
	if [[ "${1:-}" == "tee" ]]; then
		cat >/dev/null
	fi
	return 0
}

export MCFIRMWARE_NO_SUDO=1
export APT_UPDATED=0
export SUDO_KEEPALIVE_PID=""
export USB_AUTOSUSPEND=2
USB_AUTOSUSPEND_CHANGED=0

expect_status "no-sudo predicate is enabled" 0 no_sudo_mode
expect_status "sudo session request refuses" 1 ensure_sudo_session
expect_status "sudo keepalive request refuses" 1 start_sudo_keepalive
expect_status "package installation refuses" 1 install_packages missing-package
expect_status "missing dependency refuses" 1 ensure_command definitely-not-a-real-command-mcfirmware

restricted_port="${tmp_dir}/restricted-port"
touch "$restricted_port"
chmod 000 "$restricted_port"
expect_status "inaccessible serial port refuses" 1 nrf52_serial_port_access "$restricted_port"

get_locked_service() {
	printf '%s\n' "serial-getty@example.service"
}
expect_status "locking service refuses" 1 stop_serial_locking_services "$restricted_port"

serial_lock_pids() {
	printf '%s\n' 424242
}
service_from_pid() {
	return 0
}
expect_status "locking process refuses" 1 terminate_serial_locking_processes "$restricted_port"

initialize_privilege_mode >/dev/null
configure_usb_autosuspend
[[ ! -s "$sudo_log" ]] || {
	echo "FAIL: no-sudo mode invoked sudo" >&2
	exit 1
}
[[ "$USB_AUTOSUSPEND_CHANGED" -eq 0 ]] || {
	echo "FAIL: no-sudo mode marked USB autosuspend as changed" >&2
	exit 1
}

# The default path retains its original privileged behavior.
export MCFIRMWARE_NO_SUDO=0
: > "$sudo_log"
expect_status "normal sudo session succeeds" 0 ensure_sudo_session
grep -Fxq -- "-n true" "$sudo_log"

: > "$sudo_log"
export APT_UPDATED=0
expect_status "normal package installation uses sudo" 0 install_packages example-package
grep -Fxq -- "apt-get update" "$sudo_log"
grep -Fxq -- "apt-get -y install example-package" "$sudo_log"

: > "$sudo_log"
expect_status "normal serial permission fallback uses sudo" 0 nrf52_serial_port_access "$restricted_port"
grep -Fxq -- "chmod a+rw $restricted_port" "$sudo_log"

declare -a privilege_calls=()
ensure_sudo_session() { privilege_calls+=(ensure); }
start_sudo_keepalive() { privilege_calls+=(keepalive); }
ensure_serial_group_access() { privilege_calls+=(group); }
initialize_privilege_mode >/dev/null
[[ "${privilege_calls[*]}" == "ensure keepalive group" ]] || {
	echo "FAIL: normal startup privilege sequence changed: ${privilege_calls[*]}" >&2
	exit 1
}

: > "$sudo_log"
export USB_AUTOSUSPEND=2
USB_AUTOSUSPEND_CHANGED=0
configure_usb_autosuspend
grep -Fq -- "tee /sys/module/usbcore/parameters/autosuspend" "$sudo_log"
[[ "$USB_AUTOSUSPEND_CHANGED" -eq 1 ]] || {
	echo "FAIL: normal mode did not track the USB autosuspend change" >&2
	exit 1
}

echo "PASS: mcfirmware no-sudo mode is privilege-free and fails closed"
