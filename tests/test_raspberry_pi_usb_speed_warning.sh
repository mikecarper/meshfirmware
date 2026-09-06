#!/usr/bin/env bash
# Hardware-free checks for the Raspberry Pi DWC host warning and safe editor.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

extract_function() {
	local script_path="$1" function_name="$2"
	awk -v signature="${function_name}() {" '
		$0 == signature { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
}

scripts=(mcfirmware.sh mcsetup.sh mtfirmware.sh)
for script in "${scripts[@]}"; do
	bash -n "${repo_root}/${script}"
	for function_name in meshfirmware_enable_pi_usb_full_speed \
		meshfirmware_check_pi_usb_host_speed; do
		extract_function "${repo_root}/${script}" "$function_name" \
			> "${tmp_dir}/${script}.${function_name}"
		[[ -s "${tmp_dir}/${script}.${function_name}" ]]
		if [[ "$script" != mcfirmware.sh ]]; then
			cmp "${tmp_dir}/mcfirmware.sh.${function_name}" \
				"${tmp_dir}/${script}.${function_name}"
		fi
	done
done
echo 'PASS: all USB-facing shell entry points use the same syntax-valid Pi check'

# Evaluate the production functions without sourcing an interactive flasher.
# shellcheck disable=SC2294
eval "$(cat "${tmp_dir}/mcfirmware.sh.meshfirmware_enable_pi_usb_full_speed")"
# shellcheck disable=SC2294
eval "$(cat "${tmp_dir}/mcfirmware.sh.meshfirmware_check_pi_usb_host_speed")"

sudo() { "$@"; }

cmdline="${tmp_dir}/cmdline.txt"
printf '%s\n' 'console=tty1 rootwait dwc_otg.speed=0 quiet' > "$cmdline"
meshfirmware_enable_pi_usb_full_speed "$cmdline" >/dev/null
[[ "$(cat "$cmdline")" == 'console=tty1 rootwait quiet dwc_otg.speed=1' ]]
[[ "$(cat "${cmdline}.meshfirmware-backup")" == \
	'console=tty1 rootwait dwc_otg.speed=0 quiet' ]]
meshfirmware_enable_pi_usb_full_speed "$cmdline" >/dev/null
[[ "$(grep -o 'dwc_otg.speed=1' "$cmdline" | wc -l)" -eq 1 ]]
[[ "$(cat "${cmdline}.meshfirmware-backup")" == \
	'console=tty1 rootwait dwc_otg.speed=0 quiet' ]]
echo 'PASS: cmdline edit is idempotent and retains the original one-time backup'

sys_root="${tmp_dir}/sys"
proc_root="${tmp_dir}/proc"
boot_root="${tmp_dir}/boot"
controller="${sys_root}/devices/platform/mock.usb"
mkdir -p "${proc_root}/device-tree" \
	"${sys_root}/module/dwc_otg/parameters" \
	"${sys_root}/bus/usb/devices/1-1" \
	"${sys_root}/bus/platform/drivers/dwc_otg" \
	"${controller}/usb1" "${boot_root}/firmware"
ln -s "${controller}/usb1" "${sys_root}/bus/usb/devices/usb1"
ln -s "${sys_root}/bus/platform/drivers/dwc_otg" "${controller}/driver"
printf 'Raspberry Pi Zero 2 W Rev 1.0\0' > "${proc_root}/device-tree/model"
printf '%s\n' 1 > "${sys_root}/module/dwc_otg/parameters/speed"
printf '%s\n' 1a40 > "${sys_root}/bus/usb/devices/1-1/idVendor"
printf '%s\n' 0101 > "${sys_root}/bus/usb/devices/1-1/idProduct"
printf '%s\n' 'console=tty1 rootwait' > "${boot_root}/firmware/cmdline.txt"

export MESHFIRMWARE_SYS_ROOT="$sys_root"
export MESHFIRMWARE_PROC_ROOT="$proc_root"
export MESHFIRMWARE_BOOT_ROOT="$boot_root"
export MESHFIRMWARE_TTY="${tmp_dir}/no-tty"

output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq 'USB safeguard active' <<< "$output"
[[ "$(cat "${boot_root}/firmware/cmdline.txt")" == 'console=tty1 rootwait' ]]
echo 'PASS: an active 12 Mbps setting is reported without editing or prompting'

printf '%s\n' 0 > "${sys_root}/module/dwc_otg/parameters/speed"
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq 'legacy dwc_otg USB host at its default high speed' <<< "$output"
grep -Fq 'Terminus 1a40:0101 hub' <<< "$output"
grep -Fq 'Run this script interactively' <<< "$output"
[[ "$(cat "${boot_root}/firmware/cmdline.txt")" == 'console=tty1 rootwait' ]]
echo 'PASS: risky Pi topology warns but cannot change a non-interactive host'

printf '%s\n' y > "${tmp_dir}/prompt-answer"
MESHFIRMWARE_TTY="${tmp_dir}/prompt-answer"
sudo() { echo 'sudo must not run in no-sudo mode' >&2; return 99; }
no_sudo_mode() { return 0; }
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq 'MCFIRMWARE_NO_SUDO=1' <<< "$output"
[[ "$(cat "${boot_root}/firmware/cmdline.txt")" == 'console=tty1 rootwait' ]]
echo 'PASS: mcfirmware no-sudo mode cannot edit boot configuration or reboot'

printf 'Generic ARM computer\0' > "${proc_root}/device-tree/model"
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
[[ -z "$output" ]]
echo 'PASS: non-Raspberry Pi hosts are left alone'
