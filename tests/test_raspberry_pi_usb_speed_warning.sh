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
functions=(meshfirmware_enable_pi_usb_full_speed meshfirmware_pi_usb_has_uf2
	meshfirmware_classify_pi_usb_device meshfirmware_check_pi_usb_host_speed)
for script in "${scripts[@]}"; do
	bash -n "${repo_root}/${script}"
	for function_name in "${functions[@]}"; do
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
for function_name in "${functions[@]}"; do
	# shellcheck disable=SC2294
	eval "$(cat "${tmp_dir}/mcfirmware.sh.${function_name}")"
done

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
	"${sys_root}/bus/usb/devices" "${sys_root}/dev/block" "${proc_root}/self" \
	"${sys_root}/bus/platform/drivers/dwc_otg" \
	"${controller}/usb1" "${boot_root}/firmware"
ln -s "${controller}/usb1" "${sys_root}/bus/usb/devices/usb1"
ln -s "${sys_root}/bus/platform/drivers/dwc_otg" "${controller}/driver"
printf 'Raspberry Pi Zero 2 W Rev 1.0\0' > "${proc_root}/device-tree/model"
printf '%s\n' 1 > "${sys_root}/module/dwc_otg/parameters/speed"
printf '%s\n' 1d6b > "${controller}/usb1/idVendor"
printf '%s\n' 09 > "${controller}/usb1/bDeviceClass"

add_usb_device() {
	local name="$1" vendor="$2" product="$3" description="$4" class="$5"
	local path="${controller}/usb1/$name"
	mkdir -p "$path"
	ln -s "$path" "${sys_root}/bus/usb/devices/$name"
	printf '%s\n' "$vendor" > "$path/idVendor"
	printf '%s\n' "$product" > "$path/idProduct"
	printf '%s\n' "$description" > "$path/product"
	printf '%s\n' "$class" > "$path/bDeviceClass"
}

add_usb_interface() {
	local name="$1" number="$2" class="$3" subclass="$4"
	local path="${controller}/usb1/$name/$name:1.$number"
	mkdir -p "$path"
	printf '%s\n' "$class" > "$path/bInterfaceClass"
	printf '%s\n' "$subclass" > "$path/bInterfaceSubClass"
}

add_usb_device 1-1 1a40 0101 'Terminus hub' 09
add_usb_device 1-1.1 303a 1001 'Heltec Mesh Node' 00
add_usb_interface 1-1.1 0 02 02
add_usb_interface 1-1.1 2 02 02
add_usb_device 1-1.2 2886 0044 'XIAO nRF52840' 00
add_usb_interface 1-1.2 0 02 02
add_usb_interface 1-1.2 2 08 06
add_usb_device 1-1.3 10c4 ea60 'CP2102 USB to UART' 00
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
grep -Fq 'Recommendation: USB 1.1 / Full Speed' <<< "$output"
grep -Fq '3 device(s) on dwc_otg; 1 node(s), 1 DFU/UF2, 1 serial candidate(s), 0 network adapter(s), 0 storage, 0 other/unknown; 1 hub(s) excluded' <<< "$output"
grep -Fq 'Selected tier: 1/3' <<< "$output"
grep -Fq 'confirm they serve nodes' <<< "$output"
[[ "$(cat "${boot_root}/firmware/cmdline.txt")" == 'console=tty1 rootwait' ]]
echo 'PASS: risky Pi topology warns but cannot change a non-interactive host'

# These bootloaders may have no mounted drive or explicit DFU product string.
for usb_id in 2886:0057 239a:0029 239a:002a; do
	printf '%s\n' "${usb_id%:*}" > "${controller}/usb1/1-1.2/idVendor"
	printf '%s\n' "${usb_id#*:}" > "${controller}/usb1/1-1.2/idProduct"
	printf '%s\n' 'USB Device' > "${controller}/usb1/1-1.2/product"
	[[ "$(meshfirmware_classify_pi_usb_device "${controller}/usb1/1-1.2" "$sys_root" "$proc_root")" == dfu ]]
done
printf '%s\n' 2886 > "${controller}/usb1/1-1.2/idVendor"
printf '%s\n' 0044 > "${controller}/usb1/1-1.2/idProduct"
printf '%s\n' 'XIAO nRF52840' > "${controller}/usb1/1-1.2/product"
echo 'PASS: T1000-E and RAK/Feather bootloader IDs are recognized without mounted media'

# Devices on an independent controller do not influence the dwc_otg recommendation.
mkdir -p "${sys_root}/devices/platform/other.usb/usb2/2-1"
ln -s "${sys_root}/devices/platform/other.usb/usb2/2-1" "${sys_root}/bus/usb/devices/2-1"
printf '%s\n' abcd > "${sys_root}/bus/usb/devices/2-1/idVendor"
printf '%s\n' 08 > "${sys_root}/bus/usb/devices/2-1/bDeviceClass"
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq '3 device(s) on dwc_otg' <<< "$output"
grep -Fq 'Recommendation: USB 1.1 / Full Speed' <<< "$output"
echo 'PASS: dual CDC interfaces, root hubs and devices on other hosts are not double-counted'

# A real SD reader must not be treated as a node, even with a serial sibling.
add_usb_device 1-1.4 1234 5678 'SD Card Reader' 00
add_usb_interface 1-1.4 0 08 06
add_usb_interface 1-1.4 1 02 02
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq '4 device(s) on dwc_otg; 1 node(s), 1 DFU/UF2, 1 serial candidate(s), 0 network adapter(s), 1 storage' <<< "$output"
grep -Fq 'Selected tier: 3/3' <<< "$output"
grep -Fq 'Recommendation: USB 2.0 / High Speed' <<< "$output"
! grep -Fq 'Run this script interactively' <<< "$output"
! grep -Fq 'Recommendation: USB 1.1' <<< "$output"
echo 'PASS: SD-card storage overrides a node-only recommendation'

# Mounted UF2 evidence is matched through the block-device ancestry, not globally.
add_usb_device 1-1.5 abcd 1234 'Boot disk' 00
add_usb_interface 1-1.5 0 08 06
mkdir -p "${controller}/usb1/1-1.5/block/sdb/sdb1" "${tmp_dir}/UF2 volume"
ln -s "${controller}/usb1/1-1.5/block/sdb/sdb1" "${sys_root}/dev/block/8:17"
printf 'UF2 Bootloader 0.9.2\nBoard-ID: RAK4631\n' > "${tmp_dir}/UF2 volume/INFO_UF2.TXT"
printf '10 1 8:17 / %s/UF2\\040volume rw - vfat /dev/sdb1 rw\n' "$tmp_dir" > "${proc_root}/self/mountinfo"
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq '5 device(s) on dwc_otg; 1 node(s), 2 DFU/UF2, 1 serial candidate(s), 0 network adapter(s), 1 storage' <<< "$output"
grep -Fq 'SD Card Reader [USB storage / SD-card reader]' <<< "$output"
grep -Fq 'Boot disk [node/UF2 bootloader (DFU)]' <<< "$output"
grep -Fq 'Recommendation: USB 2.0 / High Speed' <<< "$output"
echo 'PASS: a mounted UF2 node with a space in its path does not disguise another SD reader'

# A filename alone is insufficient UF2 evidence.
printf '%s\n' 'ordinary document' > "${tmp_dir}/UF2 volume/INFO_UF2.TXT"
[[ "$(meshfirmware_classify_pi_usb_device "${controller}/usb1/1-1.5" "$sys_root" "$proc_root")" == storage ]]
printf 'UF2 Bootloader 0.9.2\nBoard-ID: RAK4631\n' > "${tmp_dir}/UF2 volume/INFO_UF2.TXT"
echo 'PASS: unrelated INFO_UF2.TXT files are not accepted as bootloader metadata'

# Descriptors can identify an unmounted bootloader, but branding alone is not enough.
printf '%s\n' 'RAK4631 UF2 Bootloader' > "${controller}/usb1/1-1.4/product"
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq '1 node(s), 3 DFU/UF2, 1 serial candidate(s), 0 network adapter(s), 0 storage' <<< "$output"
grep -Fq 'Recommendation: USB 1.1 / Full Speed' <<< "$output"
printf '%s\n' 'Heltec SD Reader' > "${controller}/usb1/1-1.4/product"
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq 'Heltec SD Reader [USB storage / SD-card reader]' <<< "$output"
grep -Fq 'Recommendation: USB 2.0 / High Speed' <<< "$output"
echo 'PASS: unmounted node bootloaders count as DFU; ordinary branded storage does not'

# Unknown peripherals favor high speed; networking alone moves to the middle tier.
add_usb_device 1-1.6 abcd 5678 'Unknown peripheral' 00
# Disconnect storage so an unknown device must change the recommendation itself.
rm -- "${sys_root}/bus/usb/devices/1-1.4"
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq '0 storage, 1 other/unknown' <<< "$output"
grep -Fq 'Recommendation: USB 2.0 / High Speed' <<< "$output"
grep -Fq 'Selected tier: 3/3' <<< "$output"
printf '%s\n' 'nRF52840 network adapter' > "${controller}/usb1/1-1.6/product"
add_usb_interface 1-1.6 0 02 06
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq 'network adapter [USB Ethernet / Wi-Fi adapter]' <<< "$output"
grep -Fq '1 network adapter(s), 0 storage, 0 other/unknown' <<< "$output"
grep -Fq 'Selected tier: 2/3' <<< "$output"
grep -Fq 'Recommendation: USB 1.1 for light networking; USB 2.0 for higher throughput' <<< "$output"
grep -Fq 'Run this script interactively' <<< "$output"
ln -s "${controller}/usb1/1-1.4" "${sys_root}/bus/usb/devices/1-1.4"
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq 'Selected tier: 3/3' <<< "$output"
grep -Fq 'Recommendation: USB 2.0 / High Speed' <<< "$output"
echo 'PASS: nodes plus Ethernet get the middle tier; storage or unknown devices favor high speed'

# A mixed topology never offers the cap/reboot, including an already-saved cap.
printf '%s\n' y > "${tmp_dir}/prompt-answer"
MESHFIRMWARE_TTY="${tmp_dir}/prompt-answer"
sudo() { echo 'unexpected sudo call' >&2; return 99; }
printf '%s\n' 'console=tty1 rootwait dwc_otg.speed=1' > "${boot_root}/firmware/cmdline.txt"
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq 'remove dwc_otg.speed=1' <<< "$output"
! grep -Fq 'unexpected sudo' <<< "$output"
[[ "$(cat "${boot_root}/firmware/cmdline.txt")" == 'console=tty1 rootwait dwc_otg.speed=1' ]]
printf '%s\n' 1 > "${sys_root}/module/dwc_otg/parameters/speed"
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq 'USB safeguard active' <<< "$output"
grep -Fq 'Recommendation: USB 2.0 / High Speed' <<< "$output"
echo 'PASS: mixed devices advise high speed even with an active or pending cap, without edits or reboot'

# Remove these fixture bus links to return to the original three node candidates.
rm -- "${sys_root}/bus/usb/devices/1-1.4" \
	"${sys_root}/bus/usb/devices/1-1.5" "${sys_root}/bus/usb/devices/1-1.6"
printf '%s\n' 0 > "${sys_root}/module/dwc_otg/parameters/speed"
printf '%s\n' 'console=tty1 rootwait' > "${boot_root}/firmware/cmdline.txt"

printf '%s\n' y > "${tmp_dir}/prompt-answer"
MESHFIRMWARE_TTY="${tmp_dir}/prompt-answer"
sudo() { echo 'sudo must not run in no-sudo mode' >&2; return 99; }
no_sudo_mode() { return 0; }
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq 'MCFIRMWARE_NO_SUDO=1' <<< "$output"
[[ "$(cat "${boot_root}/firmware/cmdline.txt")" == 'console=tty1 rootwait' ]]
echo 'PASS: mcfirmware no-sudo mode cannot edit boot configuration or reboot'

rm -- "${sys_root}/bus/usb/devices/1-1.1" \
	"${sys_root}/bus/usb/devices/1-1.2" "${sys_root}/bus/usb/devices/1-1.3"
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq '0 device(s) on dwc_otg' <<< "$output"
grep -Fq 'No node devices were identified' <<< "$output"
grep -Fq 'Recommendation: USB 2.0 / High Speed' <<< "$output"
echo 'PASS: an empty bus or hubs alone cannot trigger a node-only recommendation'

# Ethernet by itself is in the middle and still requires confirmation to apply.
unset -f no_sudo_mode
printf '%s\n' n > "${tmp_dir}/prompt-answer"
ln -s "${controller}/usb1/1-1.6" "${sys_root}/bus/usb/devices/1-1.6"
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq '1 device(s) on dwc_otg; 0 node(s), 0 DFU/UF2, 0 serial candidate(s), 1 network adapter(s)' <<< "$output"
grep -Fq 'Selected tier: 2/3' <<< "$output"
grep -Fq 'USB speed was not changed' <<< "$output"
[[ "$(cat "${boot_root}/firmware/cmdline.txt")" == 'console=tty1 rootwait' ]]
! grep -Fq 'sudo must not run' <<< "$output"
rm -- "${sys_root}/bus/usb/devices/1-1.6"
echo 'PASS: a lone Ethernet adapter gets the middle tier and declining leaves the cap unchanged'

# Wi-Fi often uses a vendor-specific interface, recognized by its Linux net device.
add_usb_device 1-1.7 0bda 1234 'USB Wireless LAN' 00
add_usb_interface 1-1.7 0 ff 00
mkdir -p "${controller}/usb1/1-1.7/1-1.7:1.0/net/wlan0"
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq 'Selected tier: 2/3' <<< "$output"
grep -Fq 'Wireless LAN [USB Ethernet / Wi-Fi adapter]' <<< "$output"
grep -Fq '1 network adapter(s), 0 storage, 0 other/unknown' <<< "$output"
printf '%s\n' 1 > "${sys_root}/module/dwc_otg/parameters/speed"
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq 'USB safeguard active' <<< "$output"
grep -Fq 'Selected tier: 2/3' <<< "$output"
! grep -Fq 'remove dwc_otg.speed=1' <<< "$output"
echo 'PASS: a lone Wi-Fi adapter is middle-tier even when the 1.1 cap is already active'

# A storage interface on that same adapter moves it to the high-speed end.
add_usb_interface 1-1.7 1 08 06
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
grep -Fq 'Selected tier: 3/3' <<< "$output"
grep -Fq '0 network adapter(s), 1 storage, 0 other/unknown' <<< "$output"
grep -Fq 'remove dwc_otg.speed=1' <<< "$output"
echo 'PASS: a composite Wi-Fi/storage device keeps the storage preference'

# Wireless-controller class e0 also includes Bluetooth, not just networking.
add_usb_device 1-1.8 1234 4321 'Bluetooth Radio' e0
add_usb_interface 1-1.8 0 e0 01
[[ "$(meshfirmware_classify_pi_usb_device "${controller}/usb1/1-1.8" "$sys_root" "$proc_root")" == other ]]
echo 'PASS: Bluetooth is not mistaken for Ethernet or Wi-Fi'

printf 'Generic ARM computer\0' > "${proc_root}/device-tree/model"
output="$(meshfirmware_check_pi_usb_host_speed 2>&1)"
[[ -z "$output" ]]
echo 'PASS: non-Raspberry Pi hosts are left alone'
