#!/usr/bin/env bash
#
: <<'EOF'

# To run this file, copy this line below and run it.
cd ~ && wget -qO - https://raw.githubusercontent.com/mikecarper/meshfirmware/refs/heads/main/mcsetup.sh | bash

#
EOF

# Strict errors.
# Trap errors and output file and line number.
set -euo pipefail

# shellcheck disable=SC2317
# Ensure we always restore on exit
cleanup() {
	if declare -F restart_stopped_time_sync_services >/dev/null; then
		restart_stopped_time_sync_services
	fi
	USB_AUTOSUSPEND_END=$(cat /sys/module/usbcore/parameters/autosuspend)
	if [[ "$USB_AUTOSUSPEND_END" != "$USB_AUTOSUSPEND" ]]; then
		echo "$USB_AUTOSUSPEND" | sudo tee /sys/module/usbcore/parameters/autosuspend >/dev/null
	fi
	if [[ -d "$FIRMWARE_ROOT" ]]; then
		chmod -R a+rX "$FIRMWARE_ROOT" >/dev/null 2>&1 || true
		sudo chown -R "$BASE_USER:$BASE_GROUP" "$FIRMWARE_ROOT" >/dev/null 2>&1 || true
	fi
	if [[ -n "${SUDO_KEEPALIVE_PID:-}" ]]; then
		kill "$SUDO_KEEPALIVE_PID" >/dev/null 2>&1 || true
	fi
}

# shellcheck disable=SC2317
error_handler() {
  local lineno=$1
  echo "FAILED at ${BASH_SOURCE[0]}:${lineno}" >&2
  cleanup
  exit 1
}

trap 'error_handler $LINENO' ERR    # on any error
trap cleanup EXIT                   # on any exit (error or normal)

# If BASH_SOURCE[0] is not set, fall back to the current working directory.
if [ -z "${BASH_SOURCE+x}" ] || [ -z "${BASH_SOURCE[0]+x}" ]; then
	# The script is likely being run via a pipe, so there's no script file path
	PWD_SCRIPT="$(pwd)"
else
	PWD_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
USB_AUTOSUSPEND=$(cat /sys/module/usbcore/parameters/autosuspend)

REPO_OWNER="meshcore-dev"
REPO_NAME="MeshCore"
CONFIG_URL="https://api.meshcore.nz/api/v1/config"

         FIRMWARE_ROOT="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}"
     RADIO_CONFIG_FILE="${FIRMWARE_ROOT}/meshcore_config.json}"
 

BOOT_WAIT="${BOOT_WAIT:-2}" 
BAUD="${3:-115200}"
DEFAULT_BAUDS=(57600 115200 38400 9600 19200 2400)
SERIAL_BAUD_CACHE=""
SERIAL_IDLE_TIMEOUT=2.5 
SERIAL_TOTAL_TIMEOUT=7.5
SERIAL_SETTINGS_PROFILE="conservative"
USB_LOGGING_SETTING=""

# Resolve base user/group
BASE_USER="${SUDO_USER:-$USER}"
BASE_GROUP="$(id -gn "$BASE_USER")"
SUDO_KEEPALIVE_PID=""
TIME_SYNC_STOPPED_SERVICES=()

ensure_sudo_session() {
  if sudo -n true 2>/dev/null; then
    return 0
  fi

  echo "sudo access is required for package, USB, and system configuration steps."
  sudo -v
}

start_sudo_keepalive() {
  if [[ -n "${SUDO_KEEPALIVE_PID:-}" ]] && kill -0 "$SUDO_KEEPALIVE_PID" >/dev/null 2>&1; then
    return 0
  fi

  (
    while true; do
      sleep 50
      sudo -n true >/dev/null 2>&1 || exit 0
    done
  ) &
  SUDO_KEEPALIVE_PID=$!
}

ensure_serial_group_access() {
  local serial_group=""

  if getent group dialout >/dev/null 2>&1; then
    serial_group="dialout"
  elif getent group uucp >/dev/null 2>&1; then
    serial_group="uucp"
  fi

  if [[ -z "$serial_group" ]]; then
    return 0
  fi

  if id -nG "$BASE_USER" | tr ' ' '\n' | grep -qx "$serial_group"; then
    return 0
  fi

  echo "Adding ${BASE_USER} to ${serial_group} for persistent serial-port access..."
  sudo usermod -aG "$serial_group" "$BASE_USER"
  echo "Group membership updated. Log out and back in for ${serial_group} access to apply."
}

meshfirmware_enable_pi_usb_full_speed() {
	local cmdline="$1" current line_count tmp token
	local -a tokens=() updated=()

	line_count="$(awk 'NF { count++ } END { print count + 0 }' "$cmdline")"
	if [[ "$line_count" -ne 1 ]]; then
		echo "Refusing to edit ${cmdline}: expected exactly one non-empty line." >&2
		return 1
	fi

	current="$(awk 'NF { print; exit }' "$cmdline")"
	read -r -a tokens <<< "$current"
	for token in "${tokens[@]}"; do
		[[ "$token" == dwc_otg.speed=* ]] || updated+=("$token")
	done
	updated+=("dwc_otg.speed=1")

	tmp="$(mktemp)"
	printf '%s\n' "${updated[*]}" > "$tmp"
	if [[ ! -e "${cmdline}.meshfirmware-backup" ]]; then
		if ! sudo cp -a -- "$cmdline" "${cmdline}.meshfirmware-backup"; then
			rm -f -- "$tmp"
			return 1
		fi
	fi
	if ! sudo cp -- "$tmp" "$cmdline"; then
		rm -f -- "$tmp"
		return 1
	fi
	rm -f -- "$tmp"

	current="$(cat "$cmdline")"
	if [[ " $current " != *' dwc_otg.speed=1 '* ]]; then
		echo "Could not verify dwc_otg.speed=1 in ${cmdline}." >&2
		return 1
	fi
	sync
	echo "Saved ${cmdline}; original retained as ${cmdline}.meshfirmware-backup."
}

# Read mounted UF2 metadata only when its block device belongs to this USB device.
# Never mount storage or enter DFU just to make a speed recommendation.
meshfirmware_pi_usb_has_uf2() {
	local usb_device="$1" sys_root="$2" proc_root="$3"
	local mount_id parent_id dev_number mount_root mount_point mount_rest block_path info_file
	[[ -r "${proc_root}/self/mountinfo" ]] || return 1
	while read -r mount_id parent_id dev_number mount_root mount_point mount_rest; do
		block_path="$(readlink -f "${sys_root}/dev/block/${dev_number}" 2>/dev/null || true)"
		[[ "$block_path" == "$usb_device/"* ]] || continue
		# mountinfo escapes spaces, tabs, newlines and backslashes using octal.
		printf -v mount_point '%b' "$mount_point"
		info_file="${mount_point%/}/INFO_UF2.TXT"
		[[ -r "$info_file" ]] || continue
		if grep -Eiq '^UF2[[:space:]]+Bootloader' "$info_file" \
			&& grep -Eiq '^Board-ID:' "$info_file"; then
			return 0
		fi
	done < "${proc_root}/self/mountinfo"
	return 1
}

meshfirmware_classify_pi_usb_device() {
	local device="$1" sys_root="$2" proc_root="$3"
	local vendor product description device_class interface interface_class subclass driver
	local storage=0 network=0 serial=0 node=0 bootloader=0
	vendor="$(cat "${device}/idVendor" 2>/dev/null || true)"
	product="$(cat "${device}/idProduct" 2>/dev/null || true)"
	description="$(cat "${device}/manufacturer" "${device}/product" 2>/dev/null || true)"
	description="${description,,}"
	device_class="$(cat "${device}/bDeviceClass" 2>/dev/null || true)"
	if [[ "$device_class" == 09 ]]; then echo hub; return 0; fi
	[[ "$device_class" != 08 ]] || storage=1
	for interface in "${device}"/*:*; do
		[[ -d "$interface" ]] || continue
		interface_class="$(cat "${interface}/bInterfaceClass" 2>/dev/null || true)"
		subclass="$(cat "${interface}/bInterfaceSubClass" 2>/dev/null || true)"
		driver="$(readlink -f "${interface}/driver" 2>/dev/null || true)"
		[[ "$interface_class" != 08 ]] || storage=1
		if [[ "$interface_class" == 09 ]]; then echo hub; return 0; fi
		if [[ -d "${interface}/net" \
			|| ( "$interface_class" == 02 && "$subclass" =~ ^(06|0d|0e)$ ) ]]; then
			network=1
		fi
		if [[ "$interface_class" == 02 && "$subclass" == 02 ]]; then serial=1; fi
		case "${driver##*/}" in
			cdc_acm|cp210x|ch341|ftdi_sio|usbserial) serial=1 ;;
			cdc_ether|cdc_ncm|cdc_mbim|rndis_host|asix|ax88179_178a|r8152|smsc95xx|smsc75xx|lan78xx)
				network=1 ;;
		esac
	done
	# Generic UART bridges are candidates, not proof that mesh firmware is running.
	case "${vendor,,}:${product,,}" in
		10c4:ea60|1a86:7523|1a86:5523|1a86:55d4|1a86:55d3|0403:6001|0403:6015|303a:1001)
			serial=1 ;;
	esac
	case "$description" in
		*meshtastic*|*meshcore*|*heltec*|*lilygo*|*rakwireless*|*wisblock*|*rak46*|*t1000*|*t-echo*|*t-beam*|*t-deck*|*xiao*|*nrf52*|*feather*)
			node=1 ;;
	esac
	case "$description" in *uf2*|*bootloader*|*dfu*) bootloader=1 ;; esac
	# A networking or mass-storage interface takes priority over a serial sibling.
	if (( network )); then
		if (( storage )); then echo storage; else echo network; fi
		return 0
	fi
	# RAK/Feather UF2 and CDC-only bootloader IDs do not contain DFU in the name:
	# https://github.com/oltaco/Adafruit_nRF52_Bootloader_OTAFIX/blob/master/src/boards/wiscore_rak4631_board/board.h
	# XIAO, T1000-E and MeshTower IDs also occur elsewhere in this repository.
	case "${vendor,,}:${product,,}" in
		2886:0044|2886:0045|2886:0057|239a:0029|239a:002a|239a:0071) echo dfu; return 0 ;;
	esac
	if (( storage )); then
		if (( node && bootloader )) \
			|| meshfirmware_pi_usb_has_uf2 "$device" "$sys_root" "$proc_root"; then
			echo dfu
		else
			echo storage
		fi
	elif (( node && bootloader )); then
		echo dfu
	elif (( node )); then
		echo node
	elif (( serial )); then
		echo serial
	else
		echo other
	fi
}

meshfirmware_check_pi_usb_host_speed() {
	local sys_root="${MESHFIRMWARE_SYS_ROOT:-/sys}"
	local proc_root="${MESHFIRMWARE_PROC_ROOT:-/proc}"
	local boot_root="${MESHFIRMWARE_BOOT_ROOT:-/boot}"
	local tty_path="${MESHFIRMWARE_TTY:-/dev/tty}"
	local model="" model_file speed speed_file usb_root resolved_root
	local controller driver_path cmdline="" answer vendor_file product_file
	local dwc_host=0 terminus_hub=0 configured=0
	local device affected category label vendor product root
	local total=0 nodes=0 dfu=0 serial=0 network=0 storage=0 other=0 hubs=0 suggest_full_speed=0
	local speed_tier=3 speed_prompt="Apply the 12 Mbps Raspberry Pi USB mitigation now? [y/N] "
	local -a dwc_roots=() device_lines=()

	[[ "${MESHFIRMWARE_PI_USB_CHECK:-1}" != 0 ]] || return 0
	[[ "$(uname -s)" == Linux ]] || return 0
	for model_file in \
		"${proc_root}/device-tree/model" \
		"${sys_root}/firmware/devicetree/base/model"; do
		if [[ -r "$model_file" ]]; then
			model="$(tr -d '\000' < "$model_file")"
			break
		fi
	done
	[[ "$model" == *'Raspberry Pi'* ]] || return 0

	speed_file="${sys_root}/module/dwc_otg/parameters/speed"
	[[ -r "$speed_file" ]] || return 0
	for usb_root in "${sys_root}"/bus/usb/devices/usb*; do
		[[ -e "$usb_root" ]] || continue
		resolved_root="$(readlink -f "$usb_root" 2>/dev/null || true)"
		[[ -n "$resolved_root" ]] || continue
		controller="$(dirname "$resolved_root")"
		driver_path="$(readlink -f "${controller}/driver" 2>/dev/null || true)"
		if [[ "${driver_path##*/}" == dwc_otg ]]; then
			dwc_host=1
			dwc_roots+=("$resolved_root")
		fi
	done
	(( dwc_host )) || return 0

	# Count physical devices once, even when they expose several CDC/MSC interfaces.
	# Only devices below dwc_otg roots are affected by this setting.
	for vendor_file in "${sys_root}"/bus/usb/devices/*/idVendor; do
		[[ -r "$vendor_file" ]] || continue
		device="$(readlink -f "${vendor_file%/idVendor}" 2>/dev/null || true)"
		[[ -n "$device" ]] || continue
		affected=0
		for root in "${dwc_roots[@]}"; do
			[[ "$device" != "$root/"* ]] || affected=1
		done
		(( affected )) || continue
		vendor="$(cat "$vendor_file" 2>/dev/null || true)"
		product_file="${device}/idProduct"
		product="$(cat "$product_file" 2>/dev/null || true)"
		category="$(meshfirmware_classify_pi_usb_device "$device" "$sys_root" "$proc_root")"
		if [[ "$category" == hub ]]; then
			hubs=$((hubs + 1))
			[[ "${vendor,,}:${product,,}" != 1a40:0101 ]] || terminus_hub=1
			continue
		fi
		total=$((total + 1))
		case "$category" in
			node) nodes=$((nodes + 1)); label="node" ;;
			dfu) dfu=$((dfu + 1)); label="node/UF2 bootloader (DFU)" ;;
			serial) serial=$((serial + 1)); label="serial adapter (possible node)" ;;
			network) network=$((network + 1)); label="USB Ethernet / Wi-Fi adapter" ;;
			storage) storage=$((storage + 1)); label="USB storage / SD-card reader" ;;
			*) other=$((other + 1)); label="other/unknown device" ;;
		esac
		product="$(cat "${device}/product" 2>/dev/null || true)"
		product="${product//[$'\r\n\t']/ }"
		device_lines+=("  ${device##*/}: ${product:-unnamed USB device} [$label]")
	done
	if (( total > 0 && storage == 0 && other == 0 )); then
		suggest_full_speed=1
		speed_tier=1
		if (( network > 0 )); then
			speed_tier=2
			speed_prompt="Use USB 1.1 for light networking (12 Mbps shared bus cap)? [y/N] "
		fi
	fi

	speed="$(cat "$speed_file" 2>/dev/null || true)"
	if [[ "$speed" == 1 && "$suggest_full_speed" == 1 \
		&& "${MESHFIRMWARE_PI_USB_VERBOSE:-0}" != 1 ]]; then
		echo "Raspberry Pi USB safeguard active: dwc_otg.speed=1 (12 Mbps USB Full Speed); no change needed." >&2
		return 0
	fi
	echo >&2
	if [[ "$speed" == 1 ]]; then
		echo "Raspberry Pi USB safeguard active: dwc_otg.speed=1 (12 Mbps USB Full Speed)." >&2
	else
		echo "WARNING: ${model} is using the legacy dwc_otg USB host at its default high speed." >&2
		echo "Some Raspberry Pi hub/radio combinations can repeatedly reset the whole USB bus" >&2
		echo "or lock the host (often error -71/-110 or FIQ FSM timeout messages)." >&2
	fi
	if (( terminus_hub )); then
		echo "A Terminus 1a40:0101 hub, a topology seen with this failure, is connected." >&2
	fi
	echo "USB inventory: $total device(s) on dwc_otg; $nodes node(s), $dfu DFU/UF2, $serial serial candidate(s), $network network adapter(s), $storage storage, $other other/unknown; $hubs hub(s) excluded." >&2
	if (( total > 0 )); then printf '%s\n' "${device_lines[@]}" >&2; fi
	echo "USB speed scale: 1 = favor 1.1 | 2 = light networking / either speed | 3 = favor 2.0" >&2
	echo "Selected tier: $speed_tier/3" >&2
	if (( suggest_full_speed )); then
		if (( speed_tier == 2 )); then
			echo "Recommendation: USB 1.1 for light networking; USB 2.0 for higher throughput (middle tier)." >&2
			echo "Only network adapters and optional nodes were found. Traffic demand is not measured." >&2
			echo "The entire USB bus shares the 12 Mbps cap, including Ethernet/Wi-Fi traffic." >&2
		else
			echo "Recommendation: USB 1.1 / Full Speed (12 Mbps) for this node-only USB bus." >&2
			echo "dwc_otg.speed=1 caps the entire bus; radio serial links are usually already 12 Mbps." >&2
		fi
		if (( serial > 0 )); then
			echo "Serial adapters are possible nodes; confirm they serve nodes before changing speed." >&2
		fi
	else
		echo "Recommendation: USB 2.0 / High Speed (up to 480 Mbps)." >&2
		if (( storage > 0 || other > 0 )); then
			echo "Storage or unidentified devices share this bus; a 12 Mbps cap may slow them." >&2
		else
			echo "No node devices were identified; reconnect the nodes before considering a 12 Mbps cap." >&2
		fi
	fi

	for cmdline in "${boot_root}/firmware/cmdline.txt" "${boot_root}/cmdline.txt"; do
		[[ -f "$cmdline" ]] && break
		cmdline=""
	done
	if [[ -n "$cmdline" ]] \
		&& grep -Eq '(^|[[:space:]])dwc_otg\.speed=1([[:space:]]|$)' "$cmdline"; then
		configured=1
	fi
	if (( ! suggest_full_speed )); then
		if [[ "$speed" == 1 ]] || (( configured )); then
			echo "To allow USB 2.0 speeds, remove dwc_otg.speed=1 from ${cmdline:-the boot cmdline.txt} and reboot when convenient." >&2
		fi
		echo "No USB speed change or reboot is being offered for this device mix." >&2
		return 0
	fi
	[[ "$speed" != 1 ]] || return 0
	if [[ -z "$cmdline" ]]; then
		echo "No Raspberry Pi cmdline.txt was found, so no automatic change is available." >&2
		return 0
	fi
	if (( configured )); then
		echo "dwc_otg.speed=1 is saved in ${cmdline} but is not active yet." >&2
	fi
	if declare -F no_sudo_mode >/dev/null 2>&1 && no_sudo_mode; then
		echo "MCFIRMWARE_NO_SUDO=1: no boot configuration or reboot action was taken." >&2
		return 0
	fi

	if [[ ! -r "$tty_path" ]]; then
		echo "Run this script interactively to apply the mitigation and reboot." >&2
		return 0
	fi
	if (( ! configured )); then
		if ! read -r -p "$speed_prompt" answer < "$tty_path"; then
			return 0
		fi
		case "$answer" in
			[Yy]|[Yy][Ee][Ss]) ;;
			*) echo "USB speed was not changed."; return 0 ;;
		esac
		if ! sudo -n true 2>/dev/null; then
			echo "sudo access is required to update ${cmdline}."
			sudo -v
		fi
		meshfirmware_enable_pi_usb_full_speed "$cmdline"
	fi

	echo "A reboot is required before the USB speed change takes effect."
	if ! read -r -p "Reboot now? [y/N] " answer < "$tty_path"; then
		return 0
	fi
	case "$answer" in
		[Yy]|[Yy][Ee][Ss])
			echo "Rebooting to activate dwc_otg.speed=1..."
			if ! sudo systemctl reboot; then
				sudo reboot
			fi
			exit 0
			;;
		*) echo "Reboot later to activate dwc_otg.speed=1." ;;
	esac
}

ensure_sudo_session
start_sudo_keepalive
ensure_serial_group_access
meshfirmware_check_pi_usb_host_speed

if [[ -n "${SUDO_USER:-}" ]]; then
  umask 022
fi

PACKAGE_MANAGER=""
PACKAGE_METADATA_UPDATED=0

detect_package_manager() {
  if [[ -n "$PACKAGE_MANAGER" ]]; then
    return 0
  fi

  for PACKAGE_MANAGER in pacman dnf apt-get; do
    if command -v "$PACKAGE_MANAGER" >/dev/null 2>&1; then
      echo "Using ${PACKAGE_MANAGER} for system packages." >&2
      return 0
    fi
  done

  PACKAGE_MANAGER=""
  echo "No supported package manager found (pacman, dnf, or apt-get)." >&2
  return 1
}

package_name_for_manager() {
  local package_name="$1"

  case "${PACKAGE_MANAGER}:${package_name}" in
    pacman:python3) package_name="python" ;;
    pacman:pip) package_name="python-pip" ;;
    pacman:pipx) package_name="python-pipx" ;;
    pacman:vim-common) package_name="tinyxxd" ;;
    dnf:pip|apt-get:pip) package_name="python3-pip" ;;
  esac

  printf '%s\n' "$package_name"
}

apt_update_or_use_cached_metadata() {
  local answer=""
  local tty_path="${MESHFIRMWARE_TTY:-/dev/tty}"

  if sudo apt-get update; then
    PACKAGE_METADATA_UPDATED=1
    return 0
  fi

  echo >&2
  echo "apt-get update failed. Existing cached package indexes may still be usable." >&2
  echo "Continuing can install older packages, but package authentication will remain enabled." >&2
  if ! read -r -p "Continue using cached apt package indexes? [y/N] " answer < "$tty_path"; then
    echo "Unable to read a response; package installation cancelled." >&2
    return 1
  fi
  case "$answer" in
    y|Y|yes|YES|Yes)
      PACKAGE_METADATA_UPDATED=1
      echo "Continuing with cached apt package indexes." >&2
      return 0
      ;;
    *)
      echo "Package installation cancelled." >&2
      return 1
      ;;
  esac
}

install_packages() {
  detect_package_manager || return 1

  local package_name
  local -a packages=()
  for package_name in "$@"; do
    packages+=("$(package_name_for_manager "$package_name")")
  done

  case "$PACKAGE_MANAGER" in
    pacman)
      sudo pacman -S --needed --noconfirm "${packages[@]}"
      ;;
    dnf)
      sudo dnf install -y "${packages[@]}"
      ;;
    apt-get)
      if (( ! PACKAGE_METADATA_UPDATED )); then
        apt_update_or_use_cached_metadata || return 1
      fi
      sudo apt-get install -y "${packages[@]}"
      ;;
  esac
}

ensure_command() {
  local command_name=$1
  shift || true

  if command -v "$command_name" >/dev/null 2>&1; then
    return 0
  fi

  echo "Installing ${command_name}..."
  if [ "$#" -gt 0 ]; then
    install_packages "$@"
  else
    install_packages "$command_name"
  fi
}

ensure_time_sync_client() {
  if command -v chronyc >/dev/null 2>&1; then
    return 0
  fi

  if command -v ntpd >/dev/null 2>&1; then
    return 0
  fi

  if command -v ntpdate >/dev/null 2>&1; then
    return 0
  fi

  if command -v ntpdig >/dev/null 2>&1; then
    return 0
  fi

  if command -v sntp >/dev/null 2>&1; then
    return 0
  fi

  if command -v timedatectl >/dev/null 2>&1; then
    return 0
  fi

  ensure_command chronyc chrony
  sudo systemctl enable chrony
  sudo systemctl restart chrony
}

system_clock_is_synchronized() {
  local synchronized=""

  if command -v timedatectl >/dev/null 2>&1; then
    synchronized="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
    [[ "${synchronized,,}" == "yes" ]] && return 0
  fi

  if command -v ntpq >/dev/null 2>&1 \
    && ntpq -pn 2>/dev/null | awk '$1 ~ /^\*/ { found=1 } END { exit !found }'; then
    return 0
  fi

  return 1
}

restart_stopped_time_sync_services() {
  local service

  ((${#TIME_SYNC_STOPPED_SERVICES[@]} > 0)) || return 0
  for service in "${TIME_SYNC_STOPPED_SERVICES[@]}"; do
    echo "Restarting time synchronization service ${service}..." >&2
    sudo systemctl start "$service" >/dev/null 2>&1 || true
  done
  TIME_SYNC_STOPPED_SERVICES=()
}

stop_active_time_sync_services() {
  local service
  local -a candidates=(
    ntp.service ntpd.service ntpsec.service systemd-timesyncd.service
  )

  TIME_SYNC_STOPPED_SERVICES=()
  command -v systemctl >/dev/null 2>&1 || return 0
  for service in "${candidates[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
      echo "Temporarily stopping time synchronization service ${service}..." >&2
      if sudo systemctl stop "$service"; then
        TIME_SYNC_STOPPED_SERVICES+=("$service")
      else
        restart_stopped_time_sync_services
        return 1
      fi
    fi
  done
}

force_time_sync() {
  local ntpd_status=0

  if system_clock_is_synchronized; then
    echo "System clock is already synchronized."
    return 0
  fi

  if command -v chronyc >/dev/null 2>&1; then
    sudo systemctl enable chrony >/dev/null 2>&1 || true
    sudo systemctl restart chrony >/dev/null 2>&1 || true
    sudo chronyc -a makestep >/dev/null 2>&1 || sudo chronyc makestep >/dev/null 2>&1
    chronyc tracking | grep -E '^(Ref(erence)? time|System time)'
    return 0
  fi

  if command -v ntpd >/dev/null 2>&1; then
    stop_active_time_sync_services || return 1
    if sudo ntpd -gq; then
      ntpd_status=0
    else
      ntpd_status=$?
    fi
    restart_stopped_time_sync_services
    if (( ntpd_status == 0 )); then
      return 0
    fi
    if system_clock_is_synchronized; then
      echo "The restored time service reports a synchronized system clock."
      return 0
    fi
    echo "Unable to synchronize the system clock with ntpd." >&2
    return "$ntpd_status"
  fi

  if command -v ntpdate >/dev/null 2>&1; then
    sudo ntpdate -u pool.ntp.org
    return 0
  fi

  if command -v ntpdig >/dev/null 2>&1; then
    sudo ntpdig -S pool.ntp.org >/dev/null
    return 0
  fi

  if command -v sntp >/dev/null 2>&1; then
    sudo sntp -sS pool.ntp.org
    return 0
  fi

  sudo timedatectl set-ntp true
  sudo systemctl restart systemd-timesyncd >/dev/null 2>&1 || true
  timedatectl timesync-status 2>/dev/null || timedatectl status
}

DEVICE_NAME=""
DETECTED_NODE_BOARD=""
DETECTED_NODE_VERSION=""
SETUP_USB_IDENTITY=""
SETUP_USB_RESET_HELPER=""
SETUP_USB_SELECTED_LINK=""
MESHCORE_USB_RESET_TOOL_SHA256="364de4c2e100df3ec2be795fc6079722ce1790416ba5a2d04d0c53e6c87c7083"

ensure_command jq
ensure_command curl
ensure_command socat
ensure_command bc
ensure_time_sync_client

ensure_meshcore_config() {
  # Ensure jq and curl exist
  ensure_command jq
  ensure_command curl

  local need_fetch=0
  if [ ! -f "$RADIO_CONFIG_FILE" ]; then
    need_fetch=1
  else
    local now mtime age
    now=$(date +%s)
    mtime=$(date -r "$RADIO_CONFIG_FILE" +%s)
    age=$(( now - mtime ))
    # 6 hours = 21600 seconds
    if [ "$age" -gt 21600 ]; then
      need_fetch=1
    fi
  fi

  if [ "$need_fetch" -eq 1 ]; then
    echo "Downloading config from $CONFIG_URL"
    curl -fsSL "$CONFIG_URL" -o "$RADIO_CONFIG_FILE"
  else
    #echo "Using cached config: $RADIO_CONFIG_FILE"
	echo 
  fi
}

get_system_timezone() {
  # Try timedatectl first
  if command -v timedatectl >/dev/null 2>&1; then
    timedatectl show -p Timezone --value 2>/dev/null && return 0
  fi

  # Then /etc/timezone (Debian/Ubuntu)
  if [ -f /etc/timezone ]; then
    cat /etc/timezone && return 0
  fi

  # Fallback to $TZ or empty
  if [ -n "${TZ:-}" ]; then
    echo "$TZ"
    return 0
  fi

  return 1
}

# Return a best-guess suggested title from timezone
# Examples of your titles:
#   "Australia"
#   "Australia: Victoria"
#   "EU/UK (Narrow)"
#   "New Zealand"
#   "USA/Canada (Recommended)"
#   "Czech Republic (Narrow)"
#   "Portugal 433" / "Portugal 868"
#   "Switzerland"
#   "Vietnam"
guess_radio_title_from_timezone() {
  local tz="$1"

  case "$tz" in
    Australia/*)
      # Could be smarter (NSW vs VIC), but generic AU for now
      echo "Australia"
      ;;
    Pacific/Auckland|Pacific/Chatham)
      echo "New Zealand"
      ;;
    Europe/Prague)
      echo "Czech Republic (Narrow)"
      ;;
    Europe/Lisbon)
      echo "Portugal 868"
      ;;
    Europe/Zurich)
      echo "Switzerland"
      ;;
    Europe/*)
      # Generic EU zone
      echo "EU/UK (Narrow)"
      ;;
    America/*|Canada/*|US/*)
      # Any Americas timezone -> USA/Canada profile
      echo "USA/Canada (Recommended)"
      ;;
    Asia/Ho_Chi_Minh)
      echo "Vietnam"
      ;;
    *)
      # Unknown / no guess
      echo ""
      ;;
  esac
}

snapshot_radio_baseline() {
  RADIO_FREQ_OLD="$RADIO_FREQ"
  RADIO_BW_OLD="$RADIO_BW"
  RADIO_SF_OLD="$RADIO_SF"
  RADIO_CR_OLD="$RADIO_CR"
}

# Custom radio setting helper
# Sets: RADIO_TITLE, RADIO_DESC, RADIO_FREQ, RADIO_SF, RADIO_BW, RADIO_CR
select_custom_radio_setting() {
  local freq sf bw cr

  echo
  echo "Custom radio settings"

  # Center frequency in MHz
  while :; do
    read -rp "Center frequency (MHz, e.g. 915.000): " freq
    # allow integer or float
    if [[ "$freq" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
      break
    fi
    echo "Please enter a numeric MHz value (e.g. 915.000)."
  done

  # Spreading factor
  echo "Spreading factor options: 5, 6, 7, 8, 9, 10, 11, 12"
  while :; do
    read -rp "SF (5-12): " sf
    if [[ "$sf" =~ ^[0-9]+$ ]] && [ "$sf" -ge 5 ] && [ "$sf" -le 12 ]; then
      break
    fi
    echo "Please enter 5, 6, 7, 8, 9, 10, 11, or 12."
  done

	# Bandwidth (kHz)
	BW_ALLOWED=(7.81 10.42 15.63 20.83 31.25 41.67 62.5 125 250 500)

	is_in_list() {
	  local x="$1"; shift
	  for v in "$@"; do
		# numeric compare via bc to handle floats precisely
		if echo "$x == $v" | bc -l >/dev/null 2>&1 && [ "$(echo "$x == $v" | bc -l)" = "1" ]; then
		  return 0
		fi
	  done
	  return 1
	}

	echo "Bandwidth options (kHz): ${BW_ALLOWED[*]}"
	while :; do
	  read -rp "BW (${BW_ALLOWED[*]}): " bw
	  # must be numeric
	  if [[ "$bw" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
		if is_in_list "$bw" "${BW_ALLOWED[@]}"; then
		  break
		fi
	  fi
	  echo "Please enter one of: ${BW_ALLOWED[*]}."
	done

  # Coding rate
  echo "Coding rate options: CR5, CR6, CR7, CR8"
  while :; do
    read -rp "CR (5-8): " cr
    if [[ "$cr" =~ ^[0-9]+$ ]] && [ "$cr" -ge 5 ] && [ "$cr" -le 8 ]; then
      break
    fi
    echo "Please enter 5, 6, 7, or 8."
  done

  RADIO_FREQ="$freq"
  RADIO_SF="$sf"
  RADIO_BW="$bw"
  RADIO_CR="$cr"

  return 0
}

select_suggested_radio_setting() {
  ensure_meshcore_config

  # Colors
  local GRAY="\033[90m"
  local RED="\033[0;31m"
  local RESET="\033[0m"

  # Read titles, descriptions, and bandwidths
  mapfile -t _RADIO_TITLES < <(jq -r '.config.suggested_radio_settings.entries[].title' "$RADIO_CONFIG_FILE")
  mapfile -t _RADIO_DESCS  < <(jq -r '.config.suggested_radio_settings.entries[].description' "$RADIO_CONFIG_FILE")
  mapfile -t _RADIO_BWS    < <(jq -r '.config.suggested_radio_settings.entries[].bandwidth' "$RADIO_CONFIG_FILE")

  if [ "${#_RADIO_TITLES[@]}" -eq 0 ]; then
    echo "No suggested_radio_settings entries found."
    return 1
  fi
  
  # Get system tz and our best-guess title
  local tz guess_title
  tz="$(get_system_timezone || echo "")"
  guess_title="$(guess_radio_title_from_timezone "$tz")"

  # First pass: count base names (strip " (" and following)
  declare -A base_counts
  local i base
  for i in "${!_RADIO_TITLES[@]}"; do
    base="${_RADIO_TITLES[i]%% (*}"
    base_counts["$base"]=$(( ${base_counts["$base"]:-0} + 1 ))
  done

  echo -n "System timezone: ${tz:-unknown}"
  [ -n "$guess_title" ] && echo ". Guessed region: $guess_title" || echo
  echo "Select a suggested radio setting:"
  echo " 0) Custom (manual freq / SF / BW / CR)"

  # Second pass: print with colors for duplicates and BW
  local idx title t_lower color mark bw
  for i in "${!_RADIO_TITLES[@]}"; do
    idx=$(( i + 1 ))
    title="${_RADIO_TITLES[i]}"
    base="${title%% (*}"
    t_lower="${title,,}"
    bw="${_RADIO_BWS[i]}"

    # default color
    color="$RESET"

    # If there are duplicate base names, mark non-narrow/non-recommended as red
    if [ "${base_counts["$base"]}" -gt 1 ]; then
      if [[ "$t_lower" == *"narrow"* || "$t_lower" == *"recommended"* ]]; then
        # preferred variant: normal color
        color="$RESET"
      else
        color="$RED"
      fi
    fi

    # If bandwidth is not 62.5, override to gray
    if [ "$bw" != "62.5" ]; then
      color="$GRAY"
    fi

    mark=""
    if [ -n "$guess_title" ] && [[ "$title" == *"$guess_title"* ]]; then
      mark="*"
    fi

    printf "%2d) %b%-25s%b %s %s\n" "$idx" "$color" "$title" "$RESET" "${_RADIO_DESCS[i]}" "$mark"
  done

  local choice sel
  while :; do
    print_detected_node_summary
    read -rp "Choice (0-${#_RADIO_TITLES[@]}, Enter for $guess_title, or q to quit): " choice
    case "$choice" in
      q|Q)
        echo "Aborted."
        return 1
        ;;
      '')
        if [ -n "$guess_title" ]; then
          # Try to find an exact match first, then substring
          sel=-1
          for i in "${!_RADIO_TITLES[@]}"; do
            if [ "${_RADIO_TITLES[i]}" = "$guess_title" ]; then
              sel="$i"
              break
            fi
          done
          if [ "$sel" -lt 0 ]; then
            for i in "${!_RADIO_TITLES[@]}"; do
              if [[ "${_RADIO_TITLES[i]}" == *"$guess_title"* ]]; then
                sel="$i"
                break
              fi
            done
          fi
          if [ "$sel" -ge 0 ]; then
            echo "Using guessed region: ${_RADIO_TITLES[$sel]}"
            break
          else
            echo "Could not match guessed region; please choose a number."
          fi
        else
          echo "No guessed region available; please choose a number."
        fi
        ;;
      *[!0-9]*)
        echo "Please enter a number, Enter for $guess_title, or q."
        ;;
      *)
        if [ "$choice" -eq 0 ]; then
          # Custom selection path
          if select_custom_radio_setting; then
            return 0
          else
            echo "Custom selection failed."
            return 1
          fi
        elif [ "$choice" -ge 1 ] && [ "$choice" -le "${#_RADIO_TITLES[@]}" ]; then
          sel=$(( choice - 1 ))
          break
        else
          echo "Out of range."
        fi
        ;;
    esac
  done

  RADIO_FREQ=$(jq -r ".config.suggested_radio_settings.entries[$sel].frequency"        "$RADIO_CONFIG_FILE")
  RADIO_SF=$(jq   -r ".config.suggested_radio_settings.entries[$sel].spreading_factor" "$RADIO_CONFIG_FILE")
  RADIO_BW=$(jq   -r ".config.suggested_radio_settings.entries[$sel].bandwidth"        "$RADIO_CONFIG_FILE")
  RADIO_CR=$(jq   -r ".config.suggested_radio_settings.entries[$sel].coding_rate"      "$RADIO_CONFIG_FILE")

  return 0
}

choose_serial() {
	local detected_dev
    local devs labels               # arrays that hold paths and friendly names
    local choice

    scan() {                        # fill devs[] / labels[]
        devs=()  labels=()
        shopt -s nullglob           # make the glob expand to nothing if empty
        for link in /dev/serial/by-id/*; do
            devs+=( "$(readlink -f "$link")" )
            labels+=( "$(basename "$link")" )
        done
        shopt -u nullglob
    }

    while :; do
        scan

        # -------------------------- nothing found --------------------------
        if ((${#devs[@]} == 0)); then
            echo "No serial devices found under /dev/serial/by-id."
            read -rp "Try again? [y/N] " yn
            [[ $yn =~ ^[Yy]$ ]] || return 1         # give up
            continue                                # rescan
        fi

        # -------------------------- single device --------------------------
	        if ((${#devs[@]} == 1)); then
				detected_dev="${devs[0]}"
	            #echo "Only one device detected - selecting it automatically: $detected_dev - ${labels[0]}"
				DEVICE_NAME="$detected_dev"
				SETUP_USB_SELECTED_LINK="/dev/serial/by-id/${labels[0]}"
				return
	        fi

        # -------------------------- menu --------------------------
        echo "Select a serial device:"
        for i in "${!devs[@]}"; do
            printf " %2d) %s  (%s)\n" $((i+1)) "${devs[$i]}" "${labels[$i]}"
        done
        echo "  0)  Scan again"

        read -rp "Choice: " choice
        if [[ $choice =~ ^[0-9]+$ ]]; then
            if (( choice == 0 ));     then continue          # rescan
	            elif (( choice >= 1 && choice <= ${#devs[@]} )); then
					detected_dev="${devs[choice-1]}"
					echo "$detected_dev"
					DEVICE_NAME="$detected_dev"
					SETUP_USB_SELECTED_LINK="/dev/serial/by-id/${labels[choice-1]}"
					return
	            fi
        fi
        echo "Invalid selection - please try again."
    done
}

setup_usb_reset_helper_matches() {
  local helper="$1" actual_hash
  [[ -f "$helper" ]] || return 1
  actual_hash="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read().replace(b"\r\n", b"\n")).hexdigest())' "$helper")" || return 1
  [[ "$actual_hash" == "$MESHCORE_USB_RESET_TOOL_SHA256" ]]
}

resolve_setup_usb_reset_helper() {
  local bundled="${PWD_SCRIPT}/tools/meshcore_usb_reset.py"
  local cache_dir="${FIRMWARE_ROOT}/tools" cached partial
  if ! command -v python3 >/dev/null 2>&1; then
    echo "USB connection recovery requires Python 3; normal setup remains available." >&2
    return 1
  fi
  if [[ -f "$bundled" ]]; then
    setup_usb_reset_helper_matches "$bundled" || {
      echo "Bundled USB reset helper does not match this mcsetup version." >&2
      return 1
    }
    printf '%s\n' "$bundled"
    return 0
  fi
  cached="${cache_dir}/meshcore_usb_reset.py"
  if setup_usb_reset_helper_matches "$cached"; then
    printf '%s\n' "$cached"
    return 0
  fi
  mkdir -p "$cache_dir" || return 1
  partial="$(mktemp "${cache_dir}/.usb-reset.XXXXXX")" || return 1
  echo "Downloading the verified USB connection recovery helper..." >&2
  if ! curl -fsSL --connect-timeout 10 --max-time 30 \
    'https://raw.githubusercontent.com/mikecarper/meshfirmware/main/tools/meshcore_usb_reset.py' -o "$partial" \
    || ! setup_usb_reset_helper_matches "$partial"; then
    rm -f -- "$partial"
    echo "USB reset helper unavailable or checksum mismatch; recovery is disabled." >&2
    return 1
  fi
  if ! mv -f -- "$partial" "$cached"; then
    rm -f -- "$partial"
    return 1
  fi
  printf '%s\n' "$cached"
}

# Capture before any serial probes, not after an unresponsive tty has been reused.
remember_setup_usb_identity() {
  SETUP_USB_IDENTITY=""
  SETUP_USB_RESET_HELPER=""
  [[ -n "${DEVICE_NAME:-}" ]] || return 1
  SETUP_USB_RESET_HELPER="$(resolve_setup_usb_reset_helper)" || return 1
  SETUP_USB_IDENTITY="$(python3 "$SETUP_USB_RESET_HELPER" --inspect --port "${SETUP_USB_SELECTED_LINK:-$DEVICE_NAME}")" || return 1
  [[ -n "$SETUP_USB_IDENTITY" ]]
}

# Return 1 for declined/unavailable; 2 after an attempted recovery fails. A caller
# must stop on 2, since a reset may have happened without a verified tty returning.
confirm_setup_usb_reset() {
  local answer result fresh_port
  if [[ -z "${SETUP_USB_IDENTITY:-}" || -z "${SETUP_USB_RESET_HELPER:-}" ]]; then
    echo "USB identity was not captured at selection. Exit and select the radio again." >&2
    return 1
  fi
  echo "Reset only the USB connection for ${DEVICE_NAME} (not a radio reboot)."
  echo "This does not erase settings or enter the bootloader. Close other serial programs first."
  read -rp "Reset this USB connection now? [y/N]: " answer || return 1
  [[ "$answer" =~ ^[Yy]$ ]] || return 1
  setup_usb_reset_helper_matches "$SETUP_USB_RESET_HELPER" || {
    echo "USB reset helper changed; recovery cancelled." >&2
    return 1
  }
  ensure_sudo_session || return 1
  if ! result="$(timeout --kill-after=2 20 sudo -n python3 "$SETUP_USB_RESET_HELPER" --port "$DEVICE_NAME" \
      --expected-identity "$SETUP_USB_IDENTITY" --timeout 10)"; then
    echo "USB recovery failed. Setup stopped; check the connection and select the radio again." >&2
    return 2
  fi
  fresh_port="$(jq -er --argjson expected "$SETUP_USB_IDENTITY" \
    'select(.status == "reset" and .identity == ($expected.identity // $expected))
     | .port | select(type == "string" and test("^/dev/tty[A-Za-z0-9]+$"))' <<<"$result")" || return 2
  DEVICE_NAME="$fresh_port"
  SETUP_USB_IDENTITY="$result"
  echo "USB connection restored on ${DEVICE_NAME}."
}

ensure_serial_access() {
  local device="${1:-$DEVICE_NAME}"

  [[ -z "$device" ]] && device="/dev/ttyACM0"

  if [[ -r "$device" && -w "$device" ]]; then
    return 0
  fi

  ensure_sudo_session
  sudo chmod a+rw "$device" >/dev/null 2>&1 || true
}

serial_cmd_echo() {
	local line="$*"
	local device_name_now="${DEVICE_NAME}"
	if [[ -z "${device_name_now}" ]]; then
		device_name_now="/dev/ttyACM0"
	fi
	printf '%s\n' "printf '%b' '${line}\\r\\n' | socat - \"OPEN:${device_name_now},raw,echo=0,b115200\" "
}

# Helper to send a command and capture reply
# Global cache for last known-good baud
serial_cmd() {
  local line="$*"

  local max_retries="${SERIAL_RETRIES:-3}"
  local delay_between="${SERIAL_RETRY_DELAY:-0.08}"
  local allow_blank_response="${SERIAL_ALLOW_BLANK_RESPONSE:-0}"
  local first_candidate_only="${SERIAL_FIRST_CANDIDATE_ONLY:-0}"
  local output_mode="${SERIAL_OUTPUT_MODE:-last}" # "last" (default) or "all"
  local response_regex="${SERIAL_RESPONSE_REGEX:-}"
  local extract_regex="${SERIAL_EXTRACT_REGEX:-}"

  # Fast read/exit behavior
  local total_timeout="${SERIAL_TOTAL_TIMEOUT:-7.5s}"  # seconds, optional s suffix
  local idle_timeout="${SERIAL_IDLE_TIMEOUT:-2.5}"    # socat exits after idle
  local device_name_now="${DEVICE_NAME}"
  if [[ -z "${device_name_now}" ]]; then
	device_name_now="/dev/ttyACM0"
  fi

  ensure_serial_access "$device_name_now"

  # Device noise lines to skip when reading command replies.
  local ts_log_pat='[0-9]{1,2}:[0-9]{2}(:[0-9]{2})?[[:space:]]*-[[:space:]]*[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}[[:space:]]+[A-Z]+([[:space:]]+[A-Z]+)*[:,]'
  local level_log_pat='^\[?(D?EBUG|T?RACE|I?NFO|W?ARN(ING)?|E?RR(OR)?|C?RITICAL|N?OTICE|V?ERBOSE)\]?[[:space:]]*:'
  local traffic_log_pat='(Dispatcher::|RadioLibWrapper:|payload_len=|SNR=|RSSI=|score delay|noise_floor|recv_errors|"(recv|sent|flood_tx|direct_tx|flood_rx|direct_rx)"[[:space:]]*:|[[:space:]]U[[:space:]]*(RX|TX)[,[:space:]])'
  local command_artifact_pat='^[[:space:]]*(get|set)[[:space:]]|[-=]+>[[:space:]]*>?'
  local damaged_guest_echo_pat='^[[:space:]]*g?e?t?[[:space:]]+gues?t?[.]password[[:space:]]*$'
  local noise_pat="(${ts_log_pat})|(${level_log_pat})|(${traffic_log_pat})|(${command_artifact_pat})|(${damaged_guest_echo_pat})"

  # Ensure socat is installed.
  ensure_command socat >&2

  # Build local candidate list (unique, in priority order)
  local -a candidates=()
  _add_unique() {
    local v="$1"
    local x
    [[ -z "$v" ]] && return 0
    for x in "${candidates[@]}"; do
      [[ "$x" == "$v" ]] && return 0
    done
    candidates+=("$v")
  }

  _add_unique "${SERIAL_BAUD_CACHE-}"
  _add_unique "${BAUD-}"
  local b
  for b in "${DEFAULT_BAUDS[@]}"; do
    _add_unique "$b"
  done
  if [[ "$first_candidate_only" == "1" && ${#candidates[@]} -gt 0 ]]; then
    candidates=("${candidates[0]}")
  fi

  local baud attempt out last_out rc=0
  last_out=""

  for baud in "${candidates[@]}"; do
    for ((attempt=1; attempt<=max_retries; attempt++)); do
      if out="$(
        printf '%s\r\n' "$line" \
          | {
              # Keep reading after printf closes stdin. Bound only the serial
              # reader so the filters can finish and retain replies even when
              # continuous packet logs keep the idle timeout from firing.
              read_status=0
              timeout --foreground --kill-after=1s "$total_timeout" \
                socat -t "${total_timeout%s}" -T "$idle_timeout" - \
                  "OPEN:${device_name_now},raw,echo=0,b${baud}" 2>/dev/null \
                || read_status=$?
              case "$read_status" in
                0|124|137) : ;;
                *) exit "$read_status" ;;
              esac
            } \
          | tr '\r' '\n' \
          | sed -E $'s/\x1B\\[[0-9;]*[A-Za-z]//g' \
          | {
              if [[ -n "$extract_regex" ]]; then
                grep -Eo "$extract_regex" || true
              else
                MCSETUP_SERIAL_COMMAND="$line" awk \
                  -v mode="$output_mode" -v response_regex="$response_regex" \
                  -v noise_pat="$noise_pat" '
                  BEGIN { cmd = ENVIRON["MCSETUP_SERIAL_COMMAND"] }
                  {
                    sub(/^[[:space:][:cntrl:]]+/, "")
                    marked = sub(/^(->|>)+[[:space:]]*/, "")
                    sub(/[[:space:]]+$/, "")
                    if (!NF || $0 == cmd) next
                    # A marked CLI reply can itself start with ERR: or contain
                    # log-like text (for example a node name or owner.info).
                    if (!marked && $0 ~ noise_pat) next
                    if (response_regex != "" && $0 !~ response_regex) next
                    if (mode == "all") print
                    else keep = $0
                  }
                  END { if (mode != "all") print keep }
                '
              fi
            }
      )"; then
        rc=0
      else
        rc=$?
        out=""
      fi

      last_out="$out"

      if [[ "$allow_blank_response" == "1" && $rc -eq 0 && -z "$out" ]]; then
        SERIAL_BAUD_CACHE="$baud"
        BAUD="$baud"
        return 0
      fi

      # Echoes and logs have already been filtered; preserve marked error replies.
      if [[ -z "$out" ]]; then
        sleep "$delay_between"
        continue
      fi

      # Success: cache and return
      SERIAL_BAUD_CACHE="$baud"
      BAUD="$baud"  # optional
      printf '%s' "$out"
      return 0
    done
  done

  # A silent device returns an empty reply; report transport failures separately.
  printf '%s' "$last_out"
  return "$rc"
}

serial_cmd_multiline_200ms() {
  SERIAL_RETRIES=1 SERIAL_OUTPUT_MODE=all SERIAL_IDLE_TIMEOUT=0.2 SERIAL_TOTAL_TIMEOUT=2s serial_cmd "$@"
}

serial_setting_cmd() {
  case "${SERIAL_SETTINGS_PROFILE:-conservative}" in
    fast)
      SERIAL_RETRIES=1 SERIAL_FIRST_CANDIDATE_ONLY=1 \
        SERIAL_IDLE_TIMEOUT=0.2 SERIAL_TOTAL_TIMEOUT=0.5s serial_cmd "$@"
      ;;
    known-noisy)
      SERIAL_RETRIES=1 SERIAL_FIRST_CANDIDATE_ONLY=1 \
        SERIAL_IDLE_TIMEOUT=0.35 SERIAL_TOTAL_TIMEOUT=2s serial_cmd "$@"
      ;;
    *) serial_cmd "$@" ;;
  esac
}

run_raw_command() {
  local line="$1" raw_out
  if [[ -z "$line" ]]; then
    echo "No command entered."
    return 0
  fi
  if [[ -z "${DEVICE_NAME:-}" ]]; then
    echo "No serial port selected. Exit and select a radio first."
    return 0
  fi

  echo "Running: $line"
  # Clock parsing is not a connection test. Send explicit raw commands even if
  # the clock query failed, and never replay a write while scanning baud rates.
  # Discover the baud with a read-only command if no earlier foreground command
  # cached it (command-substitution reads cannot update the parent shell cache).
  if [[ -z "${SERIAL_BAUD_CACHE:-}" ]]; then
    SERIAL_RETRIES=1 serial_cmd "board" >/dev/null || true
  fi
  if raw_out="$(SERIAL_RETRIES=1 SERIAL_FIRST_CANDIDATE_ONLY=1 \
      SERIAL_OUTPUT_MODE=all serial_cmd "$line")"; then
    if [[ -n "$raw_out" ]]; then
      printf '%s\n' "$raw_out"
    else
      echo "No reply received. Check the radio before retrying; no automatic retry was made."
    fi
  else
    echo "Serial command failed on ${DEVICE_NAME}. Check the connection and close other serial programs."
  fi
}

open_picocom_console() {
  local console_baud="${SERIAL_BAUD_CACHE:-${BAUD:-115200}}"

  if [[ -z "${DEVICE_NAME:-}" ]]; then
    echo "No serial port selected. Exit and select a radio first."
    return 0
  fi
  if [[ ! -e "$DEVICE_NAME" ]]; then
    echo "Serial port ${DEVICE_NAME} is not present."
    return 0
  fi
  if [[ ! "$console_baud" =~ ^[0-9]+$ ]]; then
    console_baud=115200
  fi
  if ! ensure_command picocom; then
    echo "Could not install picocom; returning to setup."
    return 0
  fi

  ensure_serial_access "$DEVICE_NAME" || true
  echo
  echo "Opening picocom on ${DEVICE_NAME} at ${console_baud} baud."
  echo "To exit: press Ctrl-A, release it, then press Ctrl-X."
  echo "Ctrl-C is sent to the radio and does not exit picocom."
  echo
  if ! picocom --baud "$console_baud" --flow n --noreset "$DEVICE_NAME"; then
    echo "Picocom ended with an error; returning to setup."
  else
    echo "Returned to setup."
  fi
  return 0
}

read_usb_logging_setting() {
  local capture value read_status=0
  capture="$(mktemp)" || return 1
  if SERIAL_RETRIES=1 SERIAL_IDLE_TIMEOUT=0.35 SERIAL_TOTAL_TIMEOUT=1.5s \
    SERIAL_RESPONSE_REGEX='^(on|off|true|false|0|1)$' \
    serial_cmd 'get usb.logging' >"$capture" 2>/dev/null; then
    read_status=0
  else
    read_status=$?
  fi
  value="$(<"$capture")"
  rm -f -- "$capture"
  (( read_status == 0 )) || return 1
  value="$(trim "$value")"
  case "${value,,}" in
    on|true|1) USB_LOGGING_SETTING=on ;;
    off|false|0) USB_LOGGING_SETTING=off ;;
    *) return 1 ;;
  esac
}

setup_has_separate_logging_tty() {
  local by_id_dir="${MCSETUP_SERIAL_BY_ID_DIR:-/dev/serial/by-id}"
  local selected_name prefix candidate candidate_name
  selected_name="$(basename "${SETUP_USB_SELECTED_LINK:-}")"
  [[ "$selected_name" == *-if00* ]] || return 1
  prefix="${selected_name%%-if00*}"
  shopt -s nullglob
  for candidate in "$by_id_dir"/*; do
    candidate_name="$(basename "$candidate")"
    if [[ "$candidate_name" == "${prefix}-if02"* ]]; then
      shopt -u nullglob
      return 0
    fi
  done
  shopt -u nullglob
  return 1
}

prime_serial_baud() {
  local capture
  [[ -n "${SERIAL_BAUD_CACHE:-}" ]] && return 0
  capture="$(mktemp)" || return 1
  SERIAL_RETRIES=1 SERIAL_IDLE_TIMEOUT=0.35 SERIAL_TOTAL_TIMEOUT=1.5s \
    serial_cmd board >"$capture" 2>/dev/null || true
  rm -f -- "$capture"
  [[ -n "${SERIAL_BAUD_CACHE:-}" ]]
}

# Return 2 after requesting the firmware's immediate reboot.
offer_disable_usb_logging() {
  local answer usb_logging="" separate_logging_tty=0

  setup_has_separate_logging_tty && separate_logging_tty=1
  if read_usb_logging_setting; then
    usb_logging="$USB_LOGGING_SETTING"
  elif (( separate_logging_tty )); then
    if prime_serial_baud; then
      SERIAL_SETTINGS_PROFILE=fast
      echo "USB logging has a separate tty; fast settings reads enabled."
    fi
    return 0
  else
    return 0
  fi

  if [[ "$usb_logging" == off ]]; then
    SERIAL_SETTINGS_PROFILE=fast
    echo "USB logging is off; fast settings reads enabled."
    return 0
  fi
  if (( separate_logging_tty )); then
    SERIAL_SETTINGS_PROFILE=fast
    echo "USB logging has a separate tty; fast settings reads enabled."
    return 0
  fi

  SERIAL_SETTINGS_PROFILE=known-noisy

  echo
  echo "USB logging is enabled and is writing debug/radio traffic to this tty."
  read -rp "Turn off USB logging and reboot the radio now? [y/N]: " answer || return 0
  if [[ ! "$answer" =~ ^[Yy]$ ]]; then
    echo "USB logging left enabled; setup reads may remain slow or noisy."
    return 0
  fi

  echo "Sending: set usb.logging off reboot"
  run_raw_command 'set usb.logging off reboot'
  echo "USB logging disable/reboot command issued. Wait for the radio to reconnect, then run mcsetup.sh again."
  return 2
}

setup_usb_host_controller() {
  jq -r '.host_controller // empty' <<<"${SETUP_USB_IDENTITY:-}" 2>/dev/null || true
}

confirm_reboot_raspberry_pi() {
  local answer

  read -rp "Reboot the Raspberry Pi now? [y/N]: " answer || return 1
  if [[ ! "$answer" =~ ^[Yy]$ ]]; then
    echo "Raspberry Pi reboot skipped."
    return 1
  fi
  if ! ensure_sudo_session; then
    echo "Could not obtain sudo access; Raspberry Pi reboot cancelled." >&2
    return 2
  fi

  echo "Rebooting the Raspberry Pi..."
  if sudo systemctl reboot; then
    return 0
  fi
  if sudo reboot; then
    return 0
  fi
  echo "Could not reboot the Raspberry Pi." >&2
  return 2
}

# Return 0 to retry the radio, 1 to continue without recovery, or 2 to stop.
recover_setup_serial_connection() {
  local choice reboot_status controller
  controller="$(setup_usb_host_controller)"

  if [[ "$controller" != dwc_otg ]]; then
    confirm_setup_usb_reset
    return $?
  fi

  echo "Automatic USB reset is unavailable on this Raspberry Pi's legacy dwc_otg host."
  echo "The reset was not attempted; the existing serial port may still be testable."
  while :; do
    echo
    echo " T) Test the existing serial port with Picocom"
    echo " R) Reboot the Raspberry Pi"
    echo " C) Continue setup without USB recovery"
    echo " Q) Quit setup"
    read -rp "Choice: " choice || return 2
    case "$choice" in
      t|T|p|P)
        open_picocom_console
        reboot_status=0
        offer_disable_usb_logging || reboot_status=$?
        if (( reboot_status == 2 )); then exit 0; fi
        echo "Retrying the radio after the Picocom test..."
        return 0
        ;;
      r|R)
        reboot_status=0
        if confirm_reboot_raspberry_pi; then
          exit 0
        else
          reboot_status=$?
          if (( reboot_status == 2 )); then return 2; fi
        fi
        ;;
      c|C|"") return 1 ;;
      q|Q) return 2 ;;
      *) echo "Choose T, R, C, or Q." ;;
    esac
  done
}

read_hex_key_setting() {
  local key="$1"
  local hex_chars="$2"
  local extract_regex="[0-9A-Fa-f]{$hex_chars}"
  local raw

  # Key replies are immediate and can be followed by unrelated debug output.
  # Extract the complete key before rejecting noisy lines, since debug output
  # can otherwise cause a valid key sharing that line to be discarded.
  raw="$(SERIAL_EXTRACT_REGEX="$extract_regex" serial_cmd_multiline_200ms "get $key")"
  printf '%s\n' "$raw" | grep -Eo "$extract_regex" | head -n1 || true
}

trim() {
  if [ $# -gt 0 ]; then
    # Trim the argument(s)
    printf '%s' "$*" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
  else
    # Trim data from stdin
    sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
  fi
}

clean_node_info_field() {
  local value="${1:-}"

  value="$(printf '%s' "$value" \
    | LC_ALL=C tr -cd '\11\12\15\40-\176' \
    | tr '\r\n' '  ' \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/[[:space:]]+/ /g')"
  if (( ${#value} > 120 )) \
    || [[ ! "$value" =~ ^[[:alnum:]][[:alnum:][:space:].,_+:/()#-]*$ ]]; then
    value=""
  fi
  case "${value,,}" in
    "unknown command"*|"err:"*|"error:"*|"error,"*|"error "*) value="" ;;
  esac
  printf '%s' "$value"
}

normalize_firmware_version() {
  local version
  version="$(clean_node_info_field "${1:-}")"
  version="${version#Companion }"
  version="${version%% (Build:*}"
  version="${version%% (protocol *}"
  trim "$version"
}

format_detected_node_summary() {
  local board="${1:-}" version="${2:-}"

  [[ -n "$board" || -n "$version" ]] || return 1
  printf 'Detected:'
  [[ -n "$board" ]] && printf ' %s' "$board"
  if [[ -n "$version" ]]; then
    [[ -n "$board" ]] && printf '.'
    printf ' %s' "$version"
  fi
}

print_detected_node_summary() {
  local summary=''
  summary="$(format_detected_node_summary \
    "$DETECTED_NODE_BOARD" "$DETECTED_NODE_VERSION" 2>/dev/null || true)"
  if [[ -n "$summary" ]]; then
    echo "$summary"
  fi
  return 0
}

query_companion_device_info() {
  local device="$1"
  local total_timeout="${MCSETUP_INFO_TOTAL_TIMEOUT:-1.2s}"
  local idle_timeout="${MCSETUP_INFO_IDLE_TIMEOUT:-0.35}"

  [[ -e "$device" ]] || return 1
  ensure_command socat || return 1
  ensure_command perl || return 1

  # shellcheck disable=SC2016
  timeout -s KILL "$total_timeout" \
    bash -o pipefail -c '
      device=$1
      idle=$2
      # End the line too: a text repeater otherwise buffers this binary probe
      # and prepends it to the following board command. Companion ignores CR/LF.
      printf "\x3c\x02\x00\x16\x0e\r\n" \
        | socat -T "$idle" - "OPEN:${device},raw,echo=0,b115200" 2>/dev/null
    ' _ "$device" "$idle_timeout" \
    | LC_ALL=C perl -0777 -ne '
      my $buf = $_;
      my $pos = 0;
      while (($pos = index($buf, ">", $pos)) >= 0) {
        last if $pos + 3 > length($buf);
        my $len = unpack("v", substr($buf, $pos + 1, 2));
        my $end = $pos + 3 + $len;
        if ($len >= 80 && $len <= 300 && $end <= length($buf)) {
          my $payload = substr($buf, $pos + 3, $len);
          if (ord(substr($payload, 0, 1)) == 13) {
            my $model = substr($payload, 20, 40);
            $model =~ s/\x00.*//s;
            $model =~ s/^\s+|\s+$//g;
            my $version = substr($payload, 60, 20);
            $version =~ s/\x00.*//s;
            $version =~ s/^\s+|\s+$//g;
            my $protocol = ord(substr($payload, 1, 1));
            print $model, "\t", $version, "\t", $protocol;
            exit;
          }
        }
        $pos++;
      }
    '
}

query_companion_full_version() {
  local device="$1"
  local total_timeout="${MCSETUP_INFO_TOTAL_TIMEOUT:-1.2s}"
  local idle_timeout="${MCSETUP_INFO_IDLE_TIMEOUT:-0.35}"

  [[ -e "$device" ]] || return 1
  ensure_command socat || return 1
  ensure_command perl || return 1

  # Protocol v14 framed CLI commands return the complete version rather than
  # RESP_CODE_DEVICE_INFO's legacy 20-byte value.
  # shellcheck disable=SC2016
  timeout -s KILL "$total_timeout" \
    bash -o pipefail -c '
      device=$1
      idle=$2
      printf "\x3c\x08\x00\x42version\r\n" \
        | socat -T "$idle" - "OPEN:${device},raw,echo=0,b115200" 2>/dev/null
    ' _ "$device" "$idle_timeout" \
    | LC_ALL=C perl -0777 -ne '
      my $buf = $_;
      my $pos = 0;
      while (($pos = index($buf, ">", $pos)) >= 0) {
        last if $pos + 3 > length($buf);
        my $len = unpack("v", substr($buf, $pos + 1, 2));
        my $end = $pos + 3 + $len;
        if ($len >= 2 && $len <= 300 && $end <= length($buf)) {
          my $payload = substr($buf, $pos + 3, $len);
          if (ord(substr($payload, 0, 1)) == 29) {
            my $reply = substr($payload, 1);
            $reply =~ s/\x00.*//s;
            if ($reply =~ /^Companion\s+(.+?)\s+\(protocol\s+/) {
              print $1;
              exit;
            }
          }
        }
        $pos++;
      }
    '
}

refresh_detected_node_info() {
  local info=''
  local board=''
  local version=''
  local protocol=''
  local full_version=''

  info="$(query_companion_device_info "$DEVICE_NAME" 2>/dev/null || true)"
  IFS=$'\t' read -r board version protocol <<< "$info"
  board="$(clean_node_info_field "$board")"
  version="$(normalize_firmware_version "$version")"

  if [[ "$protocol" =~ ^[0-9]+$ ]] && (( protocol >= 14 )); then
    full_version="$(normalize_firmware_version \
      "$(query_companion_full_version "$DEVICE_NAME" 2>/dev/null || true)")"
    [[ -z "$full_version" ]] || version="$full_version"
  fi

  [[ -n "$board" ]] \
    || board="$(clean_node_info_field "$(serial_cmd "board")")"
  [[ -n "$version" ]] \
    || version="$(normalize_firmware_version "$(serial_cmd "ver")")"

  DETECTED_NODE_BOARD="$board"
  DETECTED_NODE_VERSION="$version"
  [[ -n "$board" || -n "$version" ]]
}

# Compare numbers safely (ints/floats); returns 0 if equal
_num_equal() {
  # uses bc; treat empty as not equal
  [ -z "$1" ] || [ -z "$2" ] && return 1
  awk -v a="$1" -v b="$2" 'BEGIN{
    if (a==b) exit 0
    # numeric compare with tolerance
    aa=a+0; bb=b+0; diff=aa-bb; if (diff<0) diff=-diff
    exit (diff<=1e-9)?0:1
  }'
}

prompt_onoff() {
  # $1 = label, $2 = current, sets REPLY_ONOFF to on/off or keeps current if blank
  local lbl="$1" cur="$2" v
  while :; do
    read -rp "${lbl} (on/off, current: ${cur}): " v
    [ -z "$v" ] && { REPLY_ONOFF="$cur"; return 0; }
    case "$v" in
      on|off) REPLY_ONOFF="$v"; return 0;;
      *) echo "Please enter on or off.";;
    esac
  done
}

prompt_number() {
  # $1 = label, $2 = current; accepts int/float; sets REPLY_NUM
  local lbl="$1" cur="$2" v
  while :; do
    read -rp "${lbl} (current: ${cur}): " v
    [ -z "$v" ] && { REPLY_NUM="$cur"; return 0; }
    if [[ "$v" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
      REPLY_NUM="$v"; return 0
    else
      echo "Enter a number (e.g. 0.5, 1, 2.0)"
    fi
  done
}

# Prompt for a number within [min,max]. Blank keeps current.
# Sets REPLY_NUM on success.
prompt_number_bounded() {
  local lbl="$1" cur="$2" min="$3" max="$4" v
  while :; do
    read -rp "${lbl} (${min}-${max}, current: ${cur}): " v
    [ -z "$v" ] && { REPLY_NUM="$cur"; return 0; }
    if [[ "$v" =~ ^-?[0-9]+(\.[0-9]+)?$ ]] \
       && (( $(echo "$v >= $min && $v <= $max" | bc -l) )); then
      REPLY_NUM="$v"
      return 0
    fi
    echo "Enter a number between ${min} and ${max}"
  done
}

set_if_changed() {
  local key="${1:?missing key}"
  local cur="${2-}"
  local new="${3-}"
  local mode="${4:-str}"
  local noprefix="${5-}"
  
  new="$( trim "$new")"
  cur="$( trim "$cur")"
  [ -z "$new" ] && { echo "No change: $key left as '$cur'"; return 0; }

  if [[ "$mode" == "num" ]]; then
    if _num_equal "$cur" "$new"; then
      echo "No change: $key remains $cur"
      return 0
    fi
  else
    # case-insensitive for on/off
    if [[ "$new" =~ ^(on|off)$ && "$cur" =~ ^(on|off)$ ]]; then
      if [ "${cur,,}" = "${new,,}" ]; then
        echo "No change: $key remains $cur"
        return 0
      fi
    else
      [ "$cur" = "$new" ] && { echo "No change: $key remains $cur"; return 0; }
    fi
  fi

  echo "Updating: $key -> $new"
  if [[ -z "$noprefix" ]]; then
	if [[ -n "${device_epoch:-}" ]]; then
		serial_cmd "set $key $new"
	else
		serial_cmd_echo "set $key $new"
	fi
  else
	if [[ -n "${device_epoch:-}" ]]; then
		serial_cmd "$key $new"
	else
		serial_cmd_echo "$key $new"
	fi
  fi
}

set_empty_settings() {
	setting_af="" ;
	setting_int_thresh="" 
	setting_agc_reset_interval=""
	setting_multi_acks=""
	setting_allow_read_only=""
	setting_flood_advert_interval=""
	setting_advert_interval=""
	setting_dutycycle=""
	setting_guest_password=""
	setting_password=""
	setting_name=""
	setting_repeat=""
	setting_lat=""
	setting_lon=""
	setting_private_key=""
	setting_public_key=""
	setting_owner_info=""
	setting_path_hash_mode=""
	setting_loop_detect=""
	setting_rxdelay=""
	setting_txdelay=""
	setting_direct_txdelay=""
	setting_flood_max=""
	setting_tx=""
	setting_role=""
	setting_powersaving=""
	
	radio_raw=""
	RADIO_FREQ_OLD=""
	RADIO_BW_OLD=""
	RADIO_SF_OLD=""
	RADIO_CR_OLD=""
	RADIO_FREQ=""
	RADIO_BW=""
	RADIO_SF=""
	RADIO_CR=""
}

load_repeater_settings() {
  echo "reading all radio settings"

  # https://github.com/meshcore-dev/MeshCore/blob/main/src/helpers/CommonCLI.cpp#L131
  # keys to fetch (radio handled separately)
  local k v response_regex
  local keys=(
	  dutycycle
	  tx
	  repeat
	  role
	  allow.read.only
	  txdelay
	  rxdelay
	  direct.txdelay
	  agc.reset.interval
	  int.thresh
	  af
	  multi.acks
	  advert.interval
	  flood.advert.interval
	  flood.max
	  guest.password
	  password
	  name
	  owner.info
	  path.hash.mode
	  loop.detect
	  prv.key
	  public.key
	  lat
	  lon
  )

  # fetch generic keys
  for k in "${keys[@]}"; do
    printf '\rReading setting: %-24s' "$k"
    case "$k" in
      dutycycle|tx|txdelay|rxdelay|direct.txdelay|agc.reset.interval|int.thresh|af|multi.acks|advert.interval|flood.advert.interval|flood.max|lat|lon|path.hash.mode)
        response_regex='^[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+)%?$'
        ;;
      repeat|allow.read.only)
        response_regex='^(on|off|true|false|0|1)$'
        ;;
      loop.detect)
        response_regex='^(off|minimal|moderate|strict)$'
        ;;
      role)
        response_regex='^[0-9A-Za-z_.-]+$'
        ;;
      *)
        response_regex=''
        ;;
    esac
    case "$k" in
      guest.password)
        v="$(SERIAL_ALLOW_BLANK_RESPONSE=1 serial_setting_cmd "get $k" | trim)"
        ;;
      owner.info)
        v="$(SERIAL_ALLOW_BLANK_RESPONSE=1 serial_setting_cmd "get $k" | trim)"
        ;;
      prv.key)
        v="$(read_hex_key_setting "$k" 128)"
        ;;
      public.key)
        v="$(read_hex_key_setting "$k" 64)"
        ;;
      *)
        v="$(SERIAL_RESPONSE_REGEX="$response_regex" serial_setting_cmd "get $k" | trim)"
        ;;
    esac
    case "$k" in
	  dutycycle)             setting_dutycycle="$v" ;;
	  af)             		  setting_af="$v" ;;
	  int.thresh)             setting_int_thresh="$v" ;;
      agc.reset.interval)     setting_agc_reset_interval="$v" ;;
	  multi.acks)             setting_multi_acks="$v" ;;
	  allow.read.only)        setting_allow_read_only="$v" ;;
	  flood.advert.interval)  setting_flood_advert_interval="$v" ;;
      advert.interval)        setting_advert_interval="$v" ;;
      guest.password)         setting_guest_password="$v" ;;
      password)               setting_password="$v" ;;
	  name)                   setting_name="$v" ;;
	  owner.info)             setting_owner_info="$v" ;;
	  path.hash.mode)         setting_path_hash_mode="$v" ;;
	  loop.detect)            setting_loop_detect="$v" ;;
	  repeat)                 setting_repeat="$v" ;;
	  lat)                    setting_lat="$v" ;;
      lon)                    setting_lon="$v" ;;
      prv.key)                setting_private_key="$(printf '%s\n' "$v" | grep -Eo '[0-9A-Fa-f]{128}' | head -n1 || true)" ;;
      public.key)             setting_public_key="$(printf '%s\n' "$v" | grep -Eo '[0-9A-Fa-f]{64}' | head -n1 || true)" ;;
      rxdelay)                setting_rxdelay="$v" ;;
      txdelay)                setting_txdelay="$v" ;;
      direct.txdelay)         setting_direct_txdelay="$v" ;;
      flood.max)              setting_flood_max="$v" ;;
	  tx)                     setting_tx="$v" ;;
	  role)                   setting_role="$v" ;;

    esac
  done
  
  printf '\rReading setting: %-24s' "powersaving"
  setting_powersaving="$(SERIAL_RESPONSE_REGEX='^(on|off)$' serial_setting_cmd 'powersaving' | trim)"

  # radio needs CSV parsing: {freq},{bw},{sf},{cr}
  local radio_raw
  printf '\rReading setting: %-24s' "radio"
  radio_raw="$(SERIAL_RESPONSE_REGEX='^[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+),[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+),[0-9]+,[0-9]+$' serial_setting_cmd 'get radio' | trim)"
  # remove spaces around commas just in case
  radio_raw="$(echo "$radio_raw" | sed -E 's/[[:space:]]*,[[:space:]]*/,/g')"
  IFS=',' read -r RADIO_FREQ RADIO_BW RADIO_SF RADIO_CR <<< "$radio_raw"
  printf '\n\n'
}

edit_repeater_settings_menu() {
  local reset_status
  while :; do
    echo
    echo "Current settings:"
	echo " 0) Send Raw Command"
    echo " 1) tx                    = $setting_tx"
    echo " 2) repeat                = $setting_repeat"
    echo " 3) allow.read.only       = $setting_allow_read_only"
    echo " 4) agc.reset.interval    = $setting_agc_reset_interval"
    echo " 5) advert.interval       = $setting_advert_interval"
    echo " 6) flood.advert.interval = $setting_flood_advert_interval"
    echo " 7) flood.max             = $setting_flood_max"
    echo " 8) guest.password        = $setting_guest_password"
    echo " 9) password              = $setting_password (Reading is broken)"
    echo "10) private key           = ${setting_private_key:0:8}..."
    echo "11) public key            = ${setting_public_key:0:16}...${setting_public_key:48:16} (read-only)"
    echo "12) name                  = $setting_name"
    echo "13) lat                   = $setting_lat"
    echo "14) lon                   = $setting_lon"
    echo "15) role                  = $setting_role (read-only)"
    echo "16) txdelay               = $setting_txdelay"
    echo "17) rxdelay               = $setting_rxdelay"
    echo "18) direct.txdelay        = $setting_direct_txdelay"
    echo "19) int.thresh            = $setting_int_thresh"
    echo "20) af                    = $setting_af"
    echo "21) multi.acks            = $setting_multi_acks"
    echo "22) radio                 = freq=$RADIO_FREQ bw=$RADIO_BW sf=$RADIO_SF cr=$RADIO_CR"
    echo "23) powersaving           = $setting_powersaving"
    echo "24) dutycycle             = $setting_dutycycle"
    echo "25) owner.info            = $setting_owner_info"
    echo "26) path.hash.mode        = $setting_path_hash_mode"
    echo "27) loop.detect           = $setting_loop_detect"
	echo " R) Refresh above settings from device"
    echo " Z) Send zero-hop advert now"
    echo " A) Send flood advert now"
    echo " L) Logs: start/stop/erase"
    echo " D) Dump log"
    echo " N) Show neighbors"
    echo " X) Remove neighbor by pubkey"
    echo " O) Start OTA"
    echo " K) Clock-reset reboot"
    echo " U) Reset USB connection (not a radio reboot)"
    echo " P) Picocom serial console (exit: Ctrl-A, then Ctrl-X)"
    echo " C) Clear stats"
	echo " Q) Quit"
    echo
    echo "Choose an item, an action, type a firmware command, or q to finish."
    print_detected_node_summary
    read -rp "Choice: " choice

    case "$choice" in
      q|Q) echo "Done."; break ;;

      r|R)
        echo "Reloading settings from device..."
        load_repeater_settings
		snapshot_radio_baseline
        ;;

      u|U)
        if confirm_setup_usb_reset; then
          refresh_detected_node_info || true
          device_epoch="$(read_device_clock_epoch)"
          if [[ -n "$device_epoch" ]]; then
            load_repeater_settings
            snapshot_radio_baseline
          else
            echo "USB reset completed, but the radio still did not answer the clock query."
          fi
        else
          reset_status=$?
          if (( reset_status == 2 )); then return 2; fi
        fi
        ;;

      p|P)
        open_picocom_console
        ;;

		0)
          echo "Examples: get tx; get tempradioat"
          echo "Temporary radio: tempradio 910.1,500,7,5,180 (180 minutes = 3 hours)"
          echo "Scheduled radio: set tempradioat freq,bw,sf,cr,start_epoch,end_epoch"
          read -rp "Command to run: " v
          run_raw_command "$v"
		  ;;

		1)
		  prompt_number "tx" "$setting_tx"
		  set_if_changed "tx" "$setting_tx" "$REPLY_NUM" num
		  [ -n "$REPLY_NUM" ] && setting_tx="$REPLY_NUM"
		  ;;

		2)
		  prompt_onoff "repeat" "$setting_repeat"
		  set_if_changed "repeat" "$setting_repeat" "$REPLY_ONOFF"
		  [ -n "$REPLY_ONOFF" ] && setting_repeat="$REPLY_ONOFF"
		  ;;

		3)
		  prompt_onoff "allow.read.only" "$setting_allow_read_only"
		  set_if_changed "allow.read.only" "$setting_allow_read_only" "$REPLY_ONOFF"
		  [ -n "$REPLY_ONOFF" ] && setting_allow_read_only="$REPLY_ONOFF"
		  ;;

		4)
		  prompt_number "agc.reset.interval" "$setting_agc_reset_interval"
		  set_if_changed "agc.reset.interval" "$setting_agc_reset_interval" "$REPLY_NUM" num
		  [ -n "$REPLY_NUM" ] && setting_agc_reset_interval="$REPLY_NUM"
		  ;;

		5)
		  prompt_number "advert.interval" "$setting_advert_interval"
		  set_if_changed "advert.interval" "$setting_advert_interval" "$REPLY_NUM" num
		  [ -n "$REPLY_NUM" ] && setting_advert_interval="$REPLY_NUM"
		  ;;

		6)
		  prompt_number "flood.advert.interval" "$setting_flood_advert_interval"
		  set_if_changed "flood.advert.interval" "$setting_flood_advert_interval" "$REPLY_NUM" num
		  [ -n "$REPLY_NUM" ] && setting_flood_advert_interval="$REPLY_NUM"
		  ;;

		7)
		  prompt_number "flood.max" "$setting_flood_max"
		  set_if_changed "flood.max" "$setting_flood_max" "$REPLY_NUM" num
		  [ -n "$REPLY_NUM" ] && setting_flood_max="$REPLY_NUM"
		  ;;

		8)
		  read -rp "guest.password (current: ${setting_guest_password:-<empty>}): " v
		  # Allow clearing by explicit "-"
		  if [ "$v" = "-" ]; then v=""; fi
		  # Only set if non-empty and changed; empty means do nothing
		  if [ -n "$v" ] && [ "$v" != "$setting_guest_password" ]; then
			echo "Updating guest.password"
			if [[ -n "${device_epoch:-}" ]]; then
				serial_cmd "set guest.password $v"
			else
				serial_cmd_echo "set guest.password $v"
			fi
			setting_guest_password="$v"
		  else
			echo "No change to guest.password"
		  fi
		  ;;

		9)
		  read -rp "password (current: ${setting_password:-<empty>}): " v
		  if [ -n "$v" ] && [ "$v" != "$setting_password" ]; then
			echo "Updating password"
			echo "password $v"
			if [[ -n "${device_epoch:-}" ]]; then
				serial_cmd "password $v"
			else
				serial_cmd_echo "password $v"
			fi

			setting_password="$v"
		  else
			echo "No change to password"
		  fi
		  ;;

		10)
		  if [[ -z "$setting_private_key" ]]; then
			echo "Retrying private key read..."
			setting_private_key="$(read_hex_key_setting "prv.key" 128)"
		  fi
		  echo "Existing key: ${setting_private_key}"
		  read -rp "private key (blank to keep): " v
		  v="$(trim "$v")"
		  if [ -n "$v" ] && [ "$v" != "$setting_private_key" ]; then
			echo "Updating private key to"
			echo "$v"
			if [[ -n "${device_epoch:-}" ]]; then
				serial_cmd "set prv.key $v"
			else
				serial_cmd_echo "set prv.key $v"
			fi
			
			setting_private_key="$v"
		  else
			echo "Private key unchanged."
		  fi
		  ;;

		12)
		  read -rp "name (current: $setting_name): " v
		  if [ -n "$v" ] && [ "$v" != "$setting_name" ]; then
			if [[ -n "${device_epoch:-}" ]]; then
				serial_cmd "set name $v"
			else
				serial_cmd_echo "set name $v"
			fi
			
			setting_name="$v"
		  else
			echo "No change to name"
		  fi
		  ;;

		13)
		  # Latitude must be within [-90, 90]
		  prompt_number_bounded "lat" "$setting_lat" -90.0 90.0
		  set_if_changed "lat" "$setting_lat" "$REPLY_NUM" num
		  [ -n "$REPLY_NUM" ] && setting_lat="$REPLY_NUM"
		  ;;

		14)
		  # Longitude must be within [-180, 180]
		  prompt_number_bounded "lon" "$setting_lon" -180.0 180.0
		  set_if_changed "lon" "$setting_lon" "$REPLY_NUM" num
		  [ -n "$REPLY_NUM" ] && setting_lon="$REPLY_NUM"
		  ;;


		16)
		  prompt_number_bounded "txdelay" "$setting_txdelay" 0.0 2.0
		  set_if_changed "txdelay" "$setting_txdelay" "$REPLY_NUM" num
		  [ -n "$REPLY_NUM" ] && setting_txdelay="$REPLY_NUM"
		  ;;

		17)
		  prompt_number "rxdelay" "$setting_rxdelay"
		  set_if_changed "rxdelay" "$setting_rxdelay" "$REPLY_NUM" num
		  [ -n "$REPLY_NUM" ] && setting_rxdelay="$REPLY_NUM"
		  ;;

		18)
		  prompt_number_bounded "direct.txdelay" "$setting_direct_txdelay" 0.0 2.0
		  set_if_changed "direct.txdelay" "$setting_direct_txdelay" "$REPLY_NUM" num
		  [ -n "$REPLY_NUM" ] && setting_direct_txdelay="$REPLY_NUM"
		  ;;

		19)
		  prompt_number "int.thresh" "$setting_int_thresh"
		  set_if_changed "int.thresh" "$setting_int_thresh" "$REPLY_NUM" num
		  [ -n "$REPLY_NUM" ] && setting_int_thresh="$REPLY_NUM"
		  ;;

		20)
		  prompt_number_bounded "af" "$setting_af" 0.0 1.0
		  set_if_changed "af" "$setting_af" "$REPLY_NUM" num
		  [ -n "$REPLY_NUM" ] && setting_af="$REPLY_NUM"
		  ;;

		21)
		  prompt_number_bounded "multi.acks" "$setting_multi_acks" 0 1
		  set_if_changed "multi.acks" "$setting_multi_acks" "$REPLY_NUM" num
		  [ -n "$REPLY_NUM" ] && setting_multi_acks="$REPLY_NUM"
		  ;;

		22)
		  if select_suggested_radio_setting; then
			# Only send if any component changed
			if [ "$RADIO_FREQ" != "$RADIO_FREQ_OLD" ] || [ "$RADIO_BW" != "$RADIO_BW_OLD" ] \
			   || [ "$RADIO_SF" != "$RADIO_SF_OLD" ] || [ "$RADIO_CR" != "$RADIO_CR_OLD" ]; then
			  echo "Setting radio: ${RADIO_FREQ},${RADIO_BW},${RADIO_SF},${RADIO_CR}"
			  
				if [[ -n "${device_epoch:-}" ]]; then
					serial_cmd "set radio ${RADIO_FREQ},${RADIO_BW},${RADIO_SF},${RADIO_CR}"
				else
					serial_cmd_echo "set radio ${RADIO_FREQ},${RADIO_BW},${RADIO_SF},${RADIO_CR}"
				fi
			  
			else
			  echo "Radio unchanged."
			fi
		  fi
		  ;;
		  
		23)
		  echo "Turning this ON will kill the USB connection right away"
		  prompt_onoff "powersaving" "$setting_powersaving"
		  set_if_changed "powersaving" "$setting_powersaving" "$REPLY_ONOFF" "" "1"
		  [ -n "$REPLY_ONOFF" ] && setting_powersaving="$REPLY_ONOFF"
		  ;;

		24)
		  prompt_number_bounded "dutycycle" "$setting_dutycycle" 1 100
		  set_if_changed "dutycycle" "$setting_dutycycle" "$REPLY_NUM" num
		  [ -n "$REPLY_NUM" ] && setting_dutycycle="$REPLY_NUM"
		  ;;

		25)
		  read -rp "owner.info (use | for line breaks, current: ${setting_owner_info:-<empty>}): " v
		  if [ -n "$v" ] && [ "$v" != "$setting_owner_info" ]; then
			echo "Updating owner.info"
			if [[ -n "${device_epoch:-}" ]]; then
				serial_cmd "set owner.info $v"
			else
				serial_cmd_echo "set owner.info $v"
			fi
			setting_owner_info="$v"
		  else
			echo "No change to owner.info"
		  fi
		  ;;

		26)
		  prompt_number_bounded "path.hash.mode" "$setting_path_hash_mode" 0 2
		  set_if_changed "path.hash.mode" "$setting_path_hash_mode" "$REPLY_NUM" num
		  [ -n "$REPLY_NUM" ] && setting_path_hash_mode="$REPLY_NUM"
		  ;;

		27)
		  while :; do
			read -rp "loop.detect (off/minimal/moderate/strict, current: ${setting_loop_detect:-<empty>}): " v
			v="$(trim "$v")"
			[ -z "$v" ] && { echo "No change to loop.detect"; break; }
			case "${v,,}" in
			  off|minimal|moderate|strict)
				set_if_changed "loop.detect" "$setting_loop_detect" "${v,,}"
				setting_loop_detect="${v,,}"
				break
				;;
			  *)
				echo "Enter one of: off, minimal, moderate, strict"
				;;
			esac
		  done
		  ;;
		  
	  z|Z)
        echo "Sending zero-hop advert..."
        serial_cmd "advert.zerohop"
        ;;

	  A)
        echo "Sending flood advert..."
        serial_cmd "advert"
        ;;

      l|L)
        echo "Logs: (s)tart, s(t)op, (e)rase"
        read -rp "Choice [s/t/e]: " v
        case "$v" in
          s|S) serial_cmd "log start" ;;
          t|T) serial_cmd "log stop" ;;
          e|E) serial_cmd "log erase" ;;
          *) echo "Unknown choice." ;;
        esac
        ;;

	  d|D)
        echo "Dumping log..."
        serial_cmd "log"
        ;;

	  n|N)
        echo "Neighbors:"
        serial_cmd "neighbors"
        ;;

	  x|X)
        read -rp "Neighbor pubkey to remove: " v
        v="$(trim "$v")"
        if [ -n "$v" ]; then
          serial_cmd "neighbor.remove $v"
        else
          echo "No pubkey entered."
        fi
        ;;

	  o|O)
        echo "Starting OTA..."
        serial_cmd "start ota"
        ;;

	  k|K)
        read -rp "Run clkreboot now? This resets the device clock and reboots the node. [y/N]: " v
        [[ "$v" =~ ^[Yy]$ ]] && serial_cmd "clkreboot" || echo "Clock-reset reboot skipped."
        ;;

      c|C)
        echo "Clearing stats..."
        serial_cmd "clear stats"
        ;;

      [[:alpha:]][[:alpha:]]*)
        run_raw_command "$choice"
        ;;

      *)
        echo "Invalid choice."
        ;;
    esac
  done
}

confirm_restart_radio() {
  local ans
  while :; do
    read -rp "Restart radio now? [y/N]: " ans
    case "$ans" in
      [Yy]) return 0 ;;   # yes
      [Nn]|"") return 1 ;;# no (default)
      *) echo "Please answer y or n." ;;
    esac
  done
}

read_device_clock_epoch() {
  local raw_device_clock
  raw_device_clock="$(serial_cmd clock || true)"
  printf '%s\n' "$raw_device_clock" \
    | sed -En 's/.*([0-9]{1,2}):([0-9]{2}) *- *([0-9]{1,2})\/([0-9]{1,2})\/([0-9]{4}) *UTC.*/\5-\4-\3 \1:\2:00/p' \
    | xargs -r -I{} date -u -d "{}" +%s
}

prompt_powercycle_and_retry_time_sync() {
  local host_epoch="$1"
  local ans

  while :; do
    read -rp "Wait for the node to reconnect, then retry clock sync now? [Y/n]: " ans
    case "$ans" in
      [Yy]|"")
        host_epoch=$(date +%s)
        echo "Retrying clock sync. Sending: time $host_epoch"
        if ! serial_cmd "time $host_epoch" >/dev/null; then
          echo "Warning: device did not acknowledge the retried time sync command"
        fi
        return 0
        ;;
      [Nn])
        return 1
        ;;
      *)
        echo "Please answer y or n."
        ;;
    esac
  done
}

prompt_clock_reset_and_retry_time_sync() {
  local host_epoch="$1"
  local ans

  while :; do
    read -rp "Device clock is in the future. Run clkreboot now? [Y/n]: " ans
    case "$ans" in
      [Yy]|"")
        echo "Sending clock-reset reboot..."
        serial_cmd "clkreboot" >/dev/null || true
        if prompt_powercycle_and_retry_time_sync "$host_epoch"; then
          return 0
        fi
        return 1
        ;;
      [Nn])
        echo "Clock-reset reboot skipped."
        return 1
        ;;
      *)
        echo "Please answer y or n."
        ;;
    esac
  done
}


# Sync Time
choose_serial || true
if [[ -n "$DEVICE_NAME" ]]; then
  remember_setup_usb_identity || true
  refresh_detected_node_info || true
  print_detected_node_summary
  usb_logging_status=0
  offer_disable_usb_logging || usb_logging_status=$?
  if (( usb_logging_status == 2 )); then exit 0; fi
fi

force_time_sync

# Read clock from device
device_epoch="$(read_device_clock_epoch)"

if [[ -z "$device_epoch" && -n "$SETUP_USB_IDENTITY" ]]; then
  echo "The radio did not answer. USB connection recovery may help a stalled USB interface."
  if recover_setup_serial_connection; then
    refresh_detected_node_info || true
    print_detected_node_summary
    device_epoch="$(read_device_clock_epoch)"
  else
    reset_status=$?
    if (( reset_status == 2 )); then exit 1; fi
  fi
fi

# Current host UNIX time (seconds since epoch)
host_epoch=$(date +%s)

echo "device_epoch: $device_epoch"
echo "host_epoch  : $host_epoch"
echo "Host   time (Local): $(date -d "@$host_epoch" '+%Y-%m-%d %H:%M %Z')"

if [[ -n "${device_epoch:-}" ]]; then
  diff=$(( device_epoch - host_epoch ))
  adiff=${diff#-}
  echo "Device time (Local): $(date -d "@$device_epoch" '+%Y-%m-%d %H:%M %Z')"
else
  adiff=$((300 + 1))
  echo "Device time (Local): unavailable"
fi


# Verdict: only act if more than 5 minutes off (60 sec * 5)
if [ "$adiff" -gt 300 ]; then
  if [[ -n "${device_epoch:-}" && "$diff" -gt 300 ]]; then
    echo "Clock off by more than 5 minutes and device time is in the future."
    if prompt_clock_reset_and_retry_time_sync "$host_epoch"; then
      sleep 2
      host_epoch=$(date +%s)
      device_epoch="$(read_device_clock_epoch)"
      if [[ -n "${device_epoch:-}" ]]; then
        diff=$(( device_epoch - host_epoch ))
        adiff=${diff#-}
        echo "Device time after reset (Local): $(date -d "@$device_epoch" '+%Y-%m-%d %H:%M %Z')"
      fi
    fi
  elif [[ -n "${device_epoch:-}" ]]; then
    echo "Clock off by more than 5 minutes; syncing time now. Sending: time $host_epoch"
    if ! serial_cmd "time $host_epoch" >/dev/null; then
      echo "Warning: device did not acknowledge the time sync command"
    fi
  else
    echo "Device clock unreadable; syncing time now. Sending: time $host_epoch"
    if ! serial_cmd "time $host_epoch" >/dev/null; then
      echo "Warning: device did not acknowledge the time sync command"
    fi
  fi
  echo
else
  echo "Clock within 5 minutes"
fi

if [[ -n "${device_epoch:-}" ]]; then
	load_repeater_settings
	snapshot_radio_baseline
else
	echo "Serial Commands seem to be broken"
	if prompt_powercycle_and_retry_time_sync "$host_epoch"; then
		sleep 2
		device_epoch="$(read_device_clock_epoch)"
	fi
	if [[ -n "${device_epoch:-}" ]]; then
		refresh_detected_node_info || true
		print_detected_node_summary
		load_repeater_settings
		snapshot_radio_baseline
	else
		echo "Changes here may not work"
		set_empty_settings
	fi
fi

edit_repeater_settings_menu

if confirm_restart_radio; then
  echo "Restarting radio..."
  serial_cmd "reboot"
else
  echo "Radio reboot skipped."
fi

exit
