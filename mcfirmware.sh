#!/usr/bin/env bash
#
: <<'EOF'

# To run this file, copy this line below and run it.
cd ~ && wget -qO - https://raw.githubusercontent.com/mikecarper/meshfirmware/refs/heads/main/mcfirmware.sh | bash

#
EOF

# Strict errors.
# Trap errors and output file and line number.
set -euo pipefail

# Ensure we always restore on exit
cleanup() {
	local usb_autosuspend_end=""
	if [[ "${USB_AUTOSUSPEND_CHANGED:-0}" -eq 1 \
		&& -n "${USB_AUTOSUSPEND:-}" \
		&& -r /sys/module/usbcore/parameters/autosuspend ]]; then
		usb_autosuspend_end="$(cat /sys/module/usbcore/parameters/autosuspend 2>/dev/null || true)"
	fi
	if [[ -n "$usb_autosuspend_end" && "$usb_autosuspend_end" != "${USB_AUTOSUSPEND:-}" ]]; then
		echo "$USB_AUTOSUSPEND" | sudo tee /sys/module/usbcore/parameters/autosuspend >/dev/null
	fi
	if declare -F restore_port_after_bootloader_probe >/dev/null; then
		restore_port_after_bootloader_probe
	fi
	if declare -F restart_locked_services >/dev/null; then
		restart_locked_services
	fi
	if [[ -n "${FIRMWARE_ROOT:-}" && -d "$FIRMWARE_ROOT" ]]; then
		chmod -R a+rX "$FIRMWARE_ROOT" >/dev/null 2>&1 || true
	fi
	if [[ -n "${SUDO_KEEPALIVE_PID:-}" ]]; then
		kill "$SUDO_KEEPALIVE_PID" >/dev/null 2>&1 || true
	fi
}
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

# Global argument variables.
DEBUG_JQ="0"
APT_UPDATED=0

# Opt-in constrained mode for hosts where the current shell cannot reuse a
# sudo credential (for example, tty-scoped sudo tickets). This never weakens
# the identity-safe DFU checks: it only skips proactive startup privilege
# setup. Any later operation that actually needs privilege must refuse.
MCFIRMWARE_NO_SUDO="${MCFIRMWARE_NO_SUDO:-0}"
case "$MCFIRMWARE_NO_SUDO" in
	0|1) ;;
	*)
		echo "MCFIRMWARE_NO_SUDO must be 0 or 1." >&2
		exit 1
		;;
esac

no_sudo_mode() {
	[[ "${MCFIRMWARE_NO_SUDO:-0}" -eq 1 ]]
}

# Global variable to track the spinner index.
spinner_index=0
# Array holding the spinner characters.
spinner_chars=("-" "\\" "|" "/")
CACHE_TIMEOUT_SECONDS=$((6 * 3600)) # 6 hours
CURL_FETCH_MAX_TIME=10
CURL_FETCH_RETRIES=3
CURL_FETCH_RETRY_DELAY=1
MOUNT_FOLDER="/mnt/meshDeviceSD"
USB_AUTOSUSPEND=$(cat /sys/module/usbcore/parameters/autosuspend)
USB_AUTOSUSPEND_CHANGED=0
BASE_USER="${SUDO_USER:-$USER}"
SUDO_KEEPALIVE_PID=""
BOOTLOADER_PROBE_PORT=""
BOOTLOADER_PROBE_ACTIVE=0
NRF52_BOARD_GUARD_PASSED=0

restore_port_after_bootloader_probe() {
	local port="${BOOTLOADER_PROBE_PORT:-}"
	local hard_reset="${HARDRESET:-hard-reset}"
	local no_reset="${NORESET:-no-reset}"
	local read_mac="${READMAC:-read-mac}"
	local watchdog_reset="${WATCHDOGRESET:-watchdog-reset}"

	[[ "${BOOTLOADER_PROBE_ACTIVE:-0}" -eq 1 ]] || return 0
	[[ -n "$port" ]] || return 0

	echo "Attempting to return ${port} to normal runtime mode..." >/dev/tty
	if ! invoke_esptool_timeout 8s --port "$port" --before "$no_reset" \
		--after "$hard_reset" "$read_mac" >/dev/null 2>&1; then
		invoke_esptool_timeout 8s --port "$port" --before "$no_reset" \
			--after "$watchdog_reset" run >/dev/null 2>&1 || true
	fi
	BOOTLOADER_PROBE_ACTIVE=0
	BOOTLOADER_PROBE_PORT=""
}

restart_locked_services() {
	local -a locked_services=()

	[[ -n "${LOCKEDSERVICE:-}" ]] || return 0
	[[ "${LOCKEDSERVICE:-}" != "None" ]] || return 0

	read -r -a locked_services <<< "$LOCKEDSERVICE"
	((${#locked_services[@]})) || return 0
	if no_sudo_mode; then
		echo "No-sudo mode cannot restart locked service(s): $LOCKEDSERVICE" >&2
		return 1
	fi

	echo "Starting service $LOCKEDSERVICE..."
	sudo systemctl start "${locked_services[@]}" || true
	LOCKEDSERVICE=""
}

ensure_sudo_session() {
	if no_sudo_mode; then
		echo "No-sudo mode refuses an operation that requires elevated access." >&2
		return 1
	fi
	if sudo -n true 2>/dev/null; then
		return 0
	fi

	echo "sudo access is required for package, USB, and serial-port operations."
	sudo -v
}

start_sudo_keepalive() {
	if no_sudo_mode; then
		echo "No-sudo mode cannot start a sudo keepalive." >&2
		return 1
	fi
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

initialize_privilege_mode() {
	if no_sudo_mode; then
		echo "MCFIRMWARE_NO_SUDO=1: leaving groups and USB autosuspend unchanged; privileged fallbacks will refuse."
		return 0
	fi
	ensure_sudo_session
	start_sudo_keepalive
	ensure_serial_group_access
}

configure_usb_autosuspend() {
	if no_sudo_mode || [[ "$USB_AUTOSUSPEND" -eq -1 ]]; then
		return 0
	fi
	# Only disable (-1) if it isn't already.
	echo "sudo needed to disable USB autosuspend and keep all USB ports active."
	USB_AUTOSUSPEND_CHANGED=1
	echo -1 | sudo tee /sys/module/usbcore/parameters/autosuspend >/dev/null
}

initialize_privilege_mode

if [[ -n "${SUDO_USER:-}" ]]; then
	umask 022
fi

configure_usb_autosuspend

MIN_BYTES=$((50 * 1024))   # 50 KB in bytes
REPO_OWNER="meshcore-dev"
REPO_NAME="MeshCore"
RELEASE_INFO1_URL="https://flasher.meshcore.io/config.json"
RELEASE_INFO2_URL="https://flasher.meshcore.io/releases"
RELEASE_INFO1_FALLBACK_URL="https://apps.meshamerica.com/proxy/flasher/config.json"
RELEASE_INFO2_FALLBACK_URL="https://apps.meshamerica.com/proxy/flasher/releases"
KEYMIND_GITHUB_TREE_URL="https://api.github.com/repos/mikecarper/MeshCore/git/trees/keymindCascade?recursive=1"
KEYMIND_RAW_BASE_URL="https://raw.githubusercontent.com/mikecarper/MeshCore/keymindCascade"
KEYMIND_CASCADE_FALLBACK_URL="${KEYMIND_RAW_BASE_URL}/mesh-america/keymind-cascade-v1.16.0-provider.json"
KEYMIND_CASCADE_LOGGING_FALLBACK_URL="${KEYMIND_RAW_BASE_URL}/mesh-america/keymind-cascade-logging-v1.16.0-provider.json"
VENDORLIST="elecrow|heltec|lilygo|seeed|seed|studio|rak|wireless|wisblock|wismesh|raspberry|pi|pico|waveshare|promicro|uniteng|sensecap|wio|xiao"
RADIOLIST="sx1262|sx126x|sx1276|sx127x"
NORESET="no-reset"
USBRESET="usb-reset"
READMAC="read-mac"
READFLASH="read-flash"
WRITEFLASH="write-flash"
ERASEFLASH="erase-flash"
HARDRESET="hard-reset"
WATCHDOGRESET="watchdog-reset"
LOCKEDSERVICE=""
CHOSEN_FILE=""
BAUD="${3:-115200}"
DEFAULT_BAUDS=(57600 115200 38400 9600 19200 2400)
SERIAL_BAUD_CACHE=57600
SERIAL_IDLE_TIMEOUT=2.5 
SERIAL_TOTAL_TIMEOUT=7.5


# Settings for the repo
        GITHUB_API_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases"
# Set Folders
         FIRMWARE_ROOT="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}"
          DOWNLOAD_DIR="${FIRMWARE_ROOT}/downloads"
# Vars to get passed around and cached as files.
           CONFIG_FILE="${FIRMWARE_ROOT}/config.json"
   DEFAULT_CONFIG_FILE="$CONFIG_FILE"
    CONFIG_SOURCE_FILE="${FIRMWARE_ROOT}/00config_source.txt"
         RELEASES_FILE="${FIRMWARE_ROOT}/releases.json"
  SELECTED_DEVICE_FILE="${FIRMWARE_ROOT}/01device.txt"
     ARCHITECTURE_FILE="${FIRMWARE_ROOT}/02architecture.txt"
        ERASE_URL_FILE="${FIRMWARE_ROOT}/03erase.txt"
    SELECTED_ROLE_FILE="${FIRMWARE_ROOT}/04role.txt"
   SELECTED_TITLE_FILE="${FIRMWARE_ROOT}/04title.txt"
SELECTED_SUBTITLE_FILE="${FIRMWARE_ROOT}/04subtitle.txt"
 SELECTED_VERSION_FILE="${FIRMWARE_ROOT}/05version.txt"
    SELECTED_TYPE_FILE="${FIRMWARE_ROOT}/06type.txt"
     SELECTED_URL_FILE="${FIRMWARE_ROOT}/07selected_url.txt"
  DOWNLOADED_FILE_FILE="${FIRMWARE_ROOT}/08downloaded_file.txt"
      DEVICE_PORT_FILE="${FIRMWARE_ROOT}/09device_port_file.txt"
 DEVICE_PORT_NAME_FILE="${FIRMWARE_ROOT}/10device_port_name_file.txt"
AUTODETECT_DEVICE_FILE="${FIRMWARE_ROOT}/11autodetect_device_file.txt"
          ESPTOOL_FILE="${FIRMWARE_ROOT}/12esptool_file.txt"
       ERASE_FILE_FILE="${FIRMWARE_ROOT}/13erase_file.txt"




spinner() {
	# Print the spinner character (using \r to overwrite the same line)
	printf "\r%s" "${spinner_chars[spinner_index]}" >/dev/tty
	# Update the index, wrapping around to 0 when reaching the end of the array.
	spinner_index=$(((spinner_index + 1) % ${#spinner_chars[@]}))
}

classify_bin() {
	local f="$1"

	ensure_command xxd vim-common

	hex() {
		xxd -p -l "$2" -s "$1" "$f" 2>/dev/null | tr -d '\n'
	}

	byte_at() {
		hex "$1" 1
	}

	csv_escape() {
		local s="${1:-}"
		s=${s//\"/\"\"}
		printf '"%s"' "$s"
	}

	trim() {
		local s="${1:-}"
		s="${s#"${s%%[![:space:]]*}"}"
		s="${s%"${s##*[![:space:]]}"}"
		printf '%s' "$s"
	}

	looks_like_esp_image_at() {
		local off="$1"
		local magic segs mode

		magic=$(byte_at "$off")
		[[ "$magic" == "e9" ]] || return 1

		segs=$(byte_at $((off + 1)))
		mode=$(byte_at $((off + 2)))

		[[ -n "$segs" && -n "$mode" ]] || return 1

		local segs_dec=$((16#$segs))
		local mode_dec=$((16#$mode))

		(( segs_dec >= 1 && segs_dec <= 16 )) || return 1
		(( mode_dec >= 0 && mode_dec <= 3 )) || return 1

		return 0
	}

	parse_esptool_output() {
		local esptool_out="$1"

		detected_image_type=$(printf '%s\n' "$esptool_out" | sed -n 's/^Detected image type:[[:space:]]*//p' | head -n1)
		chip_id=$(printf '%s\n' "$esptool_out" | sed -n 's/^Chip ID:[[:space:]]*//p' | head -n1)
		project_name=$(printf '%s\n' "$esptool_out" | sed -n 's/^Project name:[[:space:]]*//p' | head -n1)
		app_version=$(printf '%s\n' "$esptool_out" | sed -n 's/^App version:[[:space:]]*//p' | head -n1)
		compile_time=$(printf '%s\n' "$esptool_out" | sed -n 's/^Compile time:[[:space:]]*//p' | head -n1)
		esp_idf=$(printf '%s\n' "$esptool_out" | sed -n 's/^ESP-IDF:[[:space:]]*//p' | head -n1)
		validation_hash=$(printf '%s\n' "$esptool_out" | sed -n 's/^Validation hash:[[:space:]]*//p' | sed 's/[[:space:]]*(valid).*//' | head -n1)

		detected_image_type=$(trim "$detected_image_type")
		chip_id=$(trim "$chip_id")
		project_name=$(trim "$project_name")
		app_version=$(trim "$app_version")
		compile_time=$(trim "$compile_time")
		esp_idf=$(trim "$esp_idf")
		validation_hash=$(trim "$validation_hash")
	}

	run_esptool_on_file() {
		local target="$1"
		pipx run esptool image_info "$target" 2>/dev/null || true
	}

	run_esptool_on_offset_image() {
		local off="$1"
		local tmp

		tmp=$(mktemp)
		dd if="$f" of="$tmp" bs=1 skip="$off" status=none 2>/dev/null || true
		pipx run esptool image_info "$tmp" 2>/dev/null || true
		rm -f "$tmp"
	}

	local b0 b1000 b8000 b10000 result
	local img0=0 img1000=0 img10000=0 img150000=0
	local size_bytes
	local esptool_out=""
	local detected_image_type=""
	local chip_id=""
	local project_name=""
	local app_version=""
	local compile_time=""
	local esp_idf=""
	local validation_hash=""

	b0=$(hex 0x0 1)
	b1000=$(hex 0x1000 1)
	b8000=$(hex 0x8000 2)
	b10000=$(hex 0x10000 1)
	size_bytes=$(stat -c '%s' "$f" 2>/dev/null || wc -c < "$f")

	looks_like_esp_image_at 0x0     && img0=1
	looks_like_esp_image_at 0x1000  && img1000=1
	looks_like_esp_image_at 0x10000 && img10000=1
	looks_like_esp_image_at 0x150000 && img150000=1

	if [[ "$b8000" == "aa50" && ( $img10000 -eq 1 || $img150000 -eq 1 ) ]]; then
		result="HAS_PARTITION_TABLE_AND_APP"
	elif [[ $img0 -eq 1 && "$b8000" != "aa50" && ( $img10000 -eq 1 || $img150000 -eq 1 ) ]]; then
		result="MULTI_IMAGE_NO_PARTITION_TABLE"
	elif [[ $img0 -eq 1 && "$b8000" != "aa50" && $img10000 -eq 0 ]]; then
		result="LIKELY_SINGLE"
	elif [[ "$b8000" == "ffff" && $img0 -eq 0 && $img1000 -eq 0 && $img10000 -eq 0 && $img150000 -eq 0 ]]; then
		result="DATA_IMAGE"
	elif [[ $img0 -eq 0 && $img1000 -eq 0 && "$b8000" != "aa50" && $img10000 -eq 0 && $img150000 -eq 0 ]]; then
		result="NON_ESP_OR_UNKNOWN"
	else
		result="AMBIGUOUS"
	fi

	if command -v pipx >/dev/null 2>&1; then
		case "$result" in
			LIKELY_SINGLE)
				if [[ $img0 -eq 1 ]]; then
					esptool_out=$(run_esptool_on_file "$f")
				fi
				;;
			MULTI_IMAGE_NO_PARTITION_TABLE)
				if [[ $img0 -eq 1 ]]; then
					esptool_out=$(run_esptool_on_file "$f")
				fi
				;;
			HAS_PARTITION_TABLE_AND_APP)
				if [[ $img10000 -eq 1 ]]; then
					esptool_out=$(run_esptool_on_offset_image 0x10000)
				elif [[ $img150000 -eq 1 ]]; then
					esptool_out=$(run_esptool_on_offset_image 0x150000)
				fi
				;;
		esac

		if [[ -n "$esptool_out" ]]; then
			parse_esptool_output "$esptool_out"
		fi
	fi

	csv_escape "$f"; printf ','
	csv_escape "${size_bytes:-}"; printf ','
	csv_escape "${b0:-}"; printf ','
	csv_escape "${b1000:-}"; printf ','
	csv_escape "${b8000:-}"; printf ','
	csv_escape "${b10000:-}"; printf ','
	csv_escape "$img0"; printf ','
	csv_escape "$img1000"; printf ','
	csv_escape "$img10000"; printf ','
	csv_escape "$result"; printf ','
	csv_escape "$detected_image_type"; printf ','
	csv_escape "$chip_id"; printf ','
	csv_escape "$project_name"; printf ','
	csv_escape "$app_version"; printf ','
	csv_escape "$compile_time"; printf ','
	csv_escape "$esp_idf"; printf ','
	csv_escape "$validation_hash"
	printf '\n'
}

esp_filename_layout_hint() {
	local file="$1"
	local name=""

	name="${file##*/}"
	shopt -s nocasematch
	case "$name" in
		*merged.bin|*cleanInstall.bin|*factory.bin)
			echo "merged"
			;;
		*.bin)
			echo "app-only"
			;;
		*)
			echo "unknown"
			;;
	esac
	shopt -u nocasematch
}

esp_firmware_layout() {
	local file="$1" classification="" result=""

	[[ -f "$file" ]] || {
		echo "unknown"
		return 1
	}

	classification="$(classify_bin "$file")"
	result=$(printf '%s\n' "$classification" | cut -d',' -f10 | sed 's/^"//; s/"$//')

	case "$result" in
		HAS_PARTITION_TABLE_AND_APP|MULTI_IMAGE_NO_PARTITION_TABLE)
			echo "merged"
			;;
		LIKELY_SINGLE)
			echo "app-only"
			;;
		*)
			echo "unknown"
			;;
	esac
}

esp32_image_flash_mode() {
	local file=$1 mode_byte=""

	[[ -f "$file" ]] || return 1
	mode_byte="$(od -An -tu1 -j2 -N1 -- "$file" 2>/dev/null | tr -d '[:space:]')"
	case "$mode_byte" in
		0) printf '%s\n' qio ;;
		1) printf '%s\n' qout ;;
		2) printf '%s\n' dio ;;
		3) printf '%s\n' dout ;;
		*) return 1 ;;
	esac
}

esp32_validate_image_for_device() {
	local device=$1 file=$2 layout=$3 flash_mode=""

	case "${device,,}" in
		*station*g2*) ;;
		*) return 0 ;;
	esac

	# Both a merged image's first-stage bootloader and an app-only image carry
	# the SPI flash mode in byte 2 of their ESP image header. Report the mode for
	# Station G2 images, but leave compatibility decisions to the user instead of
	# refusing an otherwise valid image.
	[[ "$layout" == "merged" || "$layout" == "app-only" ]] || return 0
	flash_mode="$(esp32_image_flash_mode "$file" 2>/dev/null || true)"
	if [[ "$flash_mode" == "dio" || "$flash_mode" == "qio" ]]; then
		echo "Station G2 image flash mode: ${flash_mode^^}."
	else
		echo "Warning: Station G2 image reports ${flash_mode:-an unreadable flash mode}; continuing at user request." >&2
	fi
	return 0
}

describe_flash_action() {
	local action="${1:-}"

	case "$action" in
		flash-wipe)   printf 'new install (erase + install)' ;;
		flash-update) printf 'update' ;;
		*)            printf 'unknown' ;;
	esac
}

expand_home_path() {
	local path="${1:-}" prefix=""

	if [[ "$path" == file://* ]]; then
		prefix="file://"
		path="${path#file://}"
	fi

	case "$path" in
		\~)
			path="$HOME"
			;;
		\~/*)
			path="${HOME}/${path:2}"
			;;
	esac

	printf '%s%s' "$prefix" "$path"
}

detect_custom_firmware_type() {
	local selection="${1:-}" arch_lc="${2,,}" check="" name_lc=""

	[[ -n "$selection" ]] || return 0

	check="$selection"
	[[ "$check" == file:///* ]] && check="${check#file://}"
	check="${check%%[\?#]*}"
	name_lc="${check##*/}"
	name_lc="${name_lc,,}"

	if [[ "$arch_lc" == esp32* ]]; then
		case "$name_lc" in
			*merged.bin|*cleaninstall.bin|*factory.bin|*freshinstall*.bin|*install*.bin)
				printf '%s' "flash-wipe"
				return 0
				;;
			*update.bin|*upgrade.bin|*ota.bin)
				printf '%s' "flash-update"
				return 0
				;;
			*.bin)
				case "$(esp_filename_layout_hint "$name_lc" 2>/dev/null || true)" in
					merged)
						printf '%s' "flash-wipe"
						return 0
						;;
					app-only)
						printf '%s' "flash-update"
						return 0
						;;
				esac
				;;
		esac
	else
		case "$name_lc" in
			*.uf2|*.hex)
				printf '%s' "flash-wipe"
				return 0
				;;
			*-ota.zip|*update*.zip|*upgrade*.zip|*.zip)
				printf '%s' "flash-update"
				return 0
				;;
		esac
	fi
}

apply_custom_firmware_selection() {
	local selection="${1:-}" detected_type=""

	selection="$(expand_home_path "$selection")"
	CHOSEN_FILE="$selection"
	VERSION="custom"
	detected_type="$(detect_custom_firmware_type "$selection" "$ARCHITECTURE")"
	if [[ -n "$detected_type" ]]; then
		TYPE="$detected_type"
		echo "Auto-detected custom firmware as: $(describe_flash_action "$TYPE")"
	else
		echo "Could not determine install mode from the custom filename; the flash step will inspect it again."
	fi
}

latest_custom_firmware_file() {
	local required_ext="${1:-}" custom_dir latest

	custom_dir="${DOWNLOAD_DIR}/custom"
	[[ -d "$custom_dir" ]] || return 1

	if [[ -n "$required_ext" ]]; then
		latest="$(
			find "$custom_dir" -maxdepth 1 -type f -iname "*${required_ext}" -printf '%T@\t%p\n' 2>/dev/null \
				| sort -nr \
				| sed -n $'1{s/^[^\t]*\t//;p;}' \
				|| true
		)"
	else
		latest="$(
			find "$custom_dir" -maxdepth 1 -type f -printf '%T@\t%p\n' 2>/dev/null \
				| sort -nr \
				| sed -n $'1{s/^[^\t]*\t//;p;}' \
				|| true
		)"
	fi

	[[ -n "$latest" && -f "$latest" ]] || return 1
	printf '%s\n' "$latest"
}

format_human_age() {
	local age_seconds="${1:-0}" rounded_minutes days hours minutes
	local day_suffix="s" hour_suffix="s" minute_suffix="s"

	[[ "$age_seconds" =~ ^-?[0-9]+$ ]] || return 1
	(( age_seconds < 0 )) && age_seconds=0

	# Round to the nearest minute, with 30 seconds rounding up.
	rounded_minutes=$(( (age_seconds + 30) / 60 ))
	days=$(( rounded_minutes / 1440 ))
	hours=$(( (rounded_minutes % 1440) / 60 ))
	minutes=$(( rounded_minutes % 60 ))

	[[ "$days" -eq 1 ]] && day_suffix=""
	[[ "$hours" -eq 1 ]] && hour_suffix=""
	[[ "$minutes" -eq 1 ]] && minute_suffix=""

	if (( days > 0 )); then
		printf '%d day%s, %d hour%s, %d minute%s old' \
			"$days" "$day_suffix" "$hours" "$hour_suffix" "$minutes" "$minute_suffix"
	elif (( hours > 0 )); then
		printf '%d hour%s, %d minute%s old' \
			"$hours" "$hour_suffix" "$minutes" "$minute_suffix"
	else
		printf '%d minute%s old' "$minutes" "$minute_suffix"
	fi
}

custom_firmware_file_age() {
	local firmware_file="${1:-}" now modified

	[[ -f "$firmware_file" ]] || return 1
	now="$(date +%s)"
	modified="$(stat -c %Y -- "$firmware_file")"
	format_human_age "$(( now - modified ))"
}

print_latest_custom_firmware_option() {
	local required_ext="${1:-}" latest age age_label=""

	latest="$(latest_custom_firmware_file "$required_ext" || true)"
	if [[ -n "$latest" ]]; then
		age="$(custom_firmware_file_age "$latest" || true)"
		[[ -n "$age" ]] && age_label=" ($age)"
		echo "Custom folder: ${DOWNLOAD_DIR}/custom"
		echo "  latest) $(basename -- "$latest")${age_label}"
		echo "          $latest"
	else
		echo "Custom folder: ${DOWNLOAD_DIR}/custom"
		echo "  No custom firmware files ending with ${required_ext} found."
	fi
}

show_help() {
	echo "Usage: $(basename "$0") [OPTIONS]"
	echo ""
	echo "Options:"
	echo "  --version VERSION   Specify the version to use."
	echo "  --install           Set the operation to 'install'."
	echo "  --update            Set the operation to 'update'."
	echo "  --run               Automatically run the update script without prompting."
	echo "  -h, --help          Display this help message and exit."
	exit 0
}

# Parse command-line arguments.
parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		-h | --help)
			show_help
			;;
		*)
			echo "Unknown option: $1"
			show_help
			;;
		esac
	done
}

# Check for an active internet connection.
check_internet() {
	local domain
	domain=$(echo "$GITHUB_API_URL" | sed -E 's|https?://([^/]+)/.*|\1|')
	if ping -c1 -W2 "$domain" >/dev/null 2>&1; then
		return 0
	else
		return 1
	fi
}

install_packages() {
	if no_sudo_mode; then
		echo "No-sudo mode cannot install missing package(s): $*" >&2
		return 1
	fi
    if (( ! APT_UPDATED )); then
        sudo apt-get update || return 1
        APT_UPDATED=1
    fi

	sudo apt-get -y install "$@"
}

ensure_command() {
	local command_name=$1
	shift || true

	if command -v "$command_name" >/dev/null 2>&1; then
		return 0
	fi
	if no_sudo_mode; then
		echo "Required command '$command_name' is missing; no-sudo mode refuses package installation." >&2
		return 1
	fi

	echo "Installing ${command_name}" >&2
	if [ "$#" -gt 0 ]; then
		install_packages "$@"
	else
		install_packages "$command_name"
	fi
}

print_command() {
	local arg

	printf '  '
	for arg in "$@"; do
		printf '%q ' "$arg"
	done
	printf '\n'
}

choose_flash_execution_mode() {
	local target=$1
	local choice

	while true; do
		echo "Choose execution mode for ${target}:" >/dev/tty
		echo "  1) run commands" >/dev/tty
		echo "  2) echo commands only" >/dev/tty
		read -r -p "Selection [1/2, Enter=1]: " choice </dev/tty
		choice="${choice:-1}"
		case "$choice" in
			1|run|Run|RUN)
				printf '%s\n' "run"
				return 0
				;;
			2|echo|Echo|ECHO|dry-run|dryrun)
				printf '%s\n' "echo"
				return 0
				;;
			*)
				echo "Please enter 1 or 2." >/dev/tty
				;;
		esac
	done
}

print_nrfutil_dfu_command_live_port() {
	local package_file=$1
	local port=$2
	shift 2 || true

	print_command pipx run adafruit-nrfutil dfu serial --package "$package_file" -p "$port" -b 115200 "$@"
}

nrf52_serial_port_access() {
	local port=$1

	if [[ -r "$port" && -w "$port" ]]; then
		return 0
	fi

	echo "Serial port $port requires elevated access."
	if [[ -e "$port" ]]; then
		echo "Current permissions: $(ls -l "$port")"
	fi
	if no_sudo_mode; then
		echo "No-sudo mode cannot change serial-port permissions; grant read/write access first." >&2
		return 1
	fi
	echo "Prompting for sudo so flashing can continue..."
	ensure_sudo_session
	sudo chmod a+rw "$port"
}

run_nrfutil_dfu_serial_checked() {
	local package_file=$1
	local port=$2
	shift 2 || true
	local output_file status
	local -a command=(
		pipx run adafruit-nrfutil dfu serial
		--package "$package_file"
	)

	command+=(-p "$port" -b 115200 "$@")

	nrf52_serial_port_access "$port" || return 1
	output_file="$(mktemp)"

	# adafruit-nrfutil 0.5.x catches DFU exceptions and returns process status 0
	# after printing "Failed to upgrade target". Preserve its output, but also
	# require the positive completion marker before reporting success ourselves.
	set +e
	"${command[@]}" 2>&1 | tee "$output_file"
	status=${PIPESTATUS[0]}
	set -e

	if [[ "$status" -eq 0 ]] \
		&& ! grep -Fq "Failed to upgrade target." "$output_file" \
		&& grep -Fq "Device programmed." "$output_file"; then
		rm -f "$output_file"
		return 0
	fi

	if [[ "$status" -eq 0 ]]; then
		echo "adafruit-nrfutil did not confirm that the device was programmed." >&2
	else
		echo "adafruit-nrfutil exited with status $status." >&2
	fi
	rm -f "$output_file"
	return 1
}

run_nrfutil_dfu_serial_live_port() {
	local package_file=$1
	local port=$2
	shift 2 || true

	run_nrfutil_dfu_serial_checked "$package_file" "$port" "$@"
}

udev_device_property() {
	local port=$1
	local property=$2

	command -v udevadm >/dev/null 2>&1 || return 0
	udevadm info --query=property --name="$port" 2>/dev/null \
		| sed -n "s/^${property}=//p" \
		| head -n1
}

normalize_usb_serial_identity() {
	local serial="${1:-}"
	printf '%s' "${serial,,}" | tr -cd '[:alnum:]'
}

nrf52_usb_path_stem() {
	local path="${1:-}"
	local prefix usb_path interface_path interface_component

	# ID_PATH also contains a PCI function such as :00.0. Only remove the final
	# USB interface component after the -usb- marker. A CDC tty may end at :1.0,
	# while the same composite device's mass-storage path continues with -scsi.
	if [[ "$path" != *-usb-* ]]; then
		printf '%s' "$path"
		return 0
	fi

	prefix="${path%%-usb-*}"
	usb_path="${path#*-usb-}"
	interface_path="${usb_path%%-*}"
	interface_component="${interface_path##*:}"
	if [[ "$interface_path" == *:* \
		&& "$interface_component" =~ ^[0-9]+\.[0-9]+$ ]]; then
		printf '%s-usb-%s' "$prefix" "${interface_path%:*}"
	else
		printf '%s' "$path"
	fi
}

serial_ports_share_usb_device() {
	local first_port=$1
	local second_port=$2
	local first_path second_path first_serial second_serial

	first_path="$(nrf52_usb_path_stem "$(udev_device_property "$first_port" ID_PATH)")"
	second_path="$(nrf52_usb_path_stem "$(udev_device_property "$second_port" ID_PATH)")"
	first_serial="$(udev_device_property "$first_port" ID_SERIAL_SHORT)"
	second_serial="$(udev_device_property "$second_port" ID_SERIAL_SHORT)"
	first_serial="$(normalize_usb_serial_identity "$first_serial")"
	second_serial="$(normalize_usb_serial_identity "$second_serial")"
	if [[ -n "$first_path" && -n "$second_path" ]]; then
		[[ "$first_path" == "$second_path" ]] || return 1
		if [[ -n "$first_serial" && -n "$second_serial" \
			&& "$first_serial" != "$second_serial" ]]; then
			return 1
		fi
		return 0
	fi

	[[ -n "$first_serial" && "$first_serial" == "$second_serial" ]]
}

serial_by_id_link_for_port() {
	local port=$1
	local link resolved match=""
	local by_id_dir="${NRF52_SERIAL_BY_ID_DIR:-/dev/serial/by-id}"

	shopt -s nullglob
	for link in "${by_id_dir}"/*; do
		resolved="$(readlink -f "$link" 2>/dev/null || true)"
		[[ "$resolved" == "$port" ]] || continue
		if [[ -n "$match" && "$match" != "$link" ]]; then
			shopt -u nullglob
			return 2
		fi
		match="$link"
	done
	shopt -u nullglob

	[[ -n "$match" ]] || return 1
	printf '%s\n' "$match"
}

serial_port_has_secondary_cdc() {
	local primary_port=$1
	local link candidate candidate_interface
	local by_id_dir="${NRF52_SERIAL_BY_ID_DIR:-/dev/serial/by-id}"

	shopt -s nullglob
	for link in "${by_id_dir}"/*; do
		candidate="$(readlink -f "$link" 2>/dev/null || true)"
		[[ -n "$candidate" && -e "$candidate" && "$candidate" != "$primary_port" ]] || continue
		candidate_interface="$(udev_device_property "$candidate" ID_USB_INTERFACE_NUM)"
		[[ -n "$candidate_interface" && ! "$candidate_interface" =~ ^0+$ ]] || continue
		if serial_ports_share_usb_device "$primary_port" "$candidate"; then
			shopt -u nullglob
			return 0
		fi
	done
	shopt -u nullglob
	return 1
}

esp32_port_uses_native_usb() {
	local port=$1
	local vendor_id

	vendor_id="$(udev_device_property "$port" ID_VENDOR_ID)"
	if [[ "${vendor_id,,}" == "303a" ]]; then
		return 0
	fi
	# Full Companion may use a board-specific VID/PID, but its second CDC
	# sibling still distinguishes native USB from an external UART bridge.
	serial_port_has_secondary_cdc "$port"
}

esp32_port_is_rom_usb_jtag() {
	local port=$1
	local vendor_id model_id model

	vendor_id="$(udev_device_property "$port" ID_VENDOR_ID)"
	model_id="$(udev_device_property "$port" ID_MODEL_ID)"
	model="$(udev_device_property "$port" ID_MODEL)"
	[[ "${vendor_id,,}" == "303a" && "${model_id,,}" == "1001" \
		&& "${model,,}" == *usb_jtag_serial_debug_unit* ]]
}

save_selected_serial_port() {
	local port=$1
	local by_id_link=""

	DEVICE_PORT="$port"
	printf '%s\n' "$port" > "$DEVICE_PORT_FILE"
	by_id_link="$(serial_by_id_link_for_port "$port" 2>/dev/null || true)"
	if [[ -n "$by_id_link" ]]; then
		basename -- "$by_id_link" > "$DEVICE_PORT_NAME_FILE"
	else
		: > "$DEVICE_PORT_NAME_FILE"
	fi
}

preferred_flash_serial_link() {
	local selected_link=$1
	local selected_port selected_interface candidate candidate_port candidate_interface
	local preferred_link="" preferred_port=""
	local by_id_dir="${NRF52_SERIAL_BY_ID_DIR:-/dev/serial/by-id}"

	selected_port="$(readlink -f "$selected_link" 2>/dev/null || true)"
	if [[ -z "$selected_port" || ! -e "$selected_port" ]]; then
		printf '%s\n' "$selected_link"
		return 0
	fi

	selected_interface="$(udev_device_property "$selected_port" ID_USB_INTERFACE_NUM)"
	if [[ -z "$selected_interface" || "$selected_interface" =~ ^0+$ ]]; then
		printf '%s\n' "$selected_link"
		return 0
	fi

	# A Full Companion can expose CDC interface 00 for Companion/DFU and a
	# second CDC interface for output-only logging. Only the first CDC instance
	# responds to the 1200-baud DFU touch. Prefer its by-id link when both belong
	# to the same physical USB device, but leave single nonzero interfaces alone.
	shopt -s nullglob
	for candidate in "${by_id_dir}"/*; do
		candidate_port="$(readlink -f "$candidate" 2>/dev/null || true)"
		[[ -n "$candidate_port" && -e "$candidate_port" ]] || continue
		candidate_interface="$(udev_device_property "$candidate_port" ID_USB_INTERFACE_NUM)"
		[[ "$candidate_interface" =~ ^0+$ ]] || continue
		serial_ports_share_usb_device "$selected_port" "$candidate_port" || continue

		if [[ -n "$preferred_port" && "$candidate_port" != "$preferred_port" ]]; then
			# A cloned/ambiguous USB identity must not silently redirect flashing.
			shopt -u nullglob
			printf '%s\n' "$selected_link"
			return 0
		fi
		preferred_link="$candidate"
		preferred_port="$candidate_port"
	done
	shopt -u nullglob

	printf '%s\n' "${preferred_link:-$selected_link}"
}

preferred_flash_serial_port() {
	local selected_port=$1
	local link preferred_link preferred_port
	local by_id_dir="${NRF52_SERIAL_BY_ID_DIR:-/dev/serial/by-id}"

	shopt -s nullglob
	for link in "${by_id_dir}"/*; do
		if [[ "$(readlink -f "$link" 2>/dev/null || true)" == "$selected_port" ]]; then
			preferred_link="$(preferred_flash_serial_link "$link")"
			preferred_port="$(readlink -f "$preferred_link" 2>/dev/null || true)"
			shopt -u nullglob
			printf '%s\n' "${preferred_port:-$selected_port}"
			return 0
		fi
	done
	shopt -u nullglob

	printf '%s\n' "$selected_port"
}

nrf52_port_instance() {
	local port=$1
	[[ -e "$port" ]] || return 0
	stat -Lc '%d:%i' "$port" 2>/dev/null || true
}

nrf52_selected_by_id_path() {
	local selected_name="" selected_path=""
	local by_id_dir="${NRF52_SERIAL_BY_ID_DIR:-/dev/serial/by-id}"

	if [[ -s "$DEVICE_PORT_NAME_FILE" ]]; then
		selected_name="$(basename -- "$(<"$DEVICE_PORT_NAME_FILE")")"
		selected_path="${by_id_dir}/${selected_name}"
		# Return the saved identity even if it is currently disconnected. The
		# caller must reject a dangling link instead of falling back to whatever
		# unrelated device may now occupy the old ttyACM number. If this is a
		# secondary CDC port, prefer the matching interface-00 sibling.
		preferred_flash_serial_link "$selected_path"
		return 0
	fi

	local link
	shopt -s nullglob
	for link in "${by_id_dir}"/*; do
		if [[ "$(readlink -f "$link" 2>/dev/null || true)" == "$DEVICE_PORT" ]]; then
			preferred_flash_serial_link "$link"
			break
		fi
	done
	shopt -u nullglob
}

nrf52_uf2_mount_matches_identity() {
	local expected_serial=$1
	local expected_path_stem=$2
	local source target info_file disk_serial disk_path_stem

	command -v findmnt >/dev/null 2>&1 || return 1
	while read -r source target; do
		[[ -n "$source" && -n "$target" ]] || continue
		info_file="${target%/}/INFO_UF2.TXT"
		[[ -r "$info_file" && -r "${target%/}/CURRENT.UF2" ]] || continue
		grep -Eiq 'UF2[[:space:]]+Bootloader' "$info_file" 2>/dev/null || continue
		[[ -e "$source" ]] || continue

		disk_serial="$(udev_device_property "$source" ID_SERIAL_SHORT)"
		disk_path_stem="$(nrf52_usb_path_stem "$(udev_device_property "$source" ID_PATH)")"
		if [[ -n "$expected_serial" && "$disk_serial" == "$expected_serial" ]]; then
			return 0
		fi
		if [[ -n "$expected_path_stem" && "$disk_path_stem" == "$expected_path_stem" ]]; then
			return 0
		fi
	done < <(findmnt -rn -o SOURCE,TARGET 2>/dev/null)
	return 1
}

nrf52_port_is_dfu_bootloader() {
	local port=$1
	local candidate_link=$2
	local selected_by_id=$3
	local expected_serial=$4
	local expected_path_stem=$5
	local usb_bus usb_interfaces model vendor_id product_id

	# This shortcut is allowed only for the exact by-id link selected by the
	# user. A matching USB path or serial alone is sufficient after an expected
	# reset, but is not enough to skip that reset in the first place.
	[[ -n "$selected_by_id" && "$candidate_link" == "$selected_by_id" ]] || return 1
	nrf52_candidate_matches_identity "$port" "$candidate_link" "$selected_by_id" \
		"$expected_serial" "$expected_path_stem" || return 1
	usb_bus="$(udev_device_property "$port" ID_BUS)"
	[[ "$usb_bus" == "usb" ]] || return 1

	# Some serial-only Adafruit DFU products may have no MSC sibling and publish
	# no DFU-like model text. Accept their exact bootloader VID:PIDs,
	# but only after the selected by-id link and stable USB identity gates above.
	# The running base-XIAO MeshCore application is 2886:8044 and must not take
	# this path; 0044 and 0045 are the OTAFIX base/Sense bootloader products.
	# Likewise, HT-n5262 application firmware uses 239a:4405 while its exact
	# MeshTower V2 bootloader identity is 239a:0071.
	vendor_id="$(udev_device_property "$port" ID_VENDOR_ID)"
	product_id="$(udev_device_property "$port" ID_MODEL_ID)"
	if [[ "${vendor_id,,}" == "2886" \
		&& ( "${product_id,,}" == "0044" || "${product_id,,}" == "0045" ) ]]; then
		return 0
	fi
	if [[ "${vendor_id,,}" == "239a" && "${product_id,,}" == "0071" ]]; then
		return 0
	fi

	if nrf52_uf2_mount_matches_identity "$expected_serial" "$expected_path_stem"; then
		return 0
	fi

	# UF2 bootloaders expose CDC plus a USB mass-storage interface even when the
	# volume is not mounted. MeshCore's CDC application and ESP32 USB-JTAG ports
	# do not expose a class-08 mass-storage sibling.
	usb_interfaces="$(udev_device_property "$port" ID_USB_INTERFACES)"
	if [[ "$usb_interfaces" =~ (^|:)08[0-9A-Fa-f]{4}(:|$) ]]; then
		return 0
	fi

	# Some serial-only DFU bootloaders identify themselves explicitly without a
	# mass-storage interface. Product text is accepted only after the exact
	# selected by-id and USB identity checks above.
	model="${model:-$(udev_device_property "$port" ID_MODEL)}"
	case "${model,,}" in
		*bootloader*|*uf2*|*dfu*) return 0 ;;
	esac
	return 1
}

trigger_nrf52_1200_touch() {
	local port=$1
	local preferred_port

	preferred_port="$(preferred_flash_serial_port "$port")"
	if [[ "$preferred_port" != "$port" ]]; then
		echo "Refusing a DFU touch on secondary CDC port $port; use $preferred_port." >&2
		return 1
	fi

	nrf52_serial_port_access "$port" || return 1
	echo "Sending one 1200-baud touch to $port..."
	bash -c '
		port=$1
		exec 3<>"$port"
		stty -F "$port" 1200 hupcl
		sleep 0.1
		exec 3>&-
		exec 3<&-
	' _ "$port"
}

nrf52_candidate_identity_rank() {
	local candidate=$1
	local candidate_link=$2
	local selected_by_id=$3
	local expected_serial=$4
	local expected_path_stem=$5
	local candidate_serial candidate_path_stem candidate_interface interface_bonus=0

	candidate_serial="$(normalize_usb_serial_identity \
		"$(udev_device_property "$candidate" ID_SERIAL_SHORT)")"
	expected_serial="$(normalize_usb_serial_identity "$expected_serial")"
	candidate_path_stem="$(nrf52_usb_path_stem "$(udev_device_property "$candidate" ID_PATH)")"
	candidate_interface="$(udev_device_property "$candidate" ID_USB_INTERFACE_NUM)"
	if [[ "$candidate_interface" =~ ^0+$ ]]; then
		interface_bonus=10
	fi

	# Prefer the physical USB path across the application's and bootloader's
	# different USB product names. If both sides publish a serial, reject a
	# conflicting serial even on the same port. An exact serial is the fallback
	# for VMs that attach the re-enumerated product at a different virtual port.
	if [[ -n "$expected_path_stem" && "$candidate_path_stem" == "$expected_path_stem" ]]; then
		if [[ -n "$expected_serial" && -n "$candidate_serial" \
			&& "$candidate_serial" != "$expected_serial" ]]; then
			printf '%s\n' 0
			return 0
		fi
		printf '%s\n' $((300 + interface_bonus))
		return 0
	fi
	if [[ -n "$expected_serial" && "$candidate_serial" == "$expected_serial" ]]; then
		printf '%s\n' $((200 + interface_bonus))
		return 0
	fi
	if [[ -n "$selected_by_id" && "$candidate_link" == "$selected_by_id" ]]; then
		printf '%s\n' $((100 + interface_bonus))
		return 0
	fi
	printf '%s\n' 0
}

nrf52_candidate_matches_identity() {
	local rank
	rank="$(nrf52_candidate_identity_rank "$@")"
	[[ "$rank" =~ ^[0-9]+$ ]] && (( rank > 0 ))
}

find_reenumerated_nrf52_port() {
	local runtime_port=$1
	local selected_by_id=$2
	local expected_serial=$3
	local expected_path_stem=$4
	local original_instance=$5
	local by_id_dir="${NRF52_SERIAL_BY_ID_DIR:-/dev/serial/by-id}"
	local link candidate rank best_rank=0
	local -a links=() ports=() matches=()
	local -A seen_candidates=()

	shopt -s nullglob
	links=("${by_id_dir}"/*)
	ports=(/dev/ttyACM* /dev/ttyUSB*)
	shopt -u nullglob

	for link in "${links[@]}"; do
		candidate="$(readlink -f "$link" 2>/dev/null || true)"
		[[ -n "$candidate" && -e "$candidate" ]] || continue
		rank="$(nrf52_candidate_identity_rank "$candidate" "$link" \
			"$selected_by_id" "$expected_serial" "$expected_path_stem")"
		if [[ "$rank" =~ ^[0-9]+$ ]] && (( rank > 0 )); then
			if (( rank > best_rank )); then
				best_rank=$rank
				matches=()
				seen_candidates=()
			fi
			(( rank == best_rank )) || continue
			if [[ -z "${seen_candidates[$candidate]+x}" ]]; then
				seen_candidates[$candidate]=1
				matches+=("$candidate")
			fi
		fi
	done

	for candidate in "${ports[@]}"; do
		[[ -e "$candidate" ]] || continue
		rank="$(nrf52_candidate_identity_rank "$candidate" "" \
			"$selected_by_id" "$expected_serial" "$expected_path_stem")"
		if [[ "$rank" =~ ^[0-9]+$ ]] && (( rank > 0 )); then
			if (( rank > best_rank )); then
				best_rank=$rank
				matches=()
				seen_candidates=()
			fi
			(( rank == best_rank )) || continue
			if [[ -z "${seen_candidates[$candidate]+x}" ]]; then
				seen_candidates[$candidate]=1
				matches+=("$candidate")
			fi
		fi
	done

	if ((${#matches[@]} == 1)); then
		printf '%s\n' "${matches[0]}"
		return 0
	fi
	if ((${#matches[@]} > 1)); then
		echo "Refusing ambiguous USB serial match: ${matches[*]}" >&2
		return 2
	fi
	return 1
}

wait_for_nrf52_bootloader_port() {
	local runtime_port=$1
	local selected_by_id=$2
	local expected_serial=$3
	local expected_path_stem=$4
	local original_instance=$5
	local purpose="${6:-bootloader CDC port}"
	local timeout_seconds="${NRF52_DFU_REENUMERATE_TIMEOUT_SECONDS:-30}"
	local poll_seconds="${NRF52_DFU_REENUMERATE_POLL_SECONDS:-0.25}"
	local deadline=$((SECONDS + timeout_seconds))
	local reset_seen=0 current_instance live_port

	echo "Waiting up to ${timeout_seconds}s for the matching ${purpose}..." >&2
	while (( SECONDS <= deadline )); do
		current_instance="$(nrf52_port_instance "$runtime_port")"
		if [[ -z "$current_instance" || "$current_instance" != "$original_instance" ]]; then
			reset_seen=1
		fi

		if (( reset_seen )); then
			live_port="$(find_reenumerated_nrf52_port "$runtime_port" "$selected_by_id" \
				"$expected_serial" "$expected_path_stem" "$original_instance" || true)"
			if [[ -n "$live_port" ]]; then
				printf '%s\n' "$live_port"
				return 0
			fi
		fi
		sleep "$poll_seconds"
	done

	echo "Timed out waiting for the selected USB identity to re-enumerate as ${purpose}." >&2
	return 1
}

run_nrf52_dfu_package_buttonless() {
	local package_file=$1
	local runtime_port=$2
	local runtime_instance bootloader_port bootloader_instance candidate_link=""

	if [[ "${NRF52_BOARD_GUARD_PASSED:-0}" -ne 1 ]]; then
		echo "The nRF52 board safety check has not passed; refusing DFU." >&2
		return 1
	fi

	[[ -r "$package_file" ]] || {
		echo "nRF52 DFU package is not readable: $package_file" >&2
		return 1
	}
	[[ -e "$runtime_port" ]] || {
		echo "The selected nRF52 serial port is no longer present: $runtime_port" >&2
		return 1
	}
	if [[ -n "$NRF52_SELECTED_BY_ID" \
		&& "$(readlink -f "$NRF52_SELECTED_BY_ID" 2>/dev/null || true)" == "$runtime_port" ]]; then
		candidate_link="$NRF52_SELECTED_BY_ID"
	fi
	if ! nrf52_candidate_matches_identity "$runtime_port" "$candidate_link" \
		"$NRF52_SELECTED_BY_ID" "$NRF52_RUNTIME_SERIAL" "$NRF52_RUNTIME_PATH_STEM"; then
		echo "Serial port $runtime_port no longer matches the selected nRF52 USB identity." >&2
		return 1
	fi

	runtime_instance="$(nrf52_port_instance "$runtime_port")"
	[[ -n "$runtime_instance" ]] || {
		echo "Cannot identify the running nRF52 serial port $runtime_port." >&2
		return 1
	}
	if nrf52_port_is_dfu_bootloader "$runtime_port" "$candidate_link" \
		"$NRF52_SELECTED_BY_ID" "$NRF52_RUNTIME_SERIAL" "$NRF52_RUNTIME_PATH_STEM"; then
		echo "Selected nRF52 is already in its matching DFU bootloader on $runtime_port."
		echo "Flashing $package_file directly without a 1200-baud touch..."
		if ! run_nrfutil_dfu_serial_live_port "$package_file" "$runtime_port"; then
			return 1
		fi
		NRF52_LAST_DFU_PORT="$runtime_port"
		NRF52_LAST_DFU_INSTANCE="$runtime_instance"
		return 0
	fi
	if ! trigger_nrf52_1200_touch "$runtime_port"; then
		echo "Failed to send the 1200-baud DFU touch to $runtime_port." >&2
		return 1
	fi
	if ! bootloader_port="$(wait_for_nrf52_bootloader_port "$runtime_port" \
		"$NRF52_SELECTED_BY_ID" "$NRF52_RUNTIME_SERIAL" "$NRF52_RUNTIME_PATH_STEM" \
		"$runtime_instance")"; then
		return 1
	fi

	bootloader_instance="$(nrf52_port_instance "$bootloader_port")"
	[[ -n "$bootloader_instance" ]] || {
		echo "The matched nRF52 bootloader port disappeared before programming: $bootloader_port" >&2
		return 1
	}
	echo "Matched bootloader port: $bootloader_port"
	echo "Flashing $package_file without another 1200-baud touch..."
	if ! run_nrfutil_dfu_serial_live_port "$package_file" "$bootloader_port"; then
		return 1
	fi

	NRF52_LAST_DFU_PORT="$bootloader_port"
	NRF52_LAST_DFU_INSTANCE="$bootloader_instance"
}

_jq1() {
	local filter=("$@")              
	if [[ "$DEBUG_JQ" -eq 1 ]]; then
		echo "[_jq] jq --raw-output ${filter[*]} \"$CONFIG_FILE\"" >/dev/tty
		jq --raw-output "${filter[@]}" "$CONFIG_FILE"
	else
		jq --raw-output "${filter[@]}" "$CONFIG_FILE" 2>/dev/null
	fi
}

_jq2() {
	local filter=("$@")              
	if [[ "$DEBUG_JQ" -eq 1 ]]; then
		echo "[_jq] jq --raw-output ${filter[*]} \"$RELEASES_FILE\"" >/dev/tty
		jq --raw-output "${filter[@]}" "$RELEASES_FILE"
	else
		jq --raw-output "${filter[@]}" "$RELEASES_FILE" 2>/dev/null
	fi
}

_cached_json() {
    local primary_url="$1"    # first arg = primary URL
    local cache_file="$2"     # second arg = path to cache file
    shift 2
    local -a urls=("$primary_url" "$@")
    local age_sec="$CACHE_TIMEOUT_SECONDS"
    local validate_filter="${JSON_VALIDATE_FILTER:-.}"

	# JSON downloads are validated below, so install both tools before either
	# curl or jq can be invoked by this path.
	ensure_command curl
	ensure_command jq

    mkdir -p "$(dirname "$cache_file")"

    local fetch_needed=1
    if [[ -f "$cache_file" ]]; then
        local file_age=$(( $(date +%s) - $(stat -c %Y "$cache_file") ))
        if (( file_age < age_sec )) && jq -e "$validate_filter" "$cache_file" >/dev/null 2>&1; then
            fetch_needed=0
        fi
    fi

    if (( fetch_needed )); then
        local cache_name
        local tmp_file
        local attempt
        local max_attempts="${CURL_FETCH_RETRIES:-3}"
        local max_time="${CURL_FETCH_MAX_TIME:-10}"
        local retry_sleep="${CURL_FETCH_RETRY_DELAY:-1}"
        local download_ok=0
        local url

        cache_name="$(basename "$cache_file")"
        tmp_file="${cache_file}.tmp.$$"
        echo "Downloading ${cache_name}"

        for url in "${urls[@]}"; do
            attempt=1
            while (( attempt <= max_attempts )); do
                if curl -sSL --fail --max-time "$max_time" "$url" -o "$tmp_file"; then
                    if [[ -s "$tmp_file" ]] && jq -e "$validate_filter" "$tmp_file" >/dev/null 2>&1; then
                        mv -f "$tmp_file" "$cache_file"
                        download_ok=1
                        break 2
                    fi
                    echo "Downloaded JSON from $url did not have the expected structure." >&2
                    rm -f "$tmp_file"
                fi

                rm -f "$tmp_file"
                if (( attempt < max_attempts )); then
                    echo "Download failed from $url (${attempt}/${max_attempts}); retrying in ${retry_sleep}s..." >&2
                    sleep "$retry_sleep"
                fi
                ((attempt++))
            done

            if [[ "$url" != "${urls[${#urls[@]}-1]}" ]]; then
                echo "Trying fallback JSON source..." >&2
            fi
        done

        if (( !download_ok )); then
            if [[ -s "$cache_file" ]] && jq -e "$validate_filter" "$cache_file" >/dev/null 2>&1; then
                echo "All JSON sources failed; using cached ${cache_name}." >&2
                return 0
            fi
            echo "ERROR: all sources failed for ${cache_name} and no valid cached file is available." >&2
            return 1
        fi
    fi
}

latest_keymind_provider_url() {
    local variant="$1"
    local fallback_url pattern fallback_path latest_path tree_json

    case "$variant" in
        cascade)
            fallback_url="$KEYMIND_CASCADE_FALLBACK_URL"
            pattern='^mesh-america/keymind-cascade-v[0-9][^/]*-provider\.json$'
            ;;
        logging)
            fallback_url="$KEYMIND_CASCADE_LOGGING_FALLBACK_URL"
            pattern='^mesh-america/keymind-cascade-logging-v[0-9][^/]*-provider\.json$'
            ;;
        *)
            echo "Unknown Keymind provider variant: $variant" >&2
            return 1
            ;;
    esac

    fallback_path="${fallback_url#"${KEYMIND_RAW_BASE_URL}"/}"
    tree_json="$(curl -sSL --fail --max-time "${CURL_FETCH_MAX_TIME:-10}" "$KEYMIND_GITHUB_TREE_URL" 2>/dev/null || true)"
    latest_path="$({
        printf '%s\n' "$fallback_path"
        if [[ -n "$tree_json" ]]; then
            jq -r '.tree[]?.path // empty' <<< "$tree_json" 2>/dev/null | grep -E "$pattern" || true
        fi
    } | sort -V | tail -n 1)"

    if [[ -z "$latest_path" ]]; then
        printf '%s\n' "$fallback_url"
    else
        printf '%s/%s\n' "$KEYMIND_RAW_BASE_URL" "$latest_path"
    fi
}

activate_keymind_provider() {
    local variant="$1"
    local provider_url fallback_url provider_file

    provider_url="$(latest_keymind_provider_url "$variant")"
    if [[ "$variant" == "logging" ]]; then
        fallback_url="$KEYMIND_CASCADE_LOGGING_FALLBACK_URL"
    else
        fallback_url="$KEYMIND_CASCADE_FALLBACK_URL"
    fi
    provider_file="${DOWNLOAD_DIR}/providers/$(basename "${provider_url%%[?#]*}")"

    echo "Using Keymind provider manifest: $provider_url"
    if ! JSON_VALIDATE_FILTER='(.device | type == "array") and (.device | length > 0)' \
        _cached_json "$provider_url" "$provider_file" "$fallback_url"; then
        return 1
    fi

    CONFIG_FILE="$provider_file"
    printf '%s\n' "$provider_file" > "$CONFIG_SOURCE_FILE"
}

normalize_id() {
  # 1) drop parentheses content, 2) lower, 3) non-alnum -> _, 4) squeeze _.
  local s="$1"
  s="${s//\(/ }"; s="${s//\)/ }"
  s="$(printf '%s' "$s" | tr '[:upper:]' '[:lower:]')"
  s="$(printf '%s' "$s" | sed 's/[^a-z0-9]+/_/g; s/[^a-z0-9]/_/g; s/___*/_/g; s/^_//; s/_$//')"
  printf '%s' "$s"
}

strip_vendor_tokens() {
  # remove frequent vendor words so tails focus on model
  local s="$1"
  s=" $s "
  for w in elecrow heltec heltec_heltec lilygo seed seeed studio rak wireless wisblock wismesh raspberry pi pico waveshare promicro faketec uniteng sensecap wio xiao; do
    s="${s// $w / }"
  done
  s="$(printf '%s' "$s" | sed 's/^ *//; s/ *$//; s/  */ /g; s/ /_/g')"
  printf '%s' "$s"
}

contains_word() {
  local hay="$1" needle="$2"
  [[ "$hay" =~ (^|_)${needle}(_|$) ]]
}

is_good_tail() {
  local t="$1"
  # reject empty, short (<3), all digits/underscores, or mostly numeric like "1_6"
  [[ -n "$t" ]] || return 1
  (( ${#t} >= 3 )) || return 1
  [[ "$t" =~ [a-z] ]] || return 1
  return 0
}

_log() { 
	[[ ${DEBUG:-0} -ne 0 ]] && printf '[mc] %s\n' "$*" >&2; 
}

serial_cmd() {
  local DEVICE_NAME="$1"
  shift
  local line="$*"

  local max_retries="${SERIAL_RETRIES:-3}"
  local delay_between="${SERIAL_RETRY_DELAY:-0.08}"
  local first_candidate_only="${SERIAL_FIRST_CANDIDATE_ONLY:-0}"

  # Fast read/exit behavior
  local total_timeout="${SERIAL_TOTAL_TIMEOUT:-7.5s}"  # hard cap
  local idle_timeout="${SERIAL_IDLE_TIMEOUT:-2.5}"    # socat exits after idle
  local device_name_now="${DEVICE_NAME}"
  if [[ -z "${device_name_now}" ]]; then
	device_name_now="/dev/ttyACM0"
  fi

  # RX-log line pattern (skip)
  local rx_pat='^[0-9]{2}:[0-9]{2}(:[0-9]{2})?[[:space:]]*-[[:space:]]*[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}[[:space:]]*U:'

  # Ensure serial and binary-inspection tools are installed.
  ensure_command socat

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

  local baud attempt out last_out
  last_out=""

	for baud in "${candidates[@]}"; do
	    for ((attempt=1; attempt<=max_retries; attempt++)); do
			out="$(
			  # shellcheck disable=SC2016
			  timeout -s KILL "${total_timeout}" \
				bash -o pipefail -c '
			  device="$1"
			  baud="$2"
			  line="$3"
			  idle="$4"
			  rx_pat="$5"

			  printf "%b" "${line}\r\n" \
				| socat -T "${idle}" - "OPEN:${device},raw,echo=0,b${baud}" 2>/dev/null \
				| tr -d "\r" \
				| sed -E $'"'"'s/\x1B\\[[0-9;]*[A-Za-z]//g'"'"' \
				| sed -E "s/^[[:space:][:cntrl:]]*(->|>)+[[:space:]]*//" \
				| sed -E "s/^[[:space:][:cntrl:]]+//; s/[[:space:]]+$//" \
				| sed -E "s/^[^0-9A-Za-z+\\-]+//" \
				| grep -E -v "$rx_pat" \
				| awk -v cmd="$line" '"'"'
					NF {
					  if ($0 == cmd) next
					  keep = $0
					}
					END { print keep }
				  '"'"'
			' _ "${device_name_now}" "${baud}" "${line}" "${idle_timeout}" "${rx_pat}"
		)"
		rc=$?

		# Timeout (KILL) or other error -> retry
		if (( rc != 0 )); then
		  out=""
		fi

      last_out="$out"

      # Empty, echo, or log line -> retry
      if [[ -z "$out" || "$out" == "$line" || "$out" =~ $rx_pat ]]; then
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

  # Total failure: return empty (or whatever last_out was), but success exit code
  printf '%s' "$last_out"
  return 0
}

choose_custom_firmware_file() {
  local arch_lc required_ext extra input check check_lc role_lc local_input

  arch_lc=${ARCHITECTURE,,}
  extra=""
  if [[ "$arch_lc" == "esp32" ]]; then
    required_ext=".bin"
    extra="The merged files will do a full erase"
  else
    required_ext=".zip"
  fi

  echo "Rule: ARCHITECTURE='$ARCHITECTURE' requires files ending with ${required_ext} ${extra}"

  # Helpful base URL by role
  role_lc=${ROLE,,}
  case "$role_lc" in
    companion*) printf " https://files.brazio.org/meshcore/nightly/companion/ \n https://analyzer.letsmesh.net/observer/onboard?type=companion \n https://cloud.weyhmueller.org/s/meshcore-stuff?dir=/WiFi+Companion+Patcher \n " ;;
    repeater*)  printf " https://files.brazio.org/meshcore/nightly/repeater/ \n https://analyzer.letsmesh.net/observer/onboard?type=repeater \n https://github.com/IoTThinks/EasySkyMesh/releases/tag/PowerSaving10 \n "  ;;
    room*)      printf " https://files.brazio.org/meshcore/nightly/room-server/ \n https://analyzer.letsmesh.net/observer/onboard?type=room \n "  ;;
  esac

  print_latest_custom_firmware_option "$required_ext"

  while :; do
    read -rp "Enter full filename, url, or latest [latest]: " input < /dev/tty
    [[ -z "$input" ]] && input="latest"

    local_input="$input"
    if [[ "$local_input" == file:///* ]]; then
      local_input="${local_input#file://}"
    fi
    if [[ "${local_input,,}" == "latest" ]]; then
      local_input="$(latest_custom_firmware_file "$required_ext" || true)"
      if [[ -z "$local_input" ]]; then
        echo "ERROR: No custom firmware files ending with ${required_ext} found in ${DOWNLOAD_DIR}/custom"
        continue
      fi
      echo "Selected latest custom firmware: $local_input"
    fi

    # Strip query/fragment for extension test
    check="${local_input%%[\?#]*}"
    check_lc=${check,,}
    if [[ "$check_lc" != *"$required_ext" ]]; then
      echo "ERROR: Selection must end with ${required_ext}"
      continue
    fi

    apply_custom_firmware_selection "$local_input"
    return 0
  done
}

filter_last_two_branches() {
  local -n _IN="$1" _OUT="$2"
  local dbg="${3:-${FILTER_DEBUG:-${DEBUG:-0}}}"

  _OUT=()
  ((dbg)) && printf '[filter] bash=%s  set_e=%s  pipefail=%s\n' "$BASH_VERSION" \
    "$(set -o | awk '/errexit/{print $2}')" "$(set -o | awk '/pipefail/{print $2}')" >&2
  ((dbg)) && printf '[filter] input(%d): %s\n' "${#_IN[@]}" "${_IN[*]}" >&2
  ((${#_IN[@]}==0)) && { ((dbg)) && echo '[filter] input empty' >&2; return 0; }

  # Clean input safely
  local -a _CLEAN=()
  mapfile -t _CLEAN < <(
    printf '%s\n' "${_IN[@]}" \
      | tr -d '\r' \
      | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
      | awk 'NF' || true
  )
  ((dbg)) && printf '[filter] clean(%d): %s\n' "${#_CLEAN[@]}" "${_CLEAN[*]}" >&2
  ((${#_CLEAN[@]}==0)) && { ((dbg)) && echo '[filter] nothing after clean' >&2; return 0; }

  # Extract unique branches X.Y sorted desc
  local -a _BRANCHES=()
  mapfile -t _BRANCHES < <(
    printf '%s\n' "${_CLEAN[@]}" \
	  | grep -Eo '[Vv]?[0-9]+\.[0-9]+' \
	  | sed -E 's/^[Vv]//' \
      | sort -t. -k1,1nr -k2,2nr \
      | awk '!seen[$0]++' || true
  )
  ((dbg)) && printf '[filter] branches(%d): %s\n' "${#_BRANCHES[@]}" "${_BRANCHES[*]}" >&2

  local -a choose=("${_BRANCHES[@]:0:2}")
  ((dbg)) && printf '[filter] chosen(%d): %s\n' "${#choose[@]}" "${choose[*]}" >&2
  ((${#choose[@]}==0)) && { ((dbg)) && echo '[filter] no branches parsed' >&2; return 0; }

  local re
  re="$(printf '%s\n' "${choose[@]}" | sed -E 's/\./\\./g' | paste -sd'|' -)"
  ((dbg)) && printf '[filter] regex: ^[Vv]?(%s)(\\.|$)\n' "$re" >&2

  mapfile -t _OUT < <(
    printf '%s\n' "${_CLEAN[@]}" \
	  | grep -E "(^|[^0-9])[Vv]?(${re})(\.|$)" 2>/dev/null \
      | sort -V -r \
      | awk '!seen[$0]++' || true
  )
  ((dbg)) && printf '[filter] output(%d): %s\n' "${#_OUT[@]}" "${_OUT[*]}" >&2
  return 0
}

choose_version_from_releases() {
	local DEVICE="$1"
	local ROLE="$2"
	local ARCHITECTURE="$3"
	local ERASE_URL="$4"
	local TITLE="$5"
	local cache_file="${CACHE_FILE:-$RELEASES_FILE}"

	# ---- fetch / reuse cache ---------------------------------------------
    JSON_VALIDATE_FILTER='type == "array"' \
        _cached_json "$RELEASE_INFO2_URL" "$cache_file" "$RELEASE_INFO2_FALLBACK_URL"

	local VERSION=''
    local TYPE=''
	[[ -f "$SELECTED_VERSION_FILE" ]] && VERSION="$(<"$SELECTED_VERSION_FILE")"
	[[ -f "$SELECTED_TYPE_FILE"    ]] && TYPE="$(<"$SELECTED_TYPE_FILE")"
	local CHOSEN_FILE=''

    # ---------------- step 3 - version ------------------------------------
	if [[ -z "$VERSION" ]]; then
		local -a VERSIONS=()
		mapfile -t VERSIONS < <(
			_jq2 -r 'if type=="array" then .[] | (.version // empty) else empty end' \
			  | sed -E '/^[[:space:]]*$/d' \
			  | sort -ru || true
		)
		if ((${#VERSIONS[@]} == 0)); then
			echo "No versions found in cached releases.json; forcing refresh and retry..." >&2
			local saved_cache_timeout="${CACHE_TIMEOUT_SECONDS}"
			CACHE_TIMEOUT_SECONDS=0 JSON_VALIDATE_FILTER='type == "array"' \
				_cached_json "$RELEASE_INFO2_URL" "$cache_file" "$RELEASE_INFO2_FALLBACK_URL" || true
			CACHE_TIMEOUT_SECONDS="$saved_cache_timeout"

			mapfile -t VERSIONS < <(
				_jq2 -r 'if type=="array" then .[] | (.version // empty) else empty end' \
				  | sed -E '/^[[:space:]]*$/d' \
				  | sort -ru || true
			)

			if ((${#VERSIONS[@]} == 0)); then
				echo "ERROR: no versions in /releases endpoint (file: $RELEASES_FILE)" >&2
				echo "Try removing cache and rerun: rm -f \"$RELEASES_FILE\"" >&2
				return 1
			fi
		fi

		if ((${#VERSIONS[@]} == 1)); then
			VERSION="${VERSIONS[0]}"
			echo "Auto-selected version from fallback: $VERSION"
		else
			# Keep only newest two branches (X.Y)
			local -a VERSIONS_SHOW=()
			filter_last_two_branches VERSIONS VERSIONS_SHOW
			CHOICE=""
			local -a MENU_OPTIONS=("${VERSIONS_SHOW[@]}" "Keymind Cascade" "Keymind Cascade Logging" "Custom")
		
			while [[ -z $VERSION ]]; do
				sleep 0.1
				echo
				echo "[3] Select version:"
				select CHOICE in "${MENU_OPTIONS[@]}"; do
					# Determine required extension rule
					arch_lc=${ARCHITECTURE,,}
					extra=""
					if [[ "$arch_lc" == "esp32" ]]; then
						required_ext=".bin"
						extra="The merged files will do a full erase"
					else
						required_ext=".zip"
					fi


					# If user pasted a URL/filename instead of choosing a number, handle it
					if [[ -z "$CHOICE" ]]; then
						if [[ "$REPLY" =~ ^[0-9]+$ ]]; then
							echo "Invalid selection."
							continue
						fi

						input="$REPLY"
						check="${input%%[\?#]*}"
						check_lc=${check,,}
						if [[ "$check_lc" != *"$required_ext" ]]; then
							echo "ERROR: Selection must end with ${required_ext}"
							continue
						fi
						apply_custom_firmware_selection "$input"
						break
					fi

					case "$CHOICE" in
							"Keymind Cascade"|"Keymind Cascade Logging")
							  local provider_variant="cascade"
							  [[ "$CHOICE" == "Keymind Cascade Logging" ]] && provider_variant="logging"
							  if activate_keymind_provider "$provider_variant"; then
								rm -f "$SELECTED_DEVICE_FILE" "$ARCHITECTURE_FILE" "$ERASE_URL_FILE" \
								  "$SELECTED_ROLE_FILE" "$SELECTED_TITLE_FILE" "$SELECTED_SUBTITLE_FILE" "$SELECTED_VERSION_FILE" "$SELECTED_TYPE_FILE" \
								  "$SELECTED_URL_FILE"
								CHOSEN_FILE=""
								choose_meshcore_firmware
								return
							  fi
							  echo "Keymind provider selection failed; please choose again."
							  continue
							  ;;
							"Custom")
							  if choose_custom_firmware_file; then
								break
							  else
								echo "Custom selection failed; please choose again."
								continue
							  fi
							  
							  ;;
						*)
							VERSION="$CHOICE"
							break
							
							
							;;
					esac
				done < /dev/tty
			done
		fi
	fi

    # ---------------- step 4 - type ---------------------------------------
	if [[ -z "$TYPE" ]]; then
		local -a TYPES=()
		mapfile -t TYPES < <( _jq1 --arg d "$DEVICE" --arg r "$ROLE" ".device[] | select(.name==\$d) | .firmware[] | select(.role==\$r) | .github | .files | keys[]" | sort -u )
		
		if ((${#TYPES[@]} == 1)); then
			TYPE="${TYPES[0]}"
			echo "Auto-selected type: $TYPE"
		elif ((${#TYPES[@]} == 2)) && [[ " ${TYPES[*]} " == *" flash "* ]] && [[ " ${TYPES[*]} " == *" download "* ]]; then
			TYPE="flash"
			echo "Auto-selected type: flash"
		else
			while [[ -z $TYPE ]]; do
				sleep 0.1
				echo; echo "[4] Select type 2:"
				select TYPE in "${TYPES[@]}"; do [[ -n ${TYPE:-} ]] && break; done < /dev/tty
			done
		fi
	fi

    # ---------------- step 5 - filename -----------------------------------
	if [[ -z "$CHOSEN_FILE" ]]; then
		local REGEX=''
		if [[ -n "$TITLE" ]]; then
			REGEX=$( _jq1 --arg type "$TYPE" --arg d "$DEVICE" --arg r "$ROLE" --arg title "$TITLE" ".device[] | select(.name==\$d) | .firmware[] | select(.role==\$r) | select(.title==\$title) | .github | .files | .[\$type]" | sort -u )
		fi
		if [[ -z "$REGEX" ]]; then
			REGEX=$( _jq1 --arg type "$TYPE" --arg d "$DEVICE" --arg r "$ROLE" ".device[] | select(.name==\$d) | .firmware[] | select(.role==\$r) | .github | .files | .[\$type]" | sort -u )
		fi
		#echo ">$TITLE<"
		#echo ">$REGEX<"
		ROLE_ALT="$ROLE"
		if [[ "$ROLE" == "companionBle" || "$ROLE" == "companionUsb" ]]; then
			ROLE_ALT="companion"
		fi
		

		# Provider patterns describe a single release asset. Anchor them so a
		# normal repeater entry cannot accidentally select its
		# _lora_ota_no_external_sensors sibling (or the reverse).
		CHOSEN_FILE=$( _jq2 --arg reg "$REGEX" --arg ver "$VERSION" --arg t "$TYPE" --arg d "$DEVICE" --arg r "$ROLE_ALT" ".[] | select(.version==\$ver and .type==\$r) | .files[] | select(.name|test(\"^(?:\" + \$reg + \")$\")) | .url " )
	fi
	
	echo "$DEVICE" > "$SELECTED_DEVICE_FILE"
	echo "$ROLE" > "$SELECTED_ROLE_FILE"
	echo "$ARCHITECTURE" > "$ARCHITECTURE_FILE"
	echo "$ERASE_URL" > "$ERASE_URL_FILE"

	echo "$VERSION" > "$SELECTED_VERSION_FILE"
	echo "$TYPE" > "$SELECTED_TYPE_FILE"
    echo "$CHOSEN_FILE" > "$SELECTED_URL_FILE"
}

pick_matching_device() {
	local usb_string="$1"
	local -n _DEVICES="$2"   # bash 4.3+ nameref to the array

	local usb_slug base core n cand1 cand2 cand3 name score i
	local -a toks=()
	local best_score=0
	MATCH=""
	MATCH_IDX=-1

	usb_slug="$(normalize_id "$usb_string")"

	for i in "${!_DEVICES[@]}"; do
		name="${_DEVICES[$i]}"
		base="$(normalize_id "$name")"

		# strip common vendor tokens; keep tail model words
		core="$base"
		core=$( printf '%s' "$core" | sed -E "s/\b($VENDORLIST)\b_?//g; s/__+/_/g; s/^_+//; s/_+$//")
		core=$( printf '%s' "$core" | sed -E "s/(^|_)($RADIOLIST)(_|$)/\1\3/g" )
		core=$( printf '%s' "$core" | sed -E 's/__+/_/g; s/^_+//; s/_+$//' ) # tidy underscores
		#echo "$core"

		[[ -z "$core" ]] && core="$base"

		IFS='_' read -r -a toks <<< "$core"
		n=${#toks[@]}
		cand3=""; cand2=""; cand1=""
		(( n>=3 )) && cand3="${toks[n-3]}_${toks[n-2]}_${toks[n-1]}"
		(( n>=2 )) && cand2="${toks[n-2]}_${toks[n-1]}"
		(( n>=1 )) && cand1="${toks[n-1]}"

		# Score every candidate before choosing. Returning the first loose tail
		# match makes a generic entry such as "Heltec v4" shadow the longer
		# "Heltec v4 R8" identity solely because it sorts first in the menu.
		# Exact display names are strongest, followed by complete normalized
		# names, vendor-stripped model names, and progressively shorter tails.
		score=0
		if [[ "$usb_slug" == "$base" ]]; then
			score=$((100000 + ${#base}))
		elif contains_word "$usb_slug" "$base"; then
			score=$((90000 + ${#base}))
		elif is_good_tail "$core" && contains_word "$usb_slug" "$core"; then
			score=$((80000 + ${#core}))
		elif is_good_tail "$cand3" && contains_word "$usb_slug" "$cand3"; then
			score=$((30000 + ${#cand3}))
		elif is_good_tail "$cand2" && contains_word "$usb_slug" "$cand2"; then
			score=$((20000 + ${#cand2}))
		elif is_good_tail "$cand1" && contains_word "$usb_slug" "$cand1"; then
			score=$((10000 + ${#cand1}))
		fi

		if (( score > best_score )); then
			best_score=$score
			MATCH="${_DEVICES[$i]}"
			MATCH_IDX=$((i+1))
		fi
	done

	if (( best_score > 0 )); then
		return 0
	fi

	# optional aliases
	case "$usb_slug" in
		*station_g2*)
			for i in "${!_DEVICES[@]}"; do
				if [[ "${_DEVICES[$i]}" == "UnitEng Station G2" ]]; then
					MATCH="${_DEVICES[$i]}"; MATCH_IDX=$((i+1)); return 0
				fi
			done
			;;
		*heltec*wifi*lora*32*v4*)
			for i in "${!_DEVICES[@]}"; do
				if [[ "${_DEVICES[$i]}" == "Heltec v4" ]]; then
					MATCH="${_DEVICES[$i]}"; MATCH_IDX=$((i+1)); return 0
				fi
			done
			;;
	esac

	return 1
}

#############################################################################
# choose_meshcore_firmware
# Interactively select MeshCore firmware (device -> role -> version -> type)  
# Uses a 6-hour JSON cache in $XDG_CACHE_HOME or $HOME/.cache  
# Requires: bash 4+, curl, jq
#############################################################################
choose_meshcore_firmware() {
    # ---- constants --------------------------------------------------------
    local CACHE_DIR="$DOWNLOAD_DIR"
    local CACHE_FILE="$RELEASES_FILE"
    local JSON_URL="$RELEASE_INFO1_URL"

    # ---- ensure folders ---------------------------------------------------
    mkdir -p "$CACHE_DIR"

    # ---- fetch / reuse cache ---------------------------------------------
	local config_available=0
	CONFIG_FILE="$DEFAULT_CONFIG_FILE"
	if [[ -s "$CONFIG_SOURCE_FILE" ]]; then
		local saved_config_file
		saved_config_file="$(<"$CONFIG_SOURCE_FILE")"
		if [[ -s "$saved_config_file" ]] \
			&& jq -e '(.device | type == "array") and (.device | length > 0)' "$saved_config_file" >/dev/null 2>&1; then
			CONFIG_FILE="$saved_config_file"
			config_available=1
		fi
	fi

	if (( !config_available )); then
		rm -f "$CONFIG_SOURCE_FILE"
		if JSON_VALIDATE_FILTER='(.device | type == "array") and (.device | length > 0)' \
			_cached_json "$JSON_URL" "$CONFIG_FILE" "$RELEASE_INFO1_FALLBACK_URL"; then
			config_available=1
		else
			echo "MeshCore and Mesh America flasher configs are unavailable." >&2
		fi
	fi

	local DEVICE=''
	local ARCHITECTURE=''
	local ERASE_URL=''
	local ROLE=''
	local SUBTITLE=''
	local VERSION=''
    local TYPE=''
	local TITLE=''
	[[ -f "$SELECTED_DEVICE_FILE"  ]] && DEVICE="$(<"$SELECTED_DEVICE_FILE")"
	[[ -f "$ARCHITECTURE_FILE"     ]] && ARCHITECTURE="$(<"$ARCHITECTURE_FILE")"
	[[ -f "$ERASE_URL_FILE"        ]] && ERASE_URL="$(<"$ERASE_URL_FILE")"
	[[ -f "$SELECTED_ROLE_FILE"    ]] && ROLE="$(<"$SELECTED_ROLE_FILE")"
	[[ -f "$SELECTED_TITLE_FILE"   ]] && TITLE="$(<"$SELECTED_TITLE_FILE")"
	[[ -f "$SELECTED_SUBTITLE_FILE" ]] && SUBTITLE="$(<"$SELECTED_SUBTITLE_FILE")"
	[[ -f "$SELECTED_VERSION_FILE" ]] && VERSION="$(<"$SELECTED_VERSION_FILE")"
	[[ -f "$SELECTED_TYPE_FILE"    ]] && TYPE="$(<"$SELECTED_TYPE_FILE")"

    # ---------------- step 1 - device -------------------------------------
	if [[ -z "$DEVICE" ]]; then
		if (( !config_available )); then
			echo
			echo "Select a firmware source:"
			select source_choice in "Keymind Cascade" "Keymind Cascade Logging" "Custom"; do
				case "$source_choice" in
					"Keymind Cascade")
						activate_keymind_provider cascade && break
						;;
					"Keymind Cascade Logging")
						activate_keymind_provider logging && break
						;;
					"Custom")
						DEVICE="CustomFirmware"
						break
						;;
					*)
						echo "Invalid selection."
						;;
				esac
			done < /dev/tty
		fi

		while [[ -z "$DEVICE" ]]; do
			local -a DEVICES=()
			mapfile -t DEVICES < <(_jq1 '.device[].name' 2>/dev/null | sort -u)

			if ((${#DEVICES[@]} == 0)); then
				echo "ERROR: no .device[].name entries found in $CONFIG_FILE"
				return 1
			fi

			if ((${#DEVICES[@]} == 1)); then
				DEVICE="${DEVICES[0]}"
				echo "Auto-selected device: $DEVICE"
				break
			fi

			local choice=''
			local device_port_name=''
			local device_name=''
			[[ -f "$DEVICE_PORT_NAME_FILE" ]] && device_port_name="$(<"$DEVICE_PORT_NAME_FILE")"
			[[ -f "$DEVICE_PORT_FILE" ]] && device_name="$(<"$DEVICE_PORT_FILE")"
			
			match=""
			match_idx=-1
			
			if pick_matching_device "$device_port_name" DEVICES; then
				match="$MATCH"
				match_idx="$MATCH_IDX"
			else
				match=""
				match_idx=-1
			fi
			
			while [[ -z "$DEVICE" ]]; do
				echo
				echo "[1] Select device (0 = Auto-detect):"
				printf '  0) Auto-detect\n'
				for i in "${!DEVICES[@]}"; do
					printf '  %d) %s\n' $((i+1)) "${DEVICES[$i]}"
				done
				keymind_index=$(( ${#DEVICES[@]} + 1 ))
				keymind_logging_index=$(( ${#DEVICES[@]} + 2 ))
				custom_index=$(( ${#DEVICES[@]} + 3 ))
				printf '  %d) Keymind Cascade\n' "$keymind_index"
				printf '  %d) Keymind Cascade Logging\n' "$keymind_logging_index"
				printf '  %d) Custom\n' "$custom_index"
				echo ""


				if [[ -n "$match" ]]; then
					read -r -p "Choice (Detected $match on $device_name, Enter will pick $match_idx): " choice </dev/tty
				else
					echo "$device_port_name -> $device_name"
					read -r -p 'Choice: ' choice </dev/tty
				fi
				

				if [[ "$choice" == 0 ]]; then
					echo "Auto-detection requested."
					autodetect_device
					
					[[ -f "$AUTODETECT_DEVICE_FILE" ]] && device_port_name="$(<"$AUTODETECT_DEVICE_FILE")"
					if pick_matching_device "$device_port_name" DEVICES; then
						match="$MATCH"
						match_idx="$MATCH_IDX"
					else
						match=""
						match_idx=-1
					fi
					
					[[ -f "$SELECTED_DEVICE_FILE"  ]] && DEVICE="$(<"$SELECTED_DEVICE_FILE")"
				elif [[ "$choice" =~ ^[1-9][0-9]*$ ]] && (( choice >= 1 && choice <= ${#DEVICES[@]} )); then
					DEVICE="${DEVICES[$((choice-1))]}"
				elif [[ -z "$choice" && -n "$match" ]]; then
					choice="$match_idx"
					DEVICE="${DEVICES[$((choice-1))]}"
				elif [[ "$choice" == "${keymind_index}" ]]; then
					if activate_keymind_provider cascade; then
						break
					fi
					choice=''
				elif [[ "$choice" == "${keymind_logging_index}" ]]; then
					if activate_keymind_provider logging; then
						break
					fi
					choice=''
				elif [[ "$choice" == "${custom_index}" ]]; then
					echo "Custom."
					DEVICE="CustomFirmware"
				else
					echo "Invalid selection."
					choice=''
				fi
				done
		done
	fi
	
	
	if [[ "$DEVICE" == "CustomFirmware" ]]; then
		echo "Custom firmware selected."
		echo "Is this an ESP32 or NRF52 device?"
		echo "  1) esp32"
		echo "  2) nrf52"

		while :; do
			read -rp "Choice (1/2): " ans
			case "$ans" in
				1)
					ARCHITECTURE="esp32"
					break
					;;
				2)
					ARCHITECTURE="nrf52"
					break
					;;
				*)
					echo "Please enter 1 or 2."
					;;
			esac
		done

		echo "You selected: $ARCHITECTURE"
		
		while [[ -z $CHOSEN_FILE ]]; do
			sleep 0.1
			if choose_custom_firmware_file; then
				echo ""
				ROLE="custom"
				VERSION="custom"
				[[ -n "$TYPE" ]] || TYPE="custom"
				break
			else
				echo "Custom selection failed; please choose again."
				continue
			fi
		done
	fi
	
	# ---------------- step 2 - architecture & erase -----------------------
	if [[ -z "$ARCHITECTURE" ]]; then
		ARCHITECTURE=$( _jq1 --arg d "$DEVICE" ".device[]|select(.name==\$d)|.type" )
	fi
	if [[ "$DEVICE" != "CustomFirmware" ]]; then
		JSON_VALIDATE_FILTER='type == "array"' \
			_cached_json "$RELEASE_INFO2_URL" "$CACHE_FILE" "$RELEASE_INFO2_FALLBACK_URL" || true
		ERASE_URL=$( _jq1 --arg d "$DEVICE" ".device[]|select(.name==\$d)|.erase // empty" )
		[[ -n $ERASE_URL ]] && ERASE_URL="https://flasher.meshcore.io/firmware/$ERASE_URL"
	fi

    # ---------------- step 3 - role ---------------------------------------
	if [[ -z "$ROLE" ]]; then

		# ROLES[i], TITLES[i], LABELS[i] belong together
		local -a ROLES=()
		local -a TITLES=()
		local -a SUBTITLES=()
		local -a LABELS=()

		# Read "role<TAB>title<TAB>subtitle" from jq; labels may be empty
		while IFS=$'\t' read -r role title subtitle; do
			[[ -z "$role" ]] && continue

			# Normalize missing or "null" title
			if [[ -z "$title" || "$title" == "null" ]]; then
				case "$role" in
					companionBle|companionUsb)
						title="Companion radio"
						;;
					repeater)
						title="Repeater"
						;;
					roomServer)
						title="Room Server"
						;;
					*)
						# Fallback: use role name as-is
						title="$role"
						;;
				esac
			fi

			ROLES+=("$role")
			TITLES+=("$title")
			SUBTITLES+=("$subtitle")
			done < <(
				# shellcheck disable=SC2016
				_jq1 --arg d "$DEVICE" '.device[] | select(.name == $d) | .firmware[] | "\(.role)\t\(.title // "")\t\(.subTitle // "")"' | sort -u
			)

		if ((${#ROLES[@]} == 0)); then
			echo "ERROR: no firmware roles found for device $DEVICE" >&2
			return 1
		fi

		# Build menu labels that include BLE/USB info (and optional hints)
		local i suffix
		for i in "${!ROLES[@]}"; do
			suffix=""
			case "${ROLES[i]}" in
				companionBle)
					# Show BLE and typical usage
					suffix=" (BLE) Phone"
					;;
				companionUsb)
					# Show USB and typical usage
					suffix=" (USB) Computer"
					;;
				# repeater / roomServer do not need extra suffix
			esac
			LABELS[i]="${TITLES[i]}${suffix}"
			[[ -n "${SUBTITLES[i]}" ]] && LABELS[i]+=" - ${SUBTITLES[i]}"
		done

		if ((${#ROLES[@]} == 1)); then
			ROLE="${ROLES[0]}"
			TITLE="${TITLES[0]}"
			SUBTITLE="${SUBTITLES[0]}"
			echo "Auto-selected role: $ROLE (${LABELS[0]})"
		else
			while [[ -z $ROLE ]]; do
				sleep 0.1
				echo
				echo "[2] Select role for $DEVICE:"

				# Show LABELS (title + BLE/USB), map back to ROLES/TITLES
				local COLUMNS=1
				select choice in "${LABELS[@]}"; do
					[[ -n ${choice:-} ]] || { echo "Invalid selection"; continue; }
					ROLE="${ROLES[REPLY-1]}"
					TITLE="${TITLES[REPLY-1]}"
					SUBTITLE="${SUBTITLES[REPLY-1]}"
					echo "Selected role: $ROLE ($choice)"
					break
				done < /dev/tty
			done
		fi

		fi
	
	# ---------------- step 4 - version ------------------------------------
	if [[ -z "$VERSION" ]]; then
			local -a VERSIONS=()
			mapfile -t VERSIONS < <(
				# shellcheck disable=SC2016
				_jq1 --arg d "$DEVICE" --arg r "$ROLE" --arg title "$TITLE" --arg subtitle "$SUBTITLE" '.device[] | select(.name == $d) | .firmware[] | select(.role == $r) | select((.title // "") == $title) | select((.subTitle // "") == $subtitle) | .version | keys[]' | sort -ru
			)
		if ((${#VERSIONS[@]} == 0)); then
			choose_version_from_releases "$DEVICE" "$ROLE" "$ARCHITECTURE" "$ERASE_URL" "$TITLE"
			return
		fi
		if ((${#VERSIONS[@]} == 1)); then
			VERSION="${VERSIONS[0]}"
			echo "Auto-selected version: $VERSION"
		else
			# Keep only newest two branches (X.Y)
			local -a VERSIONS_SHOW=()
			filter_last_two_branches VERSIONS VERSIONS_SHOW

			if [[ -z "$VERSION" ]]; then
				while [[ -z $VERSION ]]; do
					sleep 0.1
					echo
					echo "[3] Select version:"
					local COLUMNS=1
					select VERSION in "${VERSIONS_SHOW[@]}"; do
						[[ -n ${VERSION:-} ]] && break
					done < /dev/tty
				done
			fi
		fi
	fi


	    # ---------------- step 5 - type ---------------------------------------
		if [[ "$DEVICE" != "CustomFirmware" ]]; then
			# shellcheck disable=SC2016
			_jq1 --arg d "$DEVICE" --arg r "$ROLE" --arg title "$TITLE" --arg subtitle "$SUBTITLE" --arg v "$VERSION" '.device[] | select(.name == $d) | .firmware[] | select(.role == $r) | select((.title // "") == $title) | select((.subTitle // "") == $subtitle) | .version[$v].files[]'
		fi
	
    if [[ -z "$TYPE" ]]; then
	        local -a TYPES=()
	        mapfile -t TYPES < <(
	            # shellcheck disable=SC2016
	            _jq1 --arg d "$DEVICE" --arg r "$ROLE" --arg title "$TITLE" --arg subtitle "$SUBTITLE" --arg v "$VERSION" '.device[] | select(.name == $d) | .firmware[] | select(.role == $r) | select((.title // "") == $title) | select((.subTitle // "") == $subtitle) | .version[$v].files[] | .type' | sort -u
	        )

        if ((${#TYPES[@]} == 0)); then
            echo "ERROR: no file types found for $DEVICE / $ROLE / $VERSION" >&2
            return 1
        fi

        if ((${#TYPES[@]} == 1)); then
            TYPE="${TYPES[0]}"
            echo "Auto-selected type: $TYPE"
        elif ((${#TYPES[@]} == 2)) \
             && [[ " ${TYPES[*]} " == *" flash "* ]] \
             && [[ " ${TYPES[*]} " == *" download "* ]]; then
            TYPE="flash"
            echo "Auto-selected type: flash"
        else
            while [[ -z $TYPE ]]; do
                sleep 0.1
                echo
                echo "[4] Select type:"
                local COLUMNS=1
                select TYPE in "${TYPES[@]}"; do
                    [[ -n ${TYPE:-} ]] && break
                done < /dev/tty
            done
        fi
    fi

    # ---------------- step 6 - filename -----------------------------------
	    if [[ -z "$CHOSEN_FILE" ]]; then
	        CHOSEN_FILE=$(
	            # shellcheck disable=SC2016
	            _jq1 --arg d "$DEVICE" --arg r "$ROLE" --arg title "$TITLE" --arg subtitle "$SUBTITLE" --arg v "$VERSION" --arg t "$TYPE" '.device[] | select(.name == $d) | .firmware[] | select(.role == $r) | select((.title // "") == $title) | select((.subTitle // "") == $subtitle) | .version[$v].files[] | select(.type == $t) | (.url // .name) '
	        )
		if [[ "$CHOSEN_FILE" =~ ^https?:// || "$CHOSEN_FILE" == /* || "$CHOSEN_FILE" == firmware/* ]]; then
			echo "$CHOSEN_FILE" > "$SELECTED_URL_FILE"
		else
			echo "firmware/$CHOSEN_FILE" > "$SELECTED_URL_FILE"
		fi
    else
        echo "$CHOSEN_FILE" > "$SELECTED_URL_FILE"
    fi

    echo "$DEVICE"        > "$SELECTED_DEVICE_FILE"
    echo "$ARCHITECTURE"  > "$ARCHITECTURE_FILE"
    echo "$ERASE_URL"     > "$ERASE_URL_FILE"
	echo "$ROLE"          > "$SELECTED_ROLE_FILE"
	echo "$TITLE"         > "$SELECTED_TITLE_FILE"
	echo "$SUBTITLE"      > "$SELECTED_SUBTITLE_FILE"
    echo "$VERSION"       > "$SELECTED_VERSION_FILE"
    echo "$TYPE"          > "$SELECTED_TYPE_FILE"
	echo ">>>"
	if [[ "$CHOSEN_FILE" == file:///* ]]; then
		CHOSEN_FILE="${CHOSEN_FILE#file://}"
	fi
	if [[ "$CHOSEN_FILE" == /* && -f "$CHOSEN_FILE" ]]; then
		printf '%s\n' "$CHOSEN_FILE"
	elif [[ "$CHOSEN_FILE" =~ ^https?:// || "$CHOSEN_FILE" == firmware/* ]]; then
		printf '%s\n' "$CHOSEN_FILE"
	else
		printf 'firmware/%s\n' "$CHOSEN_FILE"
	fi
	echo "<<<"
}

download_and_verify() {
    local url=$1
	local dest_file=$2
	local verify=$3
	local dl_type=$4
	
	if [[ -z "$url" ]]; then
		echo "ERROR: empty $dl_type URL passed to download_and_verify. Try again after running" >&2
		echo "rm -rf $DOWNLOAD_DIR" >&2
		return 1
	fi

	next_non_overwrite_path_keep_ext() {
		local path="$1"
		local dir file stem ext candidate n

		if [[ ! -e "$path" ]]; then
			printf '%s' "$path"
			return 0
		fi

		dir="$(dirname -- "$path")"
		file="$(basename -- "$path")"

		if [[ "$file" == *.* && "$file" != .* ]]; then
			stem="${file%.*}"
			ext=".${file##*.}"
		else
			stem="$file"
			ext=""
		fi

		n=1
		while :; do
			candidate="${dir}/${stem}.${n}${ext}"
			if [[ ! -e "$candidate" ]]; then
				printf '%s' "$candidate"
				return 0
			fi
			((n++))
		done
	}
	
	local VERSION
	[[ -f "$SELECTED_VERSION_FILE" ]] && VERSION="$(<"$SELECTED_VERSION_FILE")"
	local version_lc="${VERSION,,}"
	local bytes
	local basename
	basename=${url##*/}           # -> file.tar.gz?version=3
	basename=${basename%%[\?#]*}  # -> file.tar.gz   (removes ?version=3 or #fragment)
	local dest="${DOWNLOAD_DIR}/${VERSION}/${basename}"
	mkdir -p "${DOWNLOAD_DIR}/${VERSION}/"

	if [[ "$version_lc" == "custom" && -e "$dest" ]]; then
		dest="$(next_non_overwrite_path_keep_ext "$dest")"
	fi
	
	MIN_BYTES_LOCAL=$MIN_BYTES               # default
    if [[ $verify -eq 0 ]]; then
        MIN_BYTES_LOCAL=$((25*1024))         # 25 kB == 25*1024 bytes
    fi

	if [[ -f "$dest" ]]; then
	    bytes=$(stat -c%s "$dest" 2>/dev/null);
		if (( bytes < MIN_BYTES_LOCAL )); then
			rm -f "$dest"
		fi
	fi

	if [[ ! -f "$dest" ]]; then
		echo "Downloading $url to $dest"
		wget -q --retry-connrefused --waitretry=1 -O "$dest" "$url" || return 1

		bytes=$(stat -c%s "$dest" 2>/dev/null);
		if (( bytes < MIN_BYTES_LOCAL )); then
			echo "Download too small ($bytes bytes < $MIN_BYTES_LOCAL); removing $dest" >&2
			rm -f "$dest"
			return 1
		fi

		echo "Downloaded $dest - $bytes bytes OK"
	else
		bytes=$(stat -c%s "$dest" 2>/dev/null);
		echo "Already downloaded $dest - $bytes bytes OK"
	fi

    echo "$dest" > "$dest_file"
}

choose_erase_zip() {
  local tty="/dev/tty"

  declare -A seen=()
  local -a dev=() erase=()
  local dn ez key

  while IFS=$'\t' read -r dn ez; do
    [[ -n "$dn" && -n "$ez" ]] || continue
    key="$dn"$'\t'"$ez"
    [[ -n "${seen[$key]+x}" ]] && continue
    seen[$key]=1
    dev+=("$dn")
    erase+=("$ez")
  done < <(_jq1 '.device[] | select(.erase? and .erase != "") | [.name, .erase] | @tsv')

  local n=${#dev[@]}
  (( n > 0 )) || { echo "No devices with .erase found" >&2; return 1; }

  {
    echo "Select erase package:"
    local i
    for i in "${!dev[@]}"; do
      printf '%3d) %-40s %s\n' "$((i+1))" "${dev[$i]}" "${erase[$i]}"
    done
  } >"$tty"

  local choice
  while true; do
    printf "Enter number (or q): " >"$tty"
    IFS= read -r choice <"$tty" || return 1

    [[ "$choice" == "q" || "$choice" == "Q" ]] && return 1
    [[ "$choice" =~ ^[0-9]+$ ]] || { echo "Not a number." >"$tty"; continue; }
    (( choice >= 1 && choice <= n )) || { echo "Out of range (1-$n)." >"$tty"; continue; }

    # ONLY the selected value goes to stdout:
    printf '%s\n' "${erase[$((choice-1))]}"
    return 0
  done
}

clean_node_info_field() {
	local value="${1:-}"
	value="$(printf '%s' "$value" | tr '\r' '\n' | sed -n '/./p' | tail -n1)"
	value="$(printf '%s' "$value" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"
	shopt -s nocasematch
	case "$value" in
		""|"unknown command"|"error"|"unsupported command")
			value=""
			;;
	esac
	shopt -u nocasematch
	printf '%s' "$value"
}

format_node_info_summary() {
	local label="$1" board="$2" version="$3" summary=""
	summary="$label"
	[[ -n "$board" ]] && summary+=" $board"
	[[ -n "$version" ]] && summary+=" $version"
	printf '%s' "$summary"
}

quick_node_info_cmd() {
	local device="$1"
	shift
	SERIAL_RETRIES=1 \
	SERIAL_RETRY_DELAY=0.02 \
	SERIAL_TOTAL_TIMEOUT="${SERIAL_INFO_TOTAL_TIMEOUT:-1.2s}" \
	SERIAL_IDLE_TIMEOUT="${SERIAL_INFO_IDLE_TIMEOUT:-0.35}" \
	SERIAL_FIRST_CANDIDATE_ONLY=1 \
		serial_cmd "$device" "$@"
}

read_board_with_retry() {
	local device="$1"
	local board=""
	local attempt

	for attempt in 1 2; do
		board=$(clean_node_info_field "$(quick_node_info_cmd "${device}" "board")")
		[[ -n "$board" ]] && break
		sleep 0.1
	done

	printf '%s' "$board"
}

query_companion_board_model() {
	local device="$1"
	local total_timeout="${SERIAL_INFO_TOTAL_TIMEOUT:-1.2s}"
	local idle_timeout="${SERIAL_INFO_IDLE_TIMEOUT:-0.35}"

	[[ -e "$device" ]] || return 1
	ensure_command socat || return 1
	ensure_command perl || return 1

	# The positional parameters and shell variables expand in the child shell.
	# shellcheck disable=SC2016
	timeout -s KILL "$total_timeout" \
		bash -o pipefail -c '
			device=$1
			idle=$2
			printf "\x3c\x02\x00\x16\x03" \
				| socat -T "$idle" - "OPEN:${device},raw,echo=0,b115200" 2>/dev/null
		' _ "$device" "$idle_timeout" \
		| LC_ALL=C perl -0777 -ne '
			my $buf = $_;
			my $pos = 0;
			while (($pos = index($buf, ">", $pos)) >= 0) {
				last if $pos + 3 > length($buf);
				my $len = unpack("v", substr($buf, $pos + 1, 2));
				my $end = $pos + 3 + $len;
				if ($len >= 60 && $len <= 300 && $end <= length($buf)) {
					my $payload = substr($buf, $pos + 3, $len);
					if (ord(substr($payload, 0, 1)) == 13) {
						my $model = substr($payload, 20, 40);
						$model =~ s/\x00.*//s;
						$model =~ s/^\s+|\s+$//g;
						print $model;
						exit;
					}
				}
				$pos++;
			}
		'
}

rak_board_family_from_text() {
	local text="${1:-}"
	local has_3401=0
	local has_4631=0

	if LC_ALL=C grep -Eqi 'rak[[:space:]_-]*3401' <<< "$text"; then
		has_3401=1
	fi
	if LC_ALL=C grep -Eqi 'rak[[:space:]_-]*4631|wismesh[[:space:]_-]*tag' <<< "$text"; then
		has_4631=1
	fi

	if (( has_3401 && has_4631 )); then
		printf '%s' "ambiguous"
	elif (( has_3401 )); then
		printf '%s' "rak3401"
	elif (( has_4631 )); then
		printf '%s' "rak4631"
	fi
}

rak_board_family_label() {
	case "${1:-unknown}" in
		rak3401) printf '%s' "RAK3401" ;;
		rak4631) printf '%s' "RAK4631 / WisMesh Tag" ;;
		ambiguous) printf '%s' "ambiguous RAK3401/RAK4631 identity" ;;
		*) printf '%s' "unknown" ;;
	esac
}

nrf52_firmware_rak_family() {
	local firmware_file="$1"
	local name_lc="${firmware_file,,}"
	local identity_text=""
	local identity_pattern='^(WisCore[ _-]+RAK[ _-]*(3401|4631)([ _-]+Board)?|RAK[[:space:]]+(3401|4631)|RAK(3401|4631)_OTA|RAK[[:space:]]+WisMesh[[:space:]]+Tag|WISMESHTAG_OTA)[[:space:]]*$'

	[[ -r "$firmware_file" ]] || return 1
	ensure_command strings binutils || return 1
	if [[ "$name_lc" == *.zip ]]; then
		ensure_command unzip || return 1
		identity_text="$({
			unzip -p -- "$firmware_file" 2>/dev/null \
				| LC_ALL=C strings -a \
				| LC_ALL=C grep -Eai "$identity_pattern" \
				|| true
		})"
	else
		identity_text="$({
			LC_ALL=C strings -a -- "$firmware_file" 2>/dev/null \
				| LC_ALL=C grep -Eai "$identity_pattern" \
				|| true
		})"
	fi

	rak_board_family_from_text "$identity_text"
}

nrf52_board_override_token() {
	local firmware_family="${1:-unknown}"
	local device_family="${2:-unknown}"

	[[ -n "$firmware_family" ]] || firmware_family="unknown"
	[[ -n "$device_family" ]] || device_family="unknown"
	printf '%s-to-%s' "$firmware_family" "$device_family"
}

nrf52_confirm_board_override() {
	local firmware_family="${1:-unknown}"
	local device_family="${2:-unknown}"
	local reason="${3:-Board identity could not be verified.}"
	local tty="${MCFIRMWARE_BOARD_GUARD_TTY:-/dev/tty}"
	local required_token configured_token answer

	required_token="$(nrf52_board_override_token "$firmware_family" "$device_family")"
	configured_token="${MCFIRMWARE_BOARD_OVERRIDE:-}"
	configured_token="${configured_token,,}"

	echo "nRF52 board safety check stopped automatic flashing." >&2
	echo "  $reason" >&2
	echo "  Firmware payload: $(rak_board_family_label "$firmware_family")" >&2
	echo "  Connected device: $(rak_board_family_label "$device_family")" >&2
	echo "  Safe default: cancel before erase or DFU." >&2

	if [[ -n "$configured_token" ]]; then
		if [[ "$configured_token" == "$required_token" ]]; then
			echo "  Explicit board override accepted: $required_token" >&2
			return 0
		fi
		echo "  MCFIRMWARE_BOARD_OVERRIDE did not match the required token." >&2
		echo "  Required token: $required_token" >&2
		return 1
	fi

	if [[ ! -r "$tty" || ! -w "$tty" ]]; then
		echo "  No interactive terminal is available." >&2
		echo "  To override deliberately, rerun with:" >&2
		echo "    MCFIRMWARE_BOARD_OVERRIDE=$required_token ./mcfirmware.sh" >&2
		return 1
	fi

	{
		echo "To override this check once, type the exact token shown below."
		echo "Anything else, including Enter, cancels."
		printf 'Override token (%s): ' "$required_token"
	} >"$tty"
	IFS= read -r answer <"$tty" || answer=""
	answer="${answer,,}"
	if [[ "$answer" == "$required_token" ]]; then
		echo "Explicit one-time board override accepted: $required_token" >&2
		return 0
	fi

	echo "Board override was not confirmed; no erase or DFU command was run." >&2
	return 1
}

nrf52_validate_rak_board_pair() {
	local firmware_file="$1"
	local device_port="$2"
	local selected_device="${3:-}"
	local embedded_family=""
	local selection_family=""
	local device_family=""
	local board_family=""
	local usb_family=""
	local reported_board=""
	local usb_identity=""

	embedded_family="$(nrf52_firmware_rak_family "$firmware_file" || true)"
	selection_family="$(rak_board_family_from_text "$selected_device ${firmware_file##*/}")"
	reported_board="$(read_board_with_retry "$device_port" 2>/dev/null || true)"
	if [[ -z "$reported_board" ]]; then
		reported_board="$(query_companion_board_model "$device_port" 2>/dev/null || true)"
	fi
	usb_identity="$(udev_device_property "$device_port" ID_MODEL) \
$(udev_device_property "$device_port" ID_SERIAL) \
$(udev_device_property "$device_port" ID_SERIAL_SHORT)"
	if [[ -s "${DEVICE_PORT_NAME_FILE:-}" ]]; then
		usb_identity+=" $(<"$DEVICE_PORT_NAME_FILE")"
	fi
	board_family="$(rak_board_family_from_text "$reported_board")"
	usb_family="$(rak_board_family_from_text "$usb_identity")"

	if [[ -n "$board_family" && -n "$usb_family" && "$board_family" != "$usb_family" ]]; then
		device_family="ambiguous"
	else
		device_family="${board_family:-$usb_family}"
	fi

	if [[ -n "$embedded_family" && -n "$selection_family" \
		&& "$embedded_family" != "$selection_family" ]]; then
		if nrf52_confirm_board_override "ambiguous" "${device_family:-unknown}" \
			"The embedded firmware target conflicts with its selected device or filename."; then
			return 0
		fi
		return 1
	fi

	if [[ -n "$embedded_family" && -n "$device_family" \
		&& "$embedded_family" == "$device_family" \
		&& "$embedded_family" != "ambiguous" ]]; then
		echo "Board safety check: $(rak_board_family_label "$embedded_family") firmware matches the connected $(rak_board_family_label "$device_family")."
		[[ -n "$reported_board" ]] && echo "  Node reports: $reported_board"
		return 0
	fi

	if [[ -z "$embedded_family" && -z "$selection_family" && -z "$device_family" ]]; then
		return 0
	fi

	if [[ -z "$embedded_family" && -n "$selection_family" ]]; then
		if nrf52_confirm_board_override "$selection_family" "${device_family:-unknown}" \
			"The filename suggests a RAK target, but the firmware payload does not prove it."; then
			return 0
		fi
		return 1
	fi

	if [[ -z "$embedded_family" ]]; then
		if nrf52_confirm_board_override "unknown" "${device_family:-unknown}" \
			"The connected node is a protected RAK target, but the firmware payload target is unknown."; then
			return 0
		fi
		return 1
	fi

	if [[ -z "$device_family" ]]; then
		if nrf52_confirm_board_override "$embedded_family" "unknown" \
			"The firmware is for a protected RAK target, but the connected board identity is unknown."; then
			return 0
		fi
		return 1
	fi

	if nrf52_confirm_board_override "$embedded_family" "$device_family" \
		"The firmware target does not match the connected board target."; then
		return 0
	fi
	return 1
}

choose_serial() {
	local detected_dev
	local devs labels               # arrays that hold paths and friendly names
	local choice

    scan() {                        # fill devs[] / labels[]
        local flash_link detected_path
        local by_id_dir="${NRF52_SERIAL_BY_ID_DIR:-/dev/serial/by-id}"
        local -A seen_paths=()
        devs=()  labels=()
        shopt -s nullglob           # make the glob expand to nothing if empty
        for link in "${by_id_dir}"/*; do
			flash_link="$(preferred_flash_serial_link "$link")"
			detected_path="$(readlink -f "$flash_link" 2>/dev/null || true)"
			[[ -n "$detected_path" && -e "$detected_path" ]] || continue
			[[ -z "${seen_paths[$detected_path]+x}" ]] || continue
			seen_paths["$detected_path"]=1
			devs+=( "$detected_path" )
			labels+=( "$(basename "$flash_link")" )
        done
        shopt -u nullglob
    }

    while :; do
        scan

        # -------------------------- nothing found --------------------------
        if ((${#devs[@]} == 0)); then
            echo "No serial devices found under ${NRF52_SERIAL_BY_ID_DIR:-/dev/serial/by-id}."
            read -rp "Try again? [y/N] " yn
            [[ $yn =~ ^[Yy]$ ]] || return 1         # give up
            continue                                # rescan
        fi

        # -------------------------- single device --------------------------
        if ((${#devs[@]} == 1)); then
			detected_dev="${devs[0]}"
			echo "Trying to get meshcore info from the node"
			board=$(read_board_with_retry "${detected_dev}")
			version=$(clean_node_info_field "$(quick_node_info_cmd "${detected_dev}" "ver")")
            echo "Only one device detected - selecting it automatically: $detected_dev - $(format_node_info_summary "${labels[0]}" "$board" "$version")"
			echo "$detected_dev" > "$DEVICE_PORT_FILE"
			echo "${labels[0]}" > "$DEVICE_PORT_NAME_FILE"
			return
        fi

        # -------------------------- menu --------------------------
        echo "Select a serial device:"
        for i in "${!devs[@]}"; do
			board=$(read_board_with_retry "${devs[$i]}")
			version=$(clean_node_info_field "$(quick_node_info_cmd "${devs[$i]}" "ver")")
            printf " %2d) %s  (%s)\n" $((i+1)) "${devs[$i]}" "$(format_node_info_summary "${labels[$i]}" "$board" "$version")"
        done
        echo "  0)  Scan again"

        read -rp "Choice: " choice
        if [[ $choice =~ ^[0-9]+$ ]]; then
            if (( choice == 0 ));     then continue          # rescan
            elif (( choice >= 1 && choice <= ${#devs[@]} )); then
				detected_dev="${devs[choice-1]}"
				echo "$detected_dev"
				echo "$detected_dev" > "$DEVICE_PORT_FILE"
				echo "${labels[choice-1]}" > "$DEVICE_PORT_NAME_FILE"
				return
            fi
        fi
        echo "Invalid selection - please try again."
    done
}

check_tty_lock() {
    local device_path="$1"
    local lock=""
    lock="/var/lock/$(basename "$device_path").lock"

    # open FD 3 on the lock file for the lifetime of this shell
    exec 3>"$lock" || return 1
    # try to acquire non-blocking lock
    if ! flock -n 3; then
        # still locked by someone else
        exec 3>&-
        return 0
    fi
    # we own the lock; release immediately and close FD
    flock -u 3
    exec 3>&-
    # not locked by others
    return 1
}

service_from_pid() {
	local pid="$1"
	local cgroup_part

	[[ -r "/proc/$pid/cgroup" ]] || return 0

	while IFS=/ read -ra cgroup_part; do
		for part in "${cgroup_part[@]}"; do
			if [[ "$part" == *.service && "$part" != user@*.service ]]; then
				printf '%s\n' "$part"
				return 0
			fi
		done
	done < "/proc/$pid/cgroup"
}

serial_lock_pids() {
	local device_name="$1"

	[[ -n "$device_name" && -e "$device_name" ]] || return 0

	ensure_command lsof
	if no_sudo_mode; then
		lsof -t "$device_name" 2>/dev/null | sort -u
	else
		sudo lsof -t "$device_name" 2>/dev/null | sort -u
	fi
}

get_locked_service() {
    local device_name="${1:-}"
    [[ -z "$device_name" && -f "$DEVICE_PORT_FILE" ]] && device_name="$(<"$DEVICE_PORT_FILE")"

    if [[ -z "$device_name" ]]; then
        # nothing to check yet
        return 0
    fi

    if [[ ! -e "$device_name" ]]; then
        echo "Serial port ${device_name} is not present." > /dev/tty
        return 0
    fi

	# Get all users locking the device (skip the header line)
	echo "Finding the process that has $device_name locked" > /dev/tty
	local -a pids=()
	mapfile -t pids < <(serial_lock_pids "$device_name")
	if ((${#pids[@]} == 0)); then
		if check_tty_lock "$device_name"; then
			echo "A UUCP-style lock exists for ${device_name}, but no open process was found." > /dev/tty
		else
			echo "No process found locking ${device_name}." > /dev/tty
		fi
		return 0
	fi

	local -a found_services=()
	local pid
	for pid in "${pids[@]}"; do
		echo "PID: $pid" > /dev/tty

		# Get the full command line for the process.
		local cmd
		cmd=$(ps -p "$pid" -o cmd= 2>/dev/null | awk '{$1=$1};1')
		echo "Command: ${cmd:-unknown}" > /dev/tty

		local service
		service="$(service_from_pid "$pid")"
		if [ -n "$service" ]; then
			found_services+=("$service")
		else
			service="None"
		fi
		echo "Service: $service"  > /dev/tty
	done

	if ((${#found_services[@]})); then
		printf '%s\n' "${found_services[@]}" | sort -u | xargs
	fi
}

record_locked_service() {
	local service="$1"

	[[ -n "$service" && "$service" != "None" ]] || return 0
	if [[ " ${LOCKEDSERVICE:-} " != *" $service "* ]]; then
		LOCKEDSERVICE="${LOCKEDSERVICE:+$LOCKEDSERVICE }$service"
	fi
}

stop_serial_locking_services() {
	local port="$1"
	local services=""
	local -a service_list=()
	local service

	services="$(get_locked_service "$port" || true)"
	[[ -n "$services" && "$services" != "None" ]] || return 1

	read -r -a service_list <<< "$services"
	((${#service_list[@]})) || return 1
	if no_sudo_mode; then
		echo "No-sudo mode found locking service(s) on $port: $services; stop them explicitly first." >&2
		return 1
	fi

	echo "Stopping service $services..."
	if ! sudo systemctl stop "${service_list[@]}"; then
		return 1
	fi
	for service in "${service_list[@]}"; do
		record_locked_service "$service"
	done
	sleep 3
	return 0
}

terminate_serial_locking_processes() {
	local port="$1"
	local pid service cmd owner choice
	local -a pids=()
	local -a process_pids=()
	local -a remaining_pids=()

	mapfile -t pids < <(serial_lock_pids "$port")
	((${#pids[@]})) || return 1

	for pid in "${pids[@]}"; do
		service="$(service_from_pid "$pid")"
		[[ -z "$service" ]] || continue
		[[ "$pid" != "$$" && "$pid" != "$BASHPID" && "$pid" != "$PPID" ]] || continue
		process_pids+=("$pid")
	done

	((${#process_pids[@]})) || return 1
	if no_sudo_mode; then
		echo "No-sudo mode found a process holding $port; close it explicitly before flashing." >&2
		return 1
	fi

	echo "The following non-service process(es) are holding ${port}:" > /dev/tty
	for pid in "${process_pids[@]}"; do
		owner=$(ps -p "$pid" -o user= 2>/dev/null | awk '{$1=$1};1')
		cmd=$(ps -p "$pid" -o cmd= 2>/dev/null | awk '{$1=$1};1')
		echo "  PID ${pid} (${owner:-unknown}): ${cmd:-unknown}" > /dev/tty
	done

	read -r -p "Terminate these process(es) so flashing can continue? [y/N]: " choice < /dev/tty
	case "$choice" in
		y|Y|yes|YES)
			;;
		*)
			return 1
			;;
	esac

	sudo kill -TERM -- "${process_pids[@]}" 2>/dev/null || true
	for _ in {1..20}; do
		mapfile -t remaining_pids < <(serial_lock_pids "$port")
		((${#remaining_pids[@]} == 0)) && return 0
		sleep 0.25
	done

	echo "Process(es) still hold ${port}; forcing termination..." > /dev/tty
	sudo kill -KILL -- "${process_pids[@]}" 2>/dev/null || true
	sleep 1
	mapfile -t remaining_pids < <(serial_lock_pids "$port")
	((${#remaining_pids[@]} == 0))
}


esptool_set_variables() {

	echo "Checking the esptool version"
	ver="$( pipx run esptool version | grep -m1 -Eo '[0-9]+(\.[0-9]+)+' )"
	major="${ver%%.*}"
	
	if [[ "$major" =~ ^[0-9]+$ ]] && (( major >= 5 )); then
	  # X: esptool >= 5
	  NORESET="no-reset"
	  USBRESET="usb-reset"
	  READMAC="read-mac"
	  READFLASH="read-flash"
	  WRITEFLASH="write-flash"
	  ERASEFLASH="erase-flash"
	  HARDRESET="hard-reset"
	  WATCHDOGRESET="watchdog-reset"
	else
	  NORESET="no_reset"
	  USBRESET="usb_reset"
	  READMAC="read_mac"
	  READFLASH="read_flash"
	  WRITEFLASH="write_flash"
	  ERASEFLASH="erase_flash"
	  HARDRESET="hard_reset"
	  WATCHDOGRESET="watchdog_reset"
	fi

}

# esptool opens Linux serial ports before it applies --before=no-reset. On a
# native ESP32-S3 USB/JTAG CDC port, pySerial's default DTR/RTS=True state can
# therefore reset the chip before esptool has selected its requested reset
# strategy. Besides selecting the wrong boot mode, that reset can also drop a
# host powered through the attached device. Pre-open every local serial port
# with both active-low control lines idle and disable HUPCL; esptool still owns
# all intentional reset transitions after the safe open.
esptool_safe_serial_bootstrap() {
	command cat <<'PY'
import sys
import termios

import serial


_serial_for_url = serial.serial_for_url


def safe_serial_for_url(*args, **kwargs):
    open_immediately = not kwargs.get("do_not_open", False)
    kwargs["do_not_open"] = True
    port = _serial_for_url(*args, **kwargs)
    port.rts = False
    port.dtr = False
    original_open = port.open

    def safe_open():
        # pySerial applies these cached states as part of open(). Set them
        # before every reopen because an esptool reset strategy may have
        # changed them during a previous connection attempt.
        port.rts = False
        port.dtr = False
        original_open()
        try:
            attributes = termios.tcgetattr(port.fileno())
            attributes[2] &= ~termios.HUPCL
            termios.tcsetattr(port.fileno(), termios.TCSANOW, attributes)
        except (AttributeError, OSError, ValueError, termios.error):
            # RFC2217/socket transports and a few USB drivers do not expose
            # termios state. The pre-open DTR/RTS protection still applies.
            pass

    port.open = safe_open
    if open_immediately:
        port.open()
    return port


serial.serial_for_url = safe_serial_for_url

import esptool  # noqa: E402 (import only after installing the serial guard)

esptool.main(sys.argv[1:])
PY
}

esptool_port_argument() {
	local arg
	while (($#)); do
		arg=$1
		case "$arg" in
			--port|-p)
				(($# >= 2)) || return 1
				printf '%s\n' "$2"
				return 0
				;;
			--port=*)
				printf '%s\n' "${arg#--port=}"
				return 0
				;;
		esac
		shift
	done
	return 1
}

configure_esptool_invocation() {
	local port="" bootstrap=""
	port="$(esptool_port_argument "$@" 2>/dev/null || true)"
	ESPTOOL_INVOKE_COMMAND=(pipx run esptool)

	# Image inspection and version checks have no serial port and need no guard.
	# Restrict the bootstrap to local device paths so socket/RFC2217 behavior is
	# unchanged.
	if [[ "$port" == /dev/* ]]; then
		bootstrap="$(esptool_safe_serial_bootstrap)"
		ESPTOOL_INVOKE_COMMAND=(
			pipx run --quiet --spec esptool python -c "$bootstrap"
		)
	fi
}

invoke_esptool() {
	configure_esptool_invocation "$@"
	"${ESPTOOL_INVOKE_COMMAND[@]}" "$@"
}

invoke_esptool_timeout() {
	local duration=$1
	shift
	configure_esptool_invocation "$@"
	command timeout "$duration" "${ESPTOOL_INVOKE_COMMAND[@]}" "$@"
}

get_espcmd() {
	[[ -f "$ESPTOOL_FILE"     ]] && ESPTOOL_CMD="$(<"$ESPTOOL_FILE")"

	# Locate a Python interpreter.
	PYTHON=""
	for candidate in python3 python; do
		if command -v "$candidate" >/dev/null 2>&1; then
			PYTHON=$(command -v "$candidate")
			break
		fi
	done
	if [ -z "$PYTHON" ]; then
		echo "No Python interpreter found. Installing python3..."
		install_packages python3
		install_packages pipx
		PYTHON=$(command -v python3) || {
			echo "Failed to install python3"
			exit 1
		}
	fi

	# Ensure pipx & meshcore-cli are installed.
	ensure_command pip 
	ensure_command pipx

	esptool_set_variables
	ESPTOOL_CMD="pipx run esptool"

	#if sudo "$PYTHON" -m esptool version >/dev/null 2>&1; then
	#	ESPTOOL_CMD="$PYTHON -m esptool"
	#elif sudo env "PATH=$HOME/.local/bin:$PATH" command -v esptool >/dev/null 2>&1; then
	#	ESPTOOL_CMD="esptool"
	#elif sudo env "PATH=$HOME/.local/bin:$PATH" command -v esptool.py >/dev/null 2>&1; then
	#	ESPTOOL_CMD="esptool.py"
	#else
	#	pipx install esptool
	#	ESPTOOL_CMD="esptool.py"
	#	pipx ensurepath
	#	# shellcheck disable=SC1091
	#	source "$HOME/.bashrc"
	#fi

	echo "$ESPTOOL_CMD" > "$ESPTOOL_FILE"
}

print_esptool_recovery_hint() {
	local output="$1"
	if grep -qiE 'Failed to connect to Espressif device|Protocol error|No serial data received' <<<"$output"; then
		echo "Hint: Reboot the node, wait 10 seconds, and try again." >&2
	fi
}

esptool_output_needs_reset() {
	local output="$1"
	grep -qiE 'Failed to connect to Espressif device|Protocol error|No serial data received' <<<"$output"
}

esptool_output_port_busy() {
	local output="$1"
	grep -qiE 'Could not exclusively lock port|Resource temporarily unavailable|Device or resource busy|port is busy' <<<"$output"
}

recover_busy_serial_port() {
	local port="$1"

	echo "Serial port $port is busy; checking for locking services..."
	if stop_serial_locking_services "$port"; then
		return 0
	fi

	if terminate_serial_locking_processes "$port"; then
		return 0
	fi
	if no_sudo_mode; then
		echo "No-sudo mode refuses to continue while ${port} may still be busy." >&2
		return 1
	fi

	echo "No locking service was stopped; waiting briefly for ${port} to be released..."
	sleep 2
	return 0
}

auto_reset_serial_port() {
	local port="$1"
	[[ -z "$port" ]] && return 1
	if esp32_port_uses_native_usb "$port"; then
		echo "Skipping raw DTR/RTS recovery on native ESP32 USB port $port." >&2
		echo "The identity-safe application-to-ROM handoff must be retried instead." >&2
		return 1
	fi
	if no_sudo_mode; then
		echo "No-sudo mode cannot run the privileged ESP serial-reset fallback on $port." >&2
		return 1
	fi

	echo "Trying automatic serial reset on $port..."
	sudo chmod a+rw "$port" 2>/dev/null || true

	echo "Trying 1200-baud touch on $port..."
	sudo bash -lc "exec 3<> \"$port\"; stty -F \"$port\" 1200 hupcl; sleep 1; exec 3>&-; exec 3<&-" || true

	echo "Trying DTR/RTS toggle on $port..."
	sudo python3 -c '
import os, sys, fcntl, termios, struct, time
port = sys.argv[1]
TIOCM_DTR = getattr(termios, "TIOCM_DTR", 0x002)
TIOCM_RTS = getattr(termios, "TIOCM_RTS", 0x004)
TIOCMBIS = getattr(termios, "TIOCMBIS", 0x5416)
TIOCMBIC = getattr(termios, "TIOCMBIC", 0x5417)
try:
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
except OSError:
    sys.exit(1)
try:
    for flag in (TIOCM_DTR, TIOCM_RTS):
        fcntl.ioctl(fd, TIOCMBIC, struct.pack("I", flag))
    time.sleep(0.1)
    fcntl.ioctl(fd, TIOCMBIS, struct.pack("I", TIOCM_DTR))
    fcntl.ioctl(fd, TIOCMBIC, struct.pack("I", TIOCM_RTS))
    time.sleep(0.1)
    fcntl.ioctl(fd, TIOCMBIS, struct.pack("I", TIOCM_RTS))
    time.sleep(0.25)
except OSError:
    sys.exit(1)
finally:
    os.close(fd)
' "$port" || true

	echo "Waiting 10 seconds for device to reboot..."
	sleep 10
	return 0
}

manual_reboot_choice() {
	local port="$1" step="$2" choice
	echo
	echo "Manual recovery needed for ${step:-this step}."
	echo "To enter manual bootloader mode on many boards:"
	echo "  1) press and hold BOOT (sometimes labeled PRG or FLASH)"
	echo "  2) while holding BOOT, briefly press and release RESET/RST"
	echo "  3) keep holding BOOT for 1-2 seconds, then release it"
	echo "If the board has only two buttons, this is usually hold BOOT, tap RESET, release BOOT."
	echo "Reboot the node connected to ${port:-the serial port}, wait 10 seconds, then choose:"
	echo "  1) retry this step"
	echo "  2) move on"
	while :; do
		read -r -p "Recovery choice [1/2]: " choice < /dev/tty
		case "$choice" in
			1)
				echo "Retrying ${step:-step} after manual reboot..."
				sleep 10
				return 0
				;;
			2)
				echo "Moving on without retrying ${step:-this step}."
				return 1
				;;
			*)
				echo "Please enter 1 or 2."
				;;
		esac
	done
}

run_esptool() {
	local output status retry_output port="" tmpfile=""

	for ((i=1; i<=$#; i++)); do
		if [[ "${!i}" == "--port" ]] && (( i < $# )); then
			j=$((i + 1))
			port="${!j}"
			break
		fi
	done

	if tmpfile=$(mktemp); then
		if invoke_esptool "$@" 2>&1 | tee "$tmpfile"; then
			output="$(<"$tmpfile")"
			status=0
		else
			status=${PIPESTATUS[0]}
			output="$(<"$tmpfile")"
		fi
		rm -f "$tmpfile"
	else
		output=""
		status=1
	fi

	if [[ ${status:-0} -eq 0 ]]; then
		return 0
	fi

	if [[ -n "$port" ]] && esptool_output_port_busy "$output"; then
		if ! recover_busy_serial_port "$port"; then
			printf '%s\n' "$output" >&2
			return "$status"
		fi
		if tmpfile=$(mktemp); then
			if invoke_esptool "$@" 2>&1 | tee "$tmpfile"; then
				rm -f "$tmpfile"
				return 0
			fi
			status=${PIPESTATUS[0]}
			retry_output="$(<"$tmpfile")"
			rm -f "$tmpfile"
		else
			retry_output=""
			status=1
		fi
		output="$retry_output"
	fi

	if grep -qi "Permission denied" <<<"$output"; then
		if no_sudo_mode; then
			echo "No-sudo mode cannot change access to ${port:-the serial port}." >&2
			return "$status"
		fi
		echo "Granting access to ${port:-serial port} and retrying esptool..."
		if [[ -n "$port" ]]; then
			sudo chmod a+rw "$port"
		fi
		if tmpfile=$(mktemp); then
			if invoke_esptool "$@" 2>&1 | tee "$tmpfile"; then
				rm -f "$tmpfile"
				return 0
			fi
			status=${PIPESTATUS[0]}
			retry_output="$(<"$tmpfile")"
			rm -f "$tmpfile"
		else
			retry_output=""
			status=1
		fi
		if [[ ${status:-0} -eq 0 ]]; then
			return 0
		fi
		printf '%s\n' "$retry_output" >&2
		print_esptool_recovery_hint "$retry_output"
		return "$status"
	fi

	if [[ -n "$port" ]] && esptool_output_needs_reset "$output"; then
		if auto_reset_serial_port "$port"; then
			if tmpfile=$(mktemp); then
				if invoke_esptool "$@" 2>&1 | tee "$tmpfile"; then
					rm -f "$tmpfile"
					return 0
				fi
				status=${PIPESTATUS[0]}
				retry_output="$(<"$tmpfile")"
				rm -f "$tmpfile"
			else
				retry_output=""
				status=1
			fi
			if [[ ${status:-0} -eq 0 ]]; then
				return 0
			fi
			if manual_reboot_choice "$port" "esptool command"; then
				if tmpfile=$(mktemp); then
					if invoke_esptool "$@" 2>&1 | tee "$tmpfile"; then
						rm -f "$tmpfile"
						return 0
					fi
					status=${PIPESTATUS[0]}
					retry_output="$(<"$tmpfile")"
					rm -f "$tmpfile"
				else
					retry_output=""
					status=1
				fi
				if [[ ${status:-0} -eq 0 ]]; then
					return 0
				fi
			fi
			printf '%s\n' "$retry_output" >&2
			print_esptool_recovery_hint "$retry_output"
			return "$status"
		fi
	fi

	printf '%s\n' "$output" >&2
	print_esptool_recovery_hint "$output"
	return "$status"
}

raw_esptool_mac_probe() {
	local output
	if ! output="$(invoke_esptool_timeout "${ESP32_PROBE_TIMEOUT_SECONDS:-8}s" \
		"$@" 2>&1)"; then
		return 1
	fi
	grep -qi -m1 'MAC' <<<"$output"
}

prepare_esp32_flash_session() {
	local port="$1"
	local device="$2"
	local preferred_port selected_by_id selected_live_port expected_serial expected_path_stem reset_port
	local original_instance bootloader_port candidate_port

	preferred_port="$(preferred_flash_serial_port "$port")"
	if [[ "$preferred_port" != "$port" ]]; then
		echo "Using primary Companion/flashing port $preferred_port instead of secondary logging port $port."
		port="$preferred_port"
	fi
	save_selected_serial_port "$port"

	BOOTLOADER_PROBE_PORT="$port"
	BOOTLOADER_PROBE_ACTIVE=1

	selected_by_id="$(serial_by_id_link_for_port "$port" 2>/dev/null || true)"
	expected_serial="$(udev_device_property "$port" ID_SERIAL_SHORT)"
	expected_path_stem="$(nrf52_usb_path_stem \
		"$(udev_device_property "$port" ID_PATH)")"
	original_instance="$(nrf52_port_instance "$port")"
	ESP32_FLASH_SELECTED_BY_ID="$selected_by_id"
	ESP32_FLASH_EXPECTED_SERIAL="$expected_serial"
	ESP32_FLASH_EXPECTED_PATH_STEM="$expected_path_stem"

	# Native-USB ESP32 applications, including both single-CDC firmware and Full
	# Companion's interface 00/02 pair, use esptool's USB-JTAG reset sequence to
	# enter the ROM. Some boards, including Heltec V4, ignore the nRF52-style
	# 1200-baud touch while --before=usb-reset works on the existing application
	# port. Prefer the selected by-id link so a tty-number change cannot redirect
	# the reset to another board. The ROM may retain the same tty or re-enumerate
	# with a different product name and serial punctuation; in either case, match
	# the captured physical USB identity before allowing any erase or write.
	if esp32_port_uses_native_usb "$port"; then
		if raw_esptool_mac_probe --port "$port" --before "$NORESET" \
			--after "$NORESET" --baud 115200 "$READMAC"; then
			echo "Selected ESP32 native USB port is already in ROM bootloader mode."
			rm -f "$DOWNLOAD_DIR/CURRENT.BAK"
			echo
			return 0
		fi

		reset_port="${selected_by_id:-$port}"
		if [[ -n "$selected_by_id" ]]; then
			selected_live_port="$(readlink -f "$selected_by_id" 2>/dev/null || true)"
			if [[ "$selected_live_port" != "$port" ]]; then
				echo "The selected ESP32 by-id link no longer resolves to $port; refusing to reset another USB device." >&2
				return 1
			fi
		fi
		echo "Setting device ${device} on ${port} into its ESP32 ROM bootloader with an identity-safe USB reset."
		if raw_esptool_mac_probe --port "$reset_port" --before "$USBRESET" \
			--after "$NORESET" --baud 115200 "$READMAC"; then
			# The successful esptool exchange proves that a reset occurred. Pass an
			# empty original instance so a V4 that keeps the same tty is accepted,
			# while the ordinary identity ranking still rejects a different board.
			if ! bootloader_port="$(wait_for_nrf52_bootloader_port "$port" \
				"$selected_by_id" "$expected_serial" "$expected_path_stem" \
				"" "ESP32 ROM serial port")"; then
				return 1
			fi
		else
			echo "The ESP32 USB reset did not answer; falling back to one 1200-baud touch on the same USB identity."
			# A timed-out USB-reset command may nevertheless have entered ROM. Find
			# only the captured identity and probe it before touching the port.
			candidate_port="$(find_reenumerated_nrf52_port "$port" \
				"$selected_by_id" "$expected_serial" "$expected_path_stem" \
				"$original_instance" 2>/dev/null || true)"
			if [[ -n "$candidate_port" ]] \
				&& raw_esptool_mac_probe --port "$candidate_port" --before "$NORESET" \
					--after "$NORESET" --baud 115200 "$READMAC"; then
				bootloader_port="$candidate_port"
			else
				[[ -n "$candidate_port" ]] || {
					echo "The selected ESP32 USB identity disappeared after the reset attempt; refusing to touch another serial port." >&2
					return 1
				}
				port="$candidate_port"
				original_instance="$(nrf52_port_instance "$port")"
				if ! trigger_nrf52_1200_touch "$port"; then
					echo "The primary CDC touch failed; checking for a service holding $port."
					stop_serial_locking_services "$port" || true
					trigger_nrf52_1200_touch "$port"
				fi
				if ! bootloader_port="$(wait_for_nrf52_bootloader_port "$port" \
					"$selected_by_id" "$expected_serial" "$expected_path_stem" \
					"$original_instance" "ESP32 ROM serial port")"; then
					return 1
				fi
			fi
		fi
		echo "Matched ESP32 ROM port: $bootloader_port"
		if ! raw_esptool_mac_probe --port "$bootloader_port" \
			--before "$NORESET" --after "$NORESET" --baud 115200 "$READMAC"; then
			echo "The matched ESP32 ROM port did not answer an identity probe." >&2
			return 1
		fi
		save_selected_serial_port "$bootloader_port"
		BOOTLOADER_PROBE_PORT="$bootloader_port"
		echo "ESP chip responded; skipping existing firmware backup."
		rm -f "$DOWNLOAD_DIR/CURRENT.BAK"
		echo
		return 0
	fi

	# A manually selected ROM port already answers without another reset.
	if raw_esptool_mac_probe --port "$port" --before "$NORESET" \
		--after "$NORESET" --baud 115200 "$READMAC"; then
		echo "ESP chip already responds in bootloader mode; skipping existing firmware backup."
		rm -f "$DOWNLOAD_DIR/CURRENT.BAK"
		echo
		return 0
	fi

	# UART-based ESP32 boards keep the same tty while esptool performs their
	# ordinary DTR/RTS reset sequence. Retain the established recovery flow for
	# those boards.
	echo "Setting device ${device} on ${port} into bootloader mode"
	echo "$ESPTOOL_CMD --port ${port} --after $NORESET --baud 1200 $READMAC"
	if probe_esptool_mac --port "$port" --after "$NORESET" \
		--baud 1200 "$READMAC"; then
		echo "ESP chip responded; skipping existing firmware backup."
		rm -f "$DOWNLOAD_DIR/CURRENT.BAK"
		echo
		return 0
	fi

	echo "ESP chip did not confirm bootloader mode; refusing to flash a stale or ambiguous serial port." >&2
	rm -f "$DOWNLOAD_DIR/CURRENT.BAK"
	return 1
}

finish_esp32_flash_session() {
	local port="${1:-${DEVICE_PORT:-}}"
	local rom_instance runtime_port

	[[ -n "$port" && -e "$port" ]] || return 0
	if ! esp32_port_is_rom_usb_jtag "$port"; then
		return 0
	fi

	rom_instance="$(nrf52_port_instance "$port")"
	echo "ESP32-S3 ROM port is still active; safely hard-resetting into the application."
	if ! invoke_esptool_timeout "${ESP32_PROBE_TIMEOUT_SECONDS:-12}s" \
		--port "$port" --before "$NORESET" --after "$HARDRESET" "$READMAC"; then
		echo "Warning: the ESP32-S3 safe hard reset failed; press RESET once to start the application." >&2
		return 1
	fi

	if runtime_port="$(wait_for_nrf52_bootloader_port "$port" \
		"${ESP32_FLASH_SELECTED_BY_ID:-}" \
		"${ESP32_FLASH_EXPECTED_SERIAL:-}" \
		"${ESP32_FLASH_EXPECTED_PATH_STEM:-}" "$rom_instance" \
		"ESP32 runtime primary CDC port" 2>/dev/null)"; then
		save_selected_serial_port "$runtime_port"
		echo "Matched ESP32 runtime port: $runtime_port"
	fi
}

probe_esptool() {
	local output status port="" retry_output

	for ((i=1; i<=$#; i++)); do
		if [[ "${!i}" == "--port" ]] && (( i < $# )); then
			j=$((i + 1))
			port="${!j}"
			break
		fi
	done

	if output=$(invoke_esptool "$@" 2>&1); then
		return 0
	fi

	status=$?
	if [[ -n "$port" ]] && esptool_output_port_busy "$output"; then
		if ! recover_busy_serial_port "$port"; then
			printf '%s\n' "$output" >&2
			return "$status"
		fi
		if retry_output=$(invoke_esptool "$@" 2>&1); then
			return 0
		fi
		status=$?
		output="$retry_output"
	fi

	if grep -qi "Permission denied" <<<"$output"; then
		if no_sudo_mode; then
			echo "No-sudo mode cannot change access to ${port:-the serial port}." >&2
			return "$status"
		fi
		echo "Granting access to ${port:-serial port} and retrying esptool..."
		if [[ -n "$port" ]]; then
			sudo chmod a+rw "$port"
		fi
		if retry_output=$(invoke_esptool "$@" 2>&1); then
			return 0
		fi
		status=$?
		print_esptool_recovery_hint "$retry_output"
		return $status
	fi

	if [[ -n "$port" ]] && esptool_output_needs_reset "$output"; then
		if auto_reset_serial_port "$port"; then
			if retry_output=$(invoke_esptool "$@" 2>&1); then
				return 0
			fi
			if manual_reboot_choice "$port" "bootloader probe"; then
				if retry_output=$(invoke_esptool "$@" 2>&1); then
					return 0
				fi
				status=$?
			fi
			print_esptool_recovery_hint "$retry_output"
			return $status
		fi
	fi

	print_esptool_recovery_hint "$output"
	return $status
}

probe_esptool_mac() {
	local output status port="" retry_output

	for ((i=1; i<=$#; i++)); do
		if [[ "${!i}" == "--port" ]] && (( i < $# )); then
			j=$((i + 1))
			port="${!j}"
			break
		fi
	done

	if output=$(invoke_esptool "$@" 2>&1); then
		grep -qi -m1 'MAC' <<<"$output"
		return $?
	fi

	status=$?
	if [[ -n "$port" ]] && esptool_output_port_busy "$output"; then
		if ! recover_busy_serial_port "$port"; then
			printf '%s\n' "$output" >&2
			return "$status"
		fi
		if retry_output=$(invoke_esptool "$@" 2>&1); then
			grep -qi -m1 'MAC' <<<"$retry_output"
			return $?
		fi
		status=$?
		output="$retry_output"
	fi

	if grep -qi "Permission denied" <<<"$output"; then
		if no_sudo_mode; then
			echo "No-sudo mode cannot change access to ${port:-the serial port}." >&2
			return "$status"
		fi
		echo "Granting access to ${port:-serial port} and retrying esptool..."
		if [[ -n "$port" ]]; then
			sudo chmod a+rw "$port"
		fi
		if retry_output=$(invoke_esptool "$@" 2>&1); then
			grep -qi -m1 'MAC' <<<"$retry_output"
			return $?
		fi
		status=$?
		print_esptool_recovery_hint "$retry_output"
		return $status
	fi

	if [[ -n "$port" ]] && esptool_output_needs_reset "$output"; then
		if auto_reset_serial_port "$port"; then
			if retry_output=$(invoke_esptool "$@" 2>&1); then
				grep -qi -m1 'MAC' <<<"$retry_output"
				return $?
			fi
			if manual_reboot_choice "$port" "ESP32 MAC probe"; then
				if retry_output=$(invoke_esptool "$@" 2>&1); then
					grep -qi -m1 'MAC' <<<"$retry_output"
					return $?
				fi
				status=$?
			fi
			print_esptool_recovery_hint "$retry_output"
			return $status
		fi
	fi

	print_esptool_recovery_hint "$output"
	return $status
}

parse_esp32_app_partitions() {
	local partition_file="$1"

	python3 - "$partition_file" <<'PY'
import struct
import sys

path = sys.argv[1]
data = open(path, "rb").read()
seen = set()

for i in range(0, min(len(data), 0x1000), 32):
    entry = data[i:i + 32]
    if len(entry) < 32:
        break

    magic = entry[0:2]
    if magic == b"\xff\xff":
        break
    if magic != b"\xaa\x50":
        continue

    part_type = entry[2]
    if part_type != 0x00:
        continue

    offset, size = struct.unpack_from("<II", entry, 4)
    if offset and offset not in seen:
        seen.add(offset)
        print(f"0x{offset:x}\t0x{size:x}")
PY
}

read_esp32_app_partitions() {
	local port="$1"
	local partition_file

	partition_file="$(mktemp)"
	if run_esptool --port "$port" --before "$NORESET" --after "$NORESET" \
		--baud 921600 "$READFLASH" 0x8000 0x1000 "$partition_file" >/dev/null; then
		parse_esp32_app_partitions "$partition_file"
	else
		echo "Warning: could not read ESP32 partition table; defaulting app update to 0x10000" >&2
	fi
	rm -f "$partition_file"
}

esp32_firmware_fits_app_partition() {
	local firmware_size="$1"
	local offset="$2"
	local partition_size_hex="$3"
	local partition_size

	partition_size=$((partition_size_hex))
	if (( firmware_size <= partition_size )); then
		return 0
	fi

	echo "ERROR: firmware is ${firmware_size} bytes, but the ESP32 app partition at ${offset} is only ${partition_size} bytes (${partition_size_hex})." >&2
	echo "The app-only image cannot be flashed safely with the device's current partition table." >&2
	echo "Use the matching -merged.bin firmware as a new install to replace the partition layout (this erases device settings), or use a smaller app-only image." >&2
	return 1
}

esp32_device_image_present_at_offset() {
	local port="$1"
	local offset="$2"
	local probe_file magic segs mode segs_dec mode_dec

	probe_file="$(mktemp)"
	if ! run_esptool --port "$port" --before "$NORESET" --after "$NORESET" \
		--baud 921600 "$READFLASH" "$offset" 4 "$probe_file" >/dev/null; then
		rm -f "$probe_file"
		return 1
	fi

	magic=$(xxd -p -l 1 -s 0 "$probe_file" 2>/dev/null | tr -d '\n')
	segs=$(xxd -p -l 1 -s 1 "$probe_file" 2>/dev/null | tr -d '\n')
	mode=$(xxd -p -l 1 -s 2 "$probe_file" 2>/dev/null | tr -d '\n')
	rm -f "$probe_file"

	[[ "$magic" == "e9" && -n "$segs" && -n "$mode" ]] || return 1

	segs_dec=$((16#$segs))
	mode_dec=$((16#$mode))
	(( segs_dec >= 1 && segs_dec <= 16 )) || return 1
	(( mode_dec >= 0 && mode_dec <= 3 )) || return 1
}

esp32_update_flash_offsets() {
	local port="$1"
	local firmware_file="$2"
	local firmware_size partition offset size primary_index=0 i
	local -a app_partitions=()
	local -a app_offsets=()
	local -a app_sizes=()
	local -a update_indices=()

	if [[ ! -f "$firmware_file" ]]; then
		echo "ERROR: firmware file not found: ${firmware_file}" >&2
		return 1
	fi
	firmware_size="$(stat -c '%s' "$firmware_file")"

	mapfile -t app_partitions < <(read_esp32_app_partitions "$port" || true)
	for partition in "${app_partitions[@]}"; do
		read -r offset size <<< "$partition"
		[[ "$offset" =~ ^0x[0-9a-fA-F]+$ && "$size" =~ ^0x[0-9a-fA-F]+$ ]] || continue
		app_offsets+=("$offset")
		app_sizes+=("$size")
	done

	if ((${#app_offsets[@]} == 0)); then
		echo "Warning: no app partitions were parsed; using 0x10000 without a partition-size check" >&2
		printf '%s\n' 0x10000
		return 0
	fi

	for ((i=0; i<${#app_offsets[@]}; i++)); do
		if [[ "${app_offsets[i]}" == "0x10000" ]]; then
			primary_index=$i
			break
		fi
	done
	if [[ "${app_offsets[primary_index]}" != "0x10000" ]]; then
		echo "ESP32 partition table does not list an app slot at 0x10000; using first app slot at ${app_offsets[primary_index]}." >&2
	fi

	esp32_firmware_fits_app_partition "$firmware_size" "${app_offsets[primary_index]}" "${app_sizes[primary_index]}" || return 1
	update_indices+=("$primary_index")

	for ((i=0; i<${#app_offsets[@]}; i++)); do
		(( i == primary_index )) && continue
		offset="${app_offsets[i]}"
		if esp32_device_image_present_at_offset "$port" "$offset"; then
			esp32_firmware_fits_app_partition "$firmware_size" "$offset" "${app_sizes[i]}" || return 1
			echo "Detected existing ESP32 app image at ${offset}; adding that app slot to the update." >&2
			update_indices+=("$i")
		else
			echo "ESP32 app partition at ${offset} contains no app image; skipping that slot." >&2
		fi
	done

	for i in "${update_indices[@]}"; do
		printf '%s\n' "${app_offsets[i]}"
	done
}

list_usb_block_devs() {
	lsblk -rpo NAME,TYPE,TRAN,MOUNTPOINT | awk '$3=="usb" {print $1}' | sort -u; 
}

scan_and_maybe_mount() {
    local -a USB_DEVS=()
    mapfile -t USB_DEVS < <(list_usb_block_devs)

    if ((${#USB_DEVS[@]} == 0)); then
        return 1                # nothing found
    fi

    for device_id in "${USB_DEVS[@]}"; do
        # find existing mountpoint (first column after device name)
        mount_pt=$(lsblk -nrpo MOUNTPOINT "$device_id" | head -n1)

        if [[ -z "$mount_pt" ]]; then
            echo "$device_id is not mounted. Mounting now..."
			if no_sudo_mode; then
				echo "No-sudo mode cannot mount $device_id; mount it explicitly first." >&2
				return 1
			fi
            sudo mkdir -p "$MOUNT_FOLDER"
            sudo mount "$device_id" "$MOUNT_FOLDER"
            mount_pt="$MOUNT_FOLDER"
        fi

        if [[ -e "$mount_pt/CURRENT.UF2" ]]; then
            echo "Found CURRENT.UF2 on $device_id ($mount_pt)"
			MOUNT_FOLDER="$mount_pt"
            return 0             # success
        fi
    done

    return 2                     # USB present but no UF2
}


autodetect_device() {
	local -a DEVICES=()
	local vendor_id="" esp32_ready=0
	mapfile -t DEVICES < <(_jq1 '.device[].name' 2>/dev/null | sort -u)
	
	choose_serial
	local DEVICE_PORT=""
	[[ -f "$DEVICE_PORT_FILE"     ]] && DEVICE_PORT="$(<"$DEVICE_PORT_FILE")"
	
	# Probe for ESP32. Native ESP32-S3 USB must be followed across its application
	# CDC -> ROM USB/JTAG re-enumeration; probing a stale application tty cannot
	# work and an ordinary pySerial open can assert DTR/RTS before esptool applies
	# --before=no-reset.
	local ESPTOOL_CMD=""
	get_espcmd
	vendor_id="$(udev_device_property "$DEVICE_PORT" ID_VENDOR_ID)"
	if [[ "${vendor_id,,}" == "303a" ]]; then
		if prepare_esp32_flash_session "$DEVICE_PORT" "ESP32 autodetect"; then
			esp32_ready=1
		fi
	elif raw_esptool_mac_probe --port "$DEVICE_PORT" \
		--after "$NORESET" --baud 115200 "$READMAC"; then
		# UART bridges retain the tty while esptool's intentional reset enters ROM.
		BOOTLOADER_PROBE_PORT="$DEVICE_PORT"
		BOOTLOADER_PROBE_ACTIVE=1
		esp32_ready=1
	fi

	[[ -f "$DEVICE_PORT_FILE" ]] && DEVICE_PORT="$(<"$DEVICE_PORT_FILE")"

	if (( esp32_ready )); then
		echo "ESP chip responded; getting existing firmware"
		run_esptool --port "$DEVICE_PORT" --before "$NORESET" \
			--after "$NORESET" --baud 921600 "$READFLASH" \
			0x10000 0x70000 "$DOWNLOAD_DIR/CURRENT.BAK"

		AUTODETECT_DEVICE=$( detect_device_from_fw "$DOWNLOAD_DIR/CURRENT.BAK" )
		if esp32_port_is_rom_usb_jtag "$DEVICE_PORT"; then
			finish_esp32_flash_session "$DEVICE_PORT"
		else
			invoke_esptool_timeout "${ESP32_PROBE_TIMEOUT_SECONDS:-12}s" \
				--port "$DEVICE_PORT" --before "$NORESET" \
				--after "$HARDRESET" "$READMAC" >/dev/null
		fi
		BOOTLOADER_PROBE_ACTIVE=0
		BOOTLOADER_PROBE_PORT=""
	else
		# ---- Y: timed-out or grep found no match -------------------------
		echo "nrf52 device"
		list_usb_block_devs
		
		if ! scan_and_maybe_mount; then
			echo "No USB mass-storage device found, sending 1200-baud reset..."
			if no_sudo_mode; then
				echo "No-sudo mode cannot run this privileged autodetect reset." >&2
				return 1
			fi
			sudo bash -c "exec 3<> \"$DEVICE_PORT\"; stty -F \"$DEVICE_PORT\" 1200; sleep 1.5"
		fi
		
		sleep 8
		
		if ! scan_and_maybe_mount; then
			echo "Device not in DFU mode. Connect via the app and set into DFU or unplug/re-plug quickly 2x."
			echo "Waiting for DFU"
			for ((i=0; i<60; i++)); do
				spinner
				if scan_and_maybe_mount; then
					echo
					break
				fi
				sleep 1
			done
		fi
		AUTODETECT_DEVICE=$( detect_device_from_fw "$MOUNT_FOLDER/CURRENT.UF2" )
		
	fi
	echo
	echo "Device detected:"
	echo "$AUTODETECT_DEVICE"
	echo "$AUTODETECT_DEVICE" > "$AUTODETECT_DEVICE_FILE"
	read -r -p "Press Enter to continue..."
}

extract_name_from_firmware() {
  local f="$1"
  LC_ALL=C perl -0777 -ne '
    # Arduino-ESP32 stores the USB product and manufacturer as adjacent
    # NUL-terminated strings.  Match that boundary exactly: looking merely
    # "near" Espressif Systems can select the tail of a parenthesized memory
    # description (for example, "MB PSRAM") instead of the board name.
    if (/([\x20-\x7e]{1,160})\x00+Espressif Systems\x00/s) {
      my $name = $1;
      $name =~ s/\s*\([^)]*(?:FLASH|PSRAM)[^)]*\)\s*$//i;
      print "$name\n"; exit
    }
  ' "$f" 2>/dev/null
}

# prints one line with fallback to .pio/libdeps/... segment
print_fw_line() {
  local label="$1" file="$2" val
  # The PlatformIO environment names the exact firmware target and therefore
  # carries more information than the generic USB product (for example V4.3,
  # Full Companion, and FEM-off). Use the USB product only for binaries that
  # do not retain a PlatformIO path.
  val="$(LC_ALL=C grep -aom1 -P '\.pio/libdeps/\K[^/\n]{1,100}' "$file" 2>/dev/null || true)"
  [[ -z "$val" ]] && val="$(extract_name_from_firmware "$file")"
  printf '    %-20s %s\n' "$label" "${val:-unknown}"
}

print_file_size_line() {
  local label="$1" file="$2" bytes=""
  [[ -f "$file" ]] && bytes="$(stat -c%s "$file" 2>/dev/null || true)"
  printf '    %-20s %s\n' "$label" "${bytes:-missing}"
}

# wrapper that returns just the detected name (same logic as print_fw_line)
detect_device_from_fw() {
  local f="$1" v
  v="$(LC_ALL=C grep -aom1 -P '\.pio/libdeps/\K[^/\n]{1,100}' "$f" 2>/dev/null || true)"
  [[ -z "$v" ]] && v="$(extract_name_from_firmware "$f")"
  printf '%s\n' "${v:-unknown}"
}

# --------------------------------------------------
# MAIN
# --------------------------------------------------

mkdir -p "$FIRMWARE_ROOT"

rm -f  \
  "$CONFIG_SOURCE_FILE"       \
  "$SELECTED_DEVICE_FILE"   \
  "$ARCHITECTURE_FILE"      \
  "$ERASE_URL_FILE"         \
  "$SELECTED_ROLE_FILE"     \
  "$SELECTED_TITLE_FILE"    \
  "$SELECTED_SUBTITLE_FILE" \
  "$SELECTED_VERSION_FILE"  \
  "$SELECTED_TYPE_FILE"     \
  "$SELECTED_URL_FILE"      \
  "$DOWNLOADED_FILE_FILE"   \
  "$ERASE_FILE_FILE"        \
  "$DEVICE_PORT_NAME_FILE"  \
  "$ESPTOOL_FILE"           \
  "$AUTODETECT_DEVICE_FILE" \
  "$DEVICE_PORT_FILE"
  
URL_PATH=''
echo "Looking for a node"
choose_serial || true
DEVICE_NAME=""
[[ -f "$DEVICE_PORT_FILE" ]] && DEVICE_NAME="$(<"$DEVICE_PORT_FILE")"

while [[ -z $URL_PATH ]]; do
	choose_meshcore_firmware

	URL_PATH=$(cat "$SELECTED_URL_FILE")
	if [[ -z "$URL_PATH" ]]; then
		ROLE=$(cat "$SELECTED_ROLE_FILE")
		echo "$ROLE is not supported with that version"
		rm -f "$SELECTED_ROLE_FILE"
		rm -f "$SELECTED_VERSION_FILE"
	fi
done
if [[ "$URL_PATH" == file:///* ]]; then
	URL_PATH="${URL_PATH#file://}"
fi
URL_PATH="$(expand_home_path "$URL_PATH")"
if [[ "$URL_PATH" =~ ^https?:// ]]; then
    URL="$URL_PATH"
	download_and_verify "$URL" "$DOWNLOADED_FILE_FILE" 1 "Firmware"
else
    if [[ "$URL_PATH" == /* && -f "$URL_PATH" ]]; then
        printf '%s\n' "$URL_PATH" > "$DOWNLOADED_FILE_FILE"
    else
        [[ "$URL_PATH" != /* ]] && URL_PATH="/$URL_PATH"
        URL="https://flasher.meshcore.io${URL_PATH}"
	    download_and_verify "$URL" "$DOWNLOADED_FILE_FILE" 1 "Firmware"
    fi
fi

ARCHITECTURE=''
DEVICE=''
DEVICE_PORT=''
DOWNLOADED_FILE=''
TYPE=''
[[ -f "$ARCHITECTURE_FILE"    ]] && ARCHITECTURE="$(<"$ARCHITECTURE_FILE")"
[[ -f "$DEVICE_PORT_FILE"     ]] && DEVICE_PORT="$(<"$DEVICE_PORT_FILE")"
[[ -f "$DOWNLOADED_FILE_FILE" ]] && DOWNLOADED_FILE="$(<"$DOWNLOADED_FILE_FILE")"
[[ -f "$SELECTED_DEVICE_FILE" ]] && DEVICE="$(<"$SELECTED_DEVICE_FILE")"
if [[ -z $DEVICE_PORT ]]; then
	choose_serial
	[[ -f "$ARCHITECTURE_FILE"    ]] && ARCHITECTURE="$(<"$ARCHITECTURE_FILE")"
	[[ -f "$DEVICE_PORT_FILE"     ]] && DEVICE_PORT="$(<"$DEVICE_PORT_FILE")"
	[[ -f "$DOWNLOADED_FILE_FILE" ]] && DOWNLOADED_FILE="$(<"$DOWNLOADED_FILE_FILE")"
	[[ -f "$SELECTED_DEVICE_FILE" ]] && DEVICE="$(<"$SELECTED_DEVICE_FILE")"
fi

echo "Architecture: $ARCHITECTURE"
if [[ "$ARCHITECTURE" =~ esp32 ]]; then

	get_espcmd
	[[ -f "$ESPTOOL_FILE"     ]] && ESPTOOL_CMD="$(<"$ESPTOOL_FILE")"
	export ESPTOOL_PORT=$DEVICE_PORT
	[[ -f "$SELECTED_TYPE_FILE"    ]] && TYPE="$(<"$SELECTED_TYPE_FILE")"
	print_fw_line "Downloaded firmware:" "$DOWNLOADED_FILE"
	print_file_size_line "Downloaded bytes:" "$DOWNLOADED_FILE"
	FW_LAYOUT="$(esp_firmware_layout "$DOWNLOADED_FILE")"
	FW_NAME_HINT="$(esp_filename_layout_hint "$DOWNLOADED_FILE")"
	if [[ "$FW_LAYOUT" == "merged" ]]; then
		echo "Firmware layout: merged image detected from file contents"
	elif [[ "$FW_LAYOUT" == "app-only" ]]; then
		echo "Firmware layout: app-only image detected from file contents"
	elif [[ "$TYPE" == "flash-wipe" ]]; then
		echo "Firmware layout: unknown from file contents; using custom file hint for a new install"
	elif [[ "$TYPE" == "flash-update" ]]; then
		echo "Firmware layout: unknown from file contents; using custom file hint for an update"
	else
		echo "Firmware layout: unknown from file contents; falling back to selected type"
	fi
	if [[ "$FW_NAME_HINT" == "unknown" ]]; then
		echo "Notice: filename does not match the usual merged/app-only pattern."
	elif [[ "$FW_LAYOUT" != "unknown" && "$FW_NAME_HINT" != "$FW_LAYOUT" ]]; then
		echo "Notice: filename does not match the detected firmware layout."
	fi
	esp32_validate_image_for_device "$DEVICE" "$DOWNLOADED_FILE" "$FW_LAYOUT"
	
	echo
	echo "Device firmware backup will be attempted after you confirm flashing."
	echo "Commands that would be run."
	
	if [[ "$FW_LAYOUT" == "merged" || ( "$FW_LAYOUT" != "app-only" && "$TYPE" == "flash-wipe" ) ]]; then

		echo "  identity-safe serial open and application-to-ROM port handoff"
		echo "  $ESPTOOL_CMD --port <matching-ROM-port> --before $NORESET --after $NORESET --baud 115200 $ERASEFLASH"
		echo "  $ESPTOOL_CMD --port <matching-ROM-port> --before $NORESET --after <safe-reset> --baud 115200 $WRITEFLASH 0x0000 \"${DOWNLOADED_FILE}\""
		EXECUTION_MODE="$(choose_flash_execution_mode "ERASE and INSTALL ${DEVICE} on ${DEVICE_PORT}")"
		if [[ "$EXECUTION_MODE" == "echo" ]]; then
			echo "Echo-only selected; no ESP32 flash commands were run."
			exit 0
		fi
		prepare_esp32_flash_session "${DEVICE_PORT}" "${DEVICE}"
		run_esptool --port "${DEVICE_PORT}" --before "$NORESET" \
			--after "$NORESET" --baud 115200 "$ERASEFLASH"
		sleep 1
		ESP32_WRITE_AFTER="$HARDRESET"
		if esp32_port_is_rom_usb_jtag "$DEVICE_PORT"; then
			# Keep the known ROM instance available until the guarded close/reset
			# path can release DTR/RTS safely and follow runtime re-enumeration.
			ESP32_WRITE_AFTER="$NORESET"
		fi
		run_esptool --port "${DEVICE_PORT}" --before "$NORESET" \
			--after "$ESP32_WRITE_AFTER" --baud 115200 "$WRITEFLASH" \
			0x0000 "${DOWNLOADED_FILE}"
		finish_esp32_flash_session "${DEVICE_PORT}"
	else
		echo "  identity-safe serial open and application-to-ROM port handoff"
		echo "  $ESPTOOL_CMD --port <matching-ROM-port> --before $NORESET --after <safe-reset> --baud 115200 $WRITEFLASH <device app offset> \"${DOWNLOADED_FILE}\""
		echo "The ESP32 partition table will be read from the device. The update will stop if the image does not fit; populated secondary app slots will also be updated."
		EXECUTION_MODE="$(choose_flash_execution_mode "UPDATE ${DEVICE} on ${DEVICE_PORT}")"
		if [[ "$EXECUTION_MODE" == "echo" ]]; then
			echo "Echo-only selected; no ESP32 flash commands were run."
			echo "Dynamic app offsets are not read in echo-only mode."
			exit 0
		fi
		prepare_esp32_flash_session "${DEVICE_PORT}" "${DEVICE}"
		ESP32_UPDATE_OFFSETS_OUTPUT=""
		if ! ESP32_UPDATE_OFFSETS_OUTPUT="$(esp32_update_flash_offsets "${DEVICE_PORT}" "${DOWNLOADED_FILE}")"; then
			exit 1
		fi
		if [[ -z "$ESP32_UPDATE_OFFSETS_OUTPUT" ]]; then
			echo "ERROR: no ESP32 app partitions were selected for the update." >&2
			exit 1
		fi
		mapfile -t ESP32_UPDATE_OFFSETS <<< "$ESP32_UPDATE_OFFSETS_OUTPUT"
		ESP32_WRITE_ARGS=()
		for flash_offset in "${ESP32_UPDATE_OFFSETS[@]}"; do
			ESP32_WRITE_ARGS+=("$flash_offset" "${DOWNLOADED_FILE}")
		done
		ESP32_WRITE_AFTER="$HARDRESET"
		if esp32_port_is_rom_usb_jtag "$DEVICE_PORT"; then
			ESP32_WRITE_AFTER="$NORESET"
		fi
		printf '%s --port %s --after %s --baud 115200 %s' "$ESPTOOL_CMD" "$DEVICE_PORT" "$ESP32_WRITE_AFTER" "$WRITEFLASH"
		for ((i=0; i<${#ESP32_WRITE_ARGS[@]}; i+=2)); do
			printf ' %s "%s"' "${ESP32_WRITE_ARGS[i]}" "${ESP32_WRITE_ARGS[i+1]}"
		done
		printf '\n'
		run_esptool --port "${DEVICE_PORT}" --before "$NORESET" \
			--after "$ESP32_WRITE_AFTER" --baud 115200 "$WRITEFLASH" \
			"${ESP32_WRITE_ARGS[@]}"
		finish_esp32_flash_session "${DEVICE_PORT}"
	fi
	BOOTLOADER_PROBE_ACTIVE=0
	BOOTLOADER_PROBE_PORT=""
	
else
	echo "nrf52 device"
	echo "Downloaded firmware: $DOWNLOADED_FILE"
	if ! nrf52_validate_rak_board_pair "$DOWNLOADED_FILE" "$DEVICE_PORT" "$DEVICE"; then
		echo "Firmware selection was cancelled by the nRF52 board safety check." >&2
		exit 1
	fi
	NRF52_BOARD_GUARD_PASSED=1

	if [[ "$TYPE" == "flash-update" || "$TYPE" == "flash-wipe" ]]; then
		ACTION="$TYPE"
		echo "Auto-detected firmware action: $(describe_flash_action "$ACTION")"
	else
		while true; do
			echo "Choose firmware action for ${DEVICE} on ${DEVICE_PORT}:"
			echo "  1) flash-update       (write only)"
			echo "  2) flash-wipe + flash (erase, then write)"
			read -r -p "Selection [1/2]: " choice < /dev/tty

			case "$choice" in
				1) ACTION="flash-update"; break ;;
				2) ACTION="flash-wipe";   break ;;
				0) echo "Skipped."; exit 0 ;;
				*) echo "Invalid choice."; continue ;;
			esac
		done
	fi
	
	if [[ $ACTION == "flash-wipe" ]]; then
		
		[[ -f "$ERASE_URL_FILE" ]] && ERASE_URL="$(<"$ERASE_URL_FILE")"
		#echo "$ERASE_URL"
		if [[ -z "$ERASE_URL" ]]; then
			ERASE_ZIP="$(choose_erase_zip)" || exit 1
			ERASE_URL="https://flasher.meshcore.io/firmware/$ERASE_ZIP"
		fi
		download_and_verify "$ERASE_URL" "$ERASE_FILE_FILE" 0 "Erase"
		[[ -f "$ERASE_FILE_FILE" ]] && ERASE_FILE="$(<"$ERASE_FILE_FILE")"
	fi

	echo "Commands that would be run."
	if [[ $ACTION == "flash-wipe" ]]; then
		echo "  identity-safe 1200-baud touch ${DEVICE_PORT}"
		echo "  wait up to ${NRF52_DFU_REENUMERATE_TIMEOUT_SECONDS:-30}s for the same USB device's bootloader"
		print_nrfutil_dfu_command_live_port "$ERASE_FILE" "<matching-bootloader-port>"
		echo "  wait for the same USB device to return after erase"
	fi
	echo "  identity-safe 1200-baud touch <matching-runtime-port>"
	echo "  wait up to ${NRF52_DFU_REENUMERATE_TIMEOUT_SECONDS:-30}s for the same USB device's bootloader"
	print_nrfutil_dfu_command_live_port "$DOWNLOADED_FILE" "<matching-bootloader-port>"
	EXECUTION_MODE="$(choose_flash_execution_mode "${ACTION} ${DEVICE} on ${DEVICE_PORT}")"
	if [[ "$EXECUTION_MODE" == "echo" ]]; then
		echo "Echo-only selected; no nRF52 DFU commands were run."
		exit 0
	fi

	echo "Getting the latest version of adafruit-nrfutil"
	pipx run adafruit-nrfutil version

	echo "Running ${ACTION}..."
	NRF52_SELECTED_BY_ID="$(nrf52_selected_by_id_path)"
	NRF52_RUNTIME_PORT="$DEVICE_PORT"
	if [[ -n "$NRF52_SELECTED_BY_ID" ]]; then
		NRF52_RUNTIME_PORT="$(readlink -f "$NRF52_SELECTED_BY_ID" 2>/dev/null || true)"
		if [[ -z "$NRF52_RUNTIME_PORT" || ! -e "$NRF52_RUNTIME_PORT" ]]; then
			echo "The selected nRF52 USB identity is no longer connected: $NRF52_SELECTED_BY_ID" >&2
			exit 1
		fi
		if [[ "$NRF52_RUNTIME_PORT" != "$DEVICE_PORT" ]]; then
			echo "Using live port $NRF52_RUNTIME_PORT instead of stale port $DEVICE_PORT."
		fi
	fi
	NRF52_RUNTIME_SERIAL="$(udev_device_property "$NRF52_RUNTIME_PORT" ID_SERIAL_SHORT)"
	NRF52_RUNTIME_PATH_STEM="$(nrf52_usb_path_stem "$(udev_device_property "$NRF52_RUNTIME_PORT" ID_PATH)")"
	NRF52_RUNTIME_INSTANCE="$(nrf52_port_instance "$NRF52_RUNTIME_PORT")"
	NRF52_LAST_DFU_PORT=""
	NRF52_LAST_DFU_INSTANCE=""

	if [[ -z "$NRF52_RUNTIME_INSTANCE" ]]; then
		echo "Cannot identify the running nRF52 serial port $NRF52_RUNTIME_PORT." >&2
		exit 1
	fi
	if [[ -z "$NRF52_SELECTED_BY_ID" && -z "$NRF52_RUNTIME_SERIAL" \
		&& -z "$NRF52_RUNTIME_PATH_STEM" ]]; then
		echo "Cannot preserve a stable USB identity for $NRF52_RUNTIME_PORT; refusing an ambiguous DFU reset." >&2
		exit 1
	fi
	DEVICE_PORT="$NRF52_RUNTIME_PORT"

	if [[ $ACTION == "flash-wipe" ]]; then
		echo "Erasing UF2 area using $ERASE_FILE"
		sleep 1
		if ! run_nrf52_dfu_package_buttonless "$ERASE_FILE" "$NRF52_RUNTIME_PORT"; then
			echo "Failed to erase ${DEVICE} on ${DEVICE_PORT}."
			exit 1
		fi
		echo "Erase done."
		echo

		echo "Flashing firmware file $DOWNLOADED_FILE..."
		sleep 1
		if ! NRF52_RUNTIME_PORT="$(wait_for_nrf52_bootloader_port "$NRF52_LAST_DFU_PORT" \
			"$NRF52_SELECTED_BY_ID" "$NRF52_RUNTIME_SERIAL" "$NRF52_RUNTIME_PATH_STEM" \
			"$NRF52_LAST_DFU_INSTANCE" "runtime CDC port after erase")"; then
			echo "The erase package programmed successfully, but ${DEVICE} did not return for the firmware install." >&2
			exit 1
		fi
		if ! run_nrf52_dfu_package_buttonless "$DOWNLOADED_FILE" "$NRF52_RUNTIME_PORT"; then
			echo "Firmware ${ACTION} failed for ${DEVICE} on ${DEVICE_PORT}."
			exit 1
		fi
	else
		if ! run_nrf52_dfu_package_buttonless "$DOWNLOADED_FILE" "$NRF52_RUNTIME_PORT"; then
			echo "Firmware ${ACTION} failed for ${DEVICE} on ${DEVICE_PORT}." >&2
			exit 1
		fi
	fi
	echo
	echo "Firmware ${ACTION} completed for ${DEVICE} on ${DEVICE_PORT}."
fi

# Restart the stopped service.
restart_locked_services
