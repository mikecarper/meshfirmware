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
	USB_AUTOSUSPEND_END=$(cat /sys/module/usbcore/parameters/autosuspend)
	if [[ "$USB_AUTOSUSPEND_END" != "$USB_AUTOSUSPEND" ]]; then
		echo "$USB_AUTOSUSPEND" | sudo tee /sys/module/usbcore/parameters/autosuspend >/dev/null
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

# Global variable to track the spinner index.
spinner_index=0
# Array holding the spinner characters.
spinner_chars=("-" "\\" "|" "/")
CACHE_TIMEOUT_SECONDS=$((6 * 3600)) # 6 hours
MOUNT_FOLDER="/mnt/meshDeviceSD"
USB_AUTOSUSPEND=$(cat /sys/module/usbcore/parameters/autosuspend)
if [[ "$USB_AUTOSUSPEND" -ne -1 ]]; then
	# Only disable (-1) if it isn’t already
	echo "sudo needed to disable USB autosuspend and keep all USB ports active."
	echo -1 | sudo tee /sys/module/usbcore/parameters/autosuspend >/dev/null
fi

MIN_BYTES=$((250 * 1024))   # 250 KB in bytes
REPO_OWNER="meshcore-dev"
REPO_NAME="MeshCore"
RELEASE_INFO1_URL="https://flasher.meshcore.dev/config.json"
RELEASE_INFO2_URL="https://flasher.meshcore.dev/releases"

# Settings for the repo
        GITHUB_API_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases"
# Set Folders
         FIRMWARE_ROOT="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}"
          DOWNLOAD_DIR="${FIRMWARE_ROOT}/downloads"
# Vars to get passed around and cached as files.
           CONFIG_FILE="${FIRMWARE_ROOT}/config.json"
         RELEASES_FILE="${FIRMWARE_ROOT}/releases.json"
  SELECTED_DEVICE_FILE="${FIRMWARE_ROOT}/01device.txt"
     ARCHITECTURE_FILE="${FIRMWARE_ROOT}/02architecture.txt"
        ERASE_URL_FILE="${FIRMWARE_ROOT}/03erase.txt"
    SELECTED_ROLE_FILE="${FIRMWARE_ROOT}/04role.txt"
 SELECTED_VERSION_FILE="${FIRMWARE_ROOT}/05version.txt"
    SELECTED_TYPE_FILE="${FIRMWARE_ROOT}/06type.txt"
     SELECTED_URL_FILE="${FIRMWARE_ROOT}/07selected_url.txt"
  DOWNLOADED_FILE_FILE="${FIRMWARE_ROOT}/08downloaded_file.txt"
      DEVICE_PORT_FILE="${FIRMWARE_ROOT}/09device_port_file.txt"
          ESPTOOL_FILE="${FIRMWARE_ROOT}/10esptool_file.txt"




spinner() {
	# Print the spinner character (using \r to overwrite the same line)
	printf "\r%s" "${spinner_chars[spinner_index]}" >/dev/tty
	# Update the index, wrapping around to 0 when reaching the end of the array.
	spinner_index=$(((spinner_index + 1) % ${#spinner_chars[@]}))
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
    local url="$1"            # first arg = URL
    local cache_file="$2"     # second arg = path to cache file
    local age_sec="$CACHE_TIMEOUT_SECONDS"

    mkdir -p "$(dirname "$cache_file")"

    local fetch_needed=1
    if [[ -f "$cache_file" ]]; then
        local file_age=$(( $(date +%s) - $(stat -c %Y "$cache_file") ))
        (( file_age < age_sec )) && fetch_needed=0
    fi

    if (( fetch_needed )); then
        echo "Downloading $(basename "$cache_file")"
        curl -sSL --fail "$url" -o "$cache_file"
    fi
}

choose_version_from_releases() {
	local DEVICE="$1"
	local ARCHITECTURE="$1"
	local DEVICE="$1"
	local ROLE="$2"
	
	# ---- fetch / reuse cache ---------------------------------------------
    _cached_json "$RELEASE_INFO2_URL" "$CACHE_FILE"

	local VERSION=''
    local TYPE=''
	[[ -f "$SELECTED_VERSION_FILE" ]] && VERSION="$(<"$SELECTED_VERSION_FILE")"
	[[ -f "$SELECTED_TYPE_FILE"    ]] && TYPE="$(<"$SELECTED_TYPE_FILE")"

    # ---------------- step 3 – version ------------------------------------
	if [[ -z "$VERSION" ]]; then
		local -a VERSIONS=()
		mapfile -t VERSIONS < <(_jq2 -r '.[] | .version' | sort -ru)
		if ((${#VERSIONS[@]} == 0)); then
			echo "ERROR: no versions in /releases endpoint" >&2
			return 1
		fi

		if ((${#VERSIONS[@]} == 1)); then
			VERSION="${VERSIONS[0]}"
			echo "Auto-selected version from fallback: $VERSION"
		else
			while [[ -z $VERSION ]]; do
				sleep 0.1
				echo; echo "[3] Select version:"
				select VERSION in "${VERSIONS[@]}"; do [[ -n $VERSION ]] && break; done < /dev/tty
			done
		fi
	fi

    # ---------------- step 4 – type ---------------------------------------
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

    # ---------------- step 5 – filename -----------------------------------
	local REGEX=''
	REGEX=$( _jq1 --arg type "$TYPE" --arg d "$DEVICE" --arg r "$ROLE" ".device[] | select(.name==\$d) | .firmware[] | select(.role==\$r) | .github | .files | .[\$type]" | sort -u )
    
	ROLE_ALT="$ROLE"
	if [[ "$ROLE" == "companionBle" || "$ROLE" == "companionUsb" ]]; then
		ROLE_ALT="companion"
	fi
	
	local CHOSEN_FILE=''
	CHOSEN_FILE=$( _jq2 --arg reg "$REGEX" --arg ver "$VERSION" --arg t "$TYPE" --arg d "$DEVICE" --arg r "$ROLE_ALT" ".[] | select(.version==\$ver and .type==\$r) | .files[] | select(.name|test(\$reg)) | .url " )

	echo "$DEVICE" > "$SELECTED_DEVICE_FILE"
	echo "$ARCHITECTURE" > "$ARCHITECTURE_FILE"
	echo "$ERASE_URL" > "$ERASE_URL_FILE"
	echo "$ROLE" > "$SELECTED_ROLE_FILE"
	echo "$VERSION" > "$SELECTED_VERSION_FILE"
	echo "$TYPE" >"$SELECTED_TYPE_FILE"
    echo "$CHOSEN_FILE" >"$SELECTED_URL_FILE"
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
    _cached_json "$JSON_URL" "$CONFIG_FILE"


    # make sure .device[].name exists
    if ! _jq1 '.device[].name' >/dev/null 2>&1; then
        echo "Cached file missing expected keys. Deleting and fetching again."
        rm -f "$CONFIG_FILE"
		sleep 1
		_cached_json "$JSON_URL" "$CONFIG_FILE"
    fi
	
	local DEVICE=''
	local ARCHITECTURE=''
	local ERASE_URL=''
	local ROLE=''
	local VERSION=''
    local TYPE=''
	[[ -f "$SELECTED_DEVICE_FILE"  ]] && DEVICE="$(<"$SELECTED_DEVICE_FILE")"
	[[ -f "$ARCHITECTURE_FILE"     ]] && ARCHITECTURE="$(<"$ARCHITECTURE_FILE")"
	[[ -f "$ERASE_URL_FILE"        ]] && ERASE_URL="$(<"$ERASE_URL_FILE")"
	[[ -f "$SELECTED_ROLE_FILE"    ]] && ROLE="$(<"$SELECTED_ROLE_FILE")"
	[[ -f "$SELECTED_VERSION_FILE" ]] && VERSION="$(<"$SELECTED_VERSION_FILE")"
	[[ -f "$SELECTED_TYPE_FILE"    ]] && TYPE="$(<"$SELECTED_TYPE_FILE")"

    # ---------------- step 1 – device -------------------------------------
	if [[ -z "$DEVICE" ]]; then
		local -a DEVICES=()
		mapfile -t DEVICES < <(_jq1 '.device[].name' 2>/dev/null | sort -u)

		if ((${#DEVICES[@]} == 0)); then
			echo "ERROR: no .device[].name entries found in $CONFIG_FILE"
			echo "Top-level keys in the JSON are:"
			_jq1 'keys[]'
			return 1
		fi

		if ((${#DEVICES[@]} == 1)); then
			DEVICE="${DEVICES[0]}"
			echo "Auto-selected device: $DEVICE"
		else
			local choice=''
			while [[ -z "$DEVICE" ]]; do
				echo
				echo "[1] Select device (0 = Auto-detect):"
				printf '  0) Auto-detect\n'
				for i in "${!DEVICES[@]}"; do
					printf '  %d) %s\n' $((i+1)) "${DEVICES[$i]}"
				done
				read -r -p 'Choice: ' choice </dev/tty

				if [[ "$choice" == 0 ]]; then
					echo "Auto-detection requested."
					autodetect_device
					[[ -f "$SELECTED_DEVICE_FILE"  ]] && DEVICE="$(<"$SELECTED_DEVICE_FILE")"
				elif [[ "$choice" =~ ^[1-9][0-9]*$ ]] && (( choice >= 1 && choice <= ${#DEVICES[@]} )); then
					DEVICE="${DEVICES[$((choice-1))]}"
				else
					echo "Invalid selection."
					choice=''
				fi
			done
		fi
	fi
	
	# ---------------- step 2 – architecture & erase -----------------------
	if [[ -z "$ARCHITECTURE" ]]; then
		ARCHITECTURE=$( _jq1 --arg d "$DEVICE" ".device[]|select(.name==\$d)|.type" )
		ERASE_URL=$( _jq1 --arg d "$DEVICE" ".device[]|select(.name==\$d)|.erase" )
		ERASE_URL="https://flasher.meshcore.dev/firmware/${ERASE_URL}"
	fi

    # ---------------- step 2 – role ---------------------------------------
	if [[ -z "$ROLE" ]]; then
		local -a ROLES=()
		mapfile -t ROLES < <(_jq1 --arg d "$DEVICE" ".device[]|select(.name==\$d)|.firmware[].role" | sort -u)

		if ((${#ROLES[@]} == 1)); then
			ROLE="${ROLES[0]}"
			echo "Auto-selected role: $ROLE"
		else
			while [[ -z $ROLE ]]; do
				sleep 0.1
				echo; echo "[2] Select role:"
				select ROLE in "${ROLES[@]}"; do [[ -n ${ROLE:-} ]] && break; done < /dev/tty
			done
		fi
	fi

    # ---------------- step 3 – version ------------------------------------
	local -a VERSIONS=()
	mapfile -t VERSIONS < <( _jq1 --arg d "$DEVICE" --arg r "$ROLE" ".device[] | select(.name==\$d) | .firmware[] | select(.role==\$r) | .version | keys[]" | sort -ru )
	if ((${#VERSIONS[@]} == 0)); then
		choose_version_from_releases "$DEVICE" "$ROLE";
		return
	fi
	if ((${#VERSIONS[@]} == 1)); then
		VERSION="${VERSIONS[0]}"
		echo "Auto-selected version: $VERSION"
	else
		if [[ -z "$VERSION" ]]; then
			while [[ -z $VERSION ]]; do
				sleep 0.1
				echo; echo "[3] Select version:"
				select VERSION in "${VERSIONS[@]}"; do [[ -n ${VERSION:-} ]] && break; done < /dev/tty
			done
		fi
	fi

    # ---------------- step 4 – type ---------------------------------------
	if [[ -z "$TYPE" ]]; then
		local -a TYPES=()
		mapfile -t TYPES < <(_jq1 --arg d "$DEVICE" --arg r "$ROLE" --arg v "$VERSION" ".device[]|select(.name==\$d) | .firmware[] | select(.role==\$r) | .version.[\$v] |.files[].type" | sort -u)

		if ((${#TYPES[@]} == 1)); then
			TYPE="${TYPES[0]}"
			echo "Auto-selected type: $TYPE"
		elif ((${#TYPES[@]} == 2)) && [[ " ${TYPES[*]} " == *" flash "* ]] && [[ " ${TYPES[*]} " == *" download "* ]]; then
			TYPE="flash"
			echo "Auto-selected type: flash"
		else
			while [[ -z $TYPE ]]; do
				sleep 0.1
				echo; echo "[4] Select type:"
				select TYPE in "${TYPES[@]}"; do [[ -n ${TYPE:-} ]] && break; done < /dev/tty
			done
		fi
	fi


    # ---------------- step 5 – filename -----------------------------------
    local CHOSEN_FILE=''
    CHOSEN_FILE=$(_jq1 --arg d "$DEVICE" --arg r "$ROLE" --arg v "$VERSION" --arg t "$TYPE" ".device[]|select(.name==\$d) | .firmware[] | select(.role==\$r) | .version.[\$v] |.files[]|select(.type==\$t)|.name")

	echo "$DEVICE" > "$SELECTED_DEVICE_FILE"
	echo "$ARCHITECTURE" > "$ARCHITECTURE_FILE"
	echo "$ERASE_URL_FILE" > "$ERASE_URL_FILE"
	echo "$ROLE" > "$SELECTED_ROLE_FILE"
	echo "$VERSION" > "$SELECTED_VERSION_FILE"
	echo "$TYPE" > "$SELECTED_TYPE_FILE"
	echo "firmware/$CHOSEN_FILE" > "$SELECTED_URL_FILE"
}

download_and_verify() {
    local url=$1
	local VERSION
	[[ -f "$SELECTED_VERSION_FILE" ]] && VERSION="$(<"$SELECTED_VERSION_FILE")"
	local bytes
	local basename
	basename=${url##*/}           # -> file.tar.gz?version=3
	basename=${basename%%[\?#]*}  # -> file.tar.gz   (removes ?version=3 or #fragment)
	local dest="${DOWNLOAD_DIR}/${VERSION}/${basename}"
	
	mkdir -p "${DOWNLOAD_DIR}/${VERSION}/"

	if [[ -f "$dest" ]]; then
	    bytes=$(stat -c%s "$dest" 2>/dev/null);
		if (( bytes < MIN_BYTES )); then
			rm -f "$dest"
		fi
	fi

	if [[ ! -f "$dest" ]]; then
		echo "Downloading firmware to $dest"
		wget -q --retry-connrefused --waitretry=1 -O "$dest" "$url" || return 1

		bytes=$(stat -c%s "$dest" 2>/dev/null);
		if (( bytes < MIN_BYTES )); then
			echo "Download too small ($bytes bytes < $MIN_BYTES); removing $dest" >&2
			rm -f "$dest"
			return 1
		fi

		echo "Downloaded $dest – $bytes bytes OK"
	else
		bytes=$(stat -c%s "$dest" 2>/dev/null);
		echo "Already downloaded $dest – $bytes bytes OK"
	fi

    echo "$dest" > "$DOWNLOADED_FILE_FILE"
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

        # ────────────────────────── nothing found ──────────────────────────
        if ((${#devs[@]} == 0)); then
            echo "No serial devices found under /dev/serial/by-id."
            read -rp "Try again? [y/N] " yn
            [[ $yn =~ ^[Yy]$ ]] || return 1         # give up
            continue                                # rescan
        fi

        # ────────────────────────── single device ──────────────────────────
        if ((${#devs[@]} == 1)); then
			detected_dev="${devs[0]}"
            echo "Only one device detected – selecting it automatically: $detected_dev - ${labels[0]}"
			echo "$detected_dev" > "$DEVICE_PORT_FILE"
			return
        fi

        # ────────────────────────── menu ──────────────────────────
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
				echo "$detected_dev" > "$DEVICE_PORT_FILE"
				return
            fi
        fi
        echo "Invalid selection – please try again."
    done
}

check_tty_lock () {
    local dev=$1
    [[ -e $dev ]] || { return 2; }

    # Open the device on fd 3 read-write (<>). Most distros let "dialout"
    # members do this without sudo.
    exec 3<>"$dev" 2>/dev/null || { return 2; }

    # Try to grab an exclusive, *non-blocking* lock on fd 3.
    if flock -n 3; then         # got the lock. device is FREE
        #echo "FREE"
        flock -u 3              # immediately unlock
        exec 3>&-               # close fd
        return 0
    else                        # lock failed. someone else holds it
        #echo "BUSY"
        exec 3>&-
        return 1
    fi
}

get_locked_service() {
	[[ -f "$DEVICE_PORT_FILE" ]] && device_name="$(<"$DEVICE_PORT_FILE")"
	
	if check_tty_lock "$device_name"; then
		return 0
	fi

	# Get all users locking the device (skip the header line)
	echo "Finding the service that has $device_name locked" > /dev/tty
	local users
	if ! command -v lsof &>/dev/null; then
		sudo apt install -y lsof
	fi
	users=$(sudo lsof "$device_name" 2>/dev/null | awk 'NR>1 {print $3}' | sort -u)
	if [ -z "$users" ]; then
		#echo "No process found locking ${device_name}."
		return 0
	fi
	#echo "User(s): $users"

	# For each user, get all their PIDs.
	local pids
	pids=$(ps -u "$users" -o pid= | tr -s ' ' | tr '\n' ' ')
	#echo "PIDs: $pids"

	local found_service=""
	#local last_pid=""
	for pid in $pids; do
		#echo "PID: $pid"

		# Get the full command line for the process.
		local cmd
		cmd=$(ps -p "$pid" -o cmd= | awk '{$1=$1};1')
		#echo "Command: $cmd"

		# Search for a systemd service file referencing the executable.
		# Using || true so that grep failing does not exit the script.
		local raw_service
		raw_service=$({ sudo grep -sR "$cmd" /etc/systemd/system/ 2>/dev/null || true; } | awk -F: '{print $1}' | sort -u)
		#echo "Raw service info: $raw_service"

		local service
		if [ -n "$raw_service" ]; then
			service=$(echo "$raw_service" | xargs -n1 basename | sort -u)
		else
			service="None"
		fi
		#echo "Service: $service"

		# If a service file was found, store it.
		if [ "$service" != "None" ]; then
			found_service="$found_service $service"
		fi
		#last_pid="$pid"
	done

	#if [ -n "$found_service" ] && [ "$found_service" != "None" ]; then
	#    echo "Service locking $device_name: $found_service"
	#else
	#    echo "Found matching process(es), but no systemd service file was identified."
	#    echo "Last checked PID: $last_pid"
	#    return 1
	#fi
	echo "$found_service" | awk '{$1=$1};1'
}

get_espcmd() {
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
		sudo apt update && sudo apt install -y python3 pipx
		PYTHON=$(command -v python3) || {
			echo "Failed to install python3"
			exit 1
		}
	fi

	# Ensure pipx & meshcore-cli are installed.
	if ! command -v pipx &>/dev/null; then
		echo "Installing pipx"
		sudo apt update && sudo apt -y install pipx pip
	fi

	if "$PYTHON" -m esptool version >/dev/null 2>&1; then
		ESPTOOL_CMD="$PYTHON -m esptool"
	elif command -v esptool >/dev/null 2>&1; then
		ESPTOOL_CMD="esptool"
	elif command -v esptool.py >/dev/null 2>&1; then
		ESPTOOL_CMD="esptool.py"
	else
		pipx install esptool
		ESPTOOL_CMD="esptool.py"
		pipx ensurepath
		# shellcheck disable=SC1091
		source "$HOME/.bashrc"
	fi

	echo "$ESPTOOL_CMD" > "$ESPTOOL_FILE"
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
	mapfile -t DEVICES < <(_jq1 '.device[].name' 2>/dev/null | sort -u)
	
	choose_serial
	local DEVICE_PORT=""
	[[ -f "$DEVICE_PORT_FILE"     ]] && DEVICE_PORT="$(<"$DEVICE_PORT_FILE")"
	
	# Stop the service.
	lockedService=$(get_locked_service)
	if [ -n "$lockedService" ] && [ "$lockedService" != "None" ]; then
		echo "Stopping service $lockedService..."
		sudo systemctl stop "$lockedService"
	fi

	# Probe for ESP32
	stty -F "$DEVICE_PORT" 1200
	local ESPTOOL_CMD=""
	get_espcmd
	[[ -f "$ESPTOOL_FILE"     ]] && ESPTOOL_CMD="$(<"$ESPTOOL_FILE")"

	if timeout 2s "$ESPTOOL_CMD" --port "$DEVICE_PORT" --baud 1200 read_mac 2>/dev/null | grep -qi -m1 'MAC'; then
		echo "ESP chip responded; getting existing firmware"
		"$ESPTOOL_CMD" --port "$DEVICE_PORT" --baud 921600 read_flash 0 0x70000 "$DOWNLOAD_DIR/CURRENT.BAK" | 
		while IFS= read -r line; do 
			printf '\r%-80s' "$line" 
		done 
		printf '\n'    
		echo
		echo "Device detected:"
		grep -m1 -aoP '\.pio/libdeps/\K[^/]{0,100}' "$DOWNLOAD_DIR/CURRENT.BAK"
	else
		# ---- Y: timed-out or grep found no match -------------------------
		echo "nrf52 device"
		list_usb_block_devs
		
		if ! scan_and_maybe_mount; then
			echo "No USB mass-storage device found, sending 1200-baud reset…"
			sudo bash -c 'exec 3<> "${DEVICE_PORT}"; stty -F "${DEVICE_PORT}" 1200; sleep 1.5'
		fi
		echo "Device not in DFU mode. Connect via the app and set into DFU or unplug/re-plug quickly 2x."
		echo "Waiting for DFU"
		
		if ! scan_and_maybe_mount; then
			for ((i=0; i<60; i++)); do
				spinner
				if scan_and_maybe_mount; then
					echo
					break
				fi
				sleep 1
			done
		fi
		echo
		echo "Device detected:"
		grep -m1 -aoP '\.pio/libdeps/\K[^/]{0,100}' "$MOUNT_FOLDER/CURRENT.UF2"
	fi
	read -r -p "Press Enter to continue..."
}

# --------------------------------------------------
# MAIN
# --------------------------------------------------

rm -f  \
  "$SELECTED_DEVICE_FILE"  \
  "$ARCHITECTURE_FILE"     \
  "$ERASE_URL_FILE"        \
  "$SELECTED_ROLE_FILE"    \
  "$SELECTED_VERSION_FILE" \
  "$SELECTED_TYPE_FILE"    \
  "$SELECTED_URL_FILE"     \
  "$DOWNLOADED_FILE_FILE"  \
  "$DEVICE_PORT_FILE"
URL_PATH=''
while [[ -z $URL_PATH ]]; do
	choose_meshcore_firmware

	URL_PATH=$(cat "$SELECTED_URL_FILE")
	if [[ -z "$URL_PATH" ]]; then
		ROLE=$(cat "$SELECTED_ROLE_FILE")
		echo "$ROLE is not supported"
		rm -f "$SELECTED_ROLE_FILE"
	fi
done
[[ $URL_PATH != /* ]] && URL_PATH="/$URL_PATH"
URL="https://flasher.meshcore.dev${URL_PATH}"


download_and_verify "$URL"


choose_serial


# Stop the service.
lockedService=$(get_locked_service)
if [ -n "$lockedService" ] && [ "$lockedService" != "None" ]; then
	echo "Stopping service $lockedService..."
	sudo systemctl stop "$lockedService"
fi
echo "lockedService: $lockedService"


[[ -f "$ARCHITECTURE_FILE"    ]] && ARCHITECTURE="$(<"$ARCHITECTURE_FILE")"
[[ -f "$DEVICE_PORT_FILE"     ]] && DEVICE_PORT="$(<"$DEVICE_PORT_FILE")"
[[ -f "$DOWNLOADED_FILE_FILE"     ]] && DOWNLOADED_FILE="$(<"$DOWNLOADED_FILE_FILE")"
[[ -f "$SELECTED_DEVICE_FILE"  ]] && DEVICE="$(<"$SELECTED_DEVICE_FILE")"

if [[ "$ARCHITECTURE" =~ esp32 ]]; then
	get_espcmd
	[[ -f "$ESPTOOL_FILE"     ]] && ESPTOOL_CMD="$(<"$ESPTOOL_FILE")"
	export ESPTOOL_PORT=$DEVICE_PORT
	echo "Setting device into bootloader mode via baud 1200"
	$ESPTOOL_CMD --port "${DEVICE_PORT}" --baud 1200 read_mac || true
	
	sleep 8
	
	echo "ESP chip responded; getting existing firmware"
	"$ESPTOOL_CMD" --port "$DEVICE_PORT" --baud 921600 read_flash 0 0x70000 "$DOWNLOAD_DIR/CURRENT.BAK" | 
	while IFS= read -r line; do 
		printf '\r%-80s' "$line" 
	done 
	printf '\n'    
	echo
	echo "Device detected:"
	grep -m1 -aoP '\.pio/libdeps/\K[^/]{0,100}' "$DOWNLOAD_DIR/CURRENT.BAK"
	
	sleep 8
	
	read -r -p "Press Enter to update the ${DEVICE} firmware on port ${DEVICE_PORT}"
	$ESPTOOL_CMD --port "${DEVICE_PORT}" --baud 115200 write_flash 0x10000 "${DOWNLOADED_FILE}"
else
	echo "nrf52 device"
	list_usb_block_devs
	
	if ! scan_and_maybe_mount; then
		echo "No USB mass-storage device found, sending 1200-baud reset…"
		sudo bash -c 'exec 3<> "${DEVICE_PORT}"; stty -F "${DEVICE_PORT}" 1200; sleep 1.5'
	fi
	echo "Device not in DFU mode. Connect via the app and set into DFU or unplug/re-plug quickly 2x."
	echo "Waiting for DFU"
	
	if ! scan_and_maybe_mount; then
		for ((i=0; i<60; i++)); do
			spinner
			if scan_and_maybe_mount; then
				echo
				break
			fi
			sleep 1
		done
	fi
	echo
	echo "Device detected:"
	grep -m1 -aoP '\.pio/libdeps/\K[^/]{0,100}' "$MOUNT_FOLDER/CURRENT.UF2"
	
	read -r -p "Press Enter to update the ${DEVICE} firmware on port ${DEVICE_PORT}"
	#sudo cp -v "$DOWNLOADED_FILE" "$MOUNT_FOLDER/"
	echo ""
	echo "Firmware for nrf52 device ${DEVICE} completed on port ${DEVICE_PORT}."
	echo
fi

# Restart the stopped service.
if [ -n "$lockedService" ] && [ "$lockedService" != "None" ]; then
	echo "Starting service $lockedService..."
	sudo systemctl start "$lockedService"
fi
