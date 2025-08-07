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
#MOUNT_FOLDER="/mnt/meshDeviceSD"
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
    SELECTED_ROLE_FILE="${FIRMWARE_ROOT}/02role.txt"
 SELECTED_VERSION_FILE="${FIRMWARE_ROOT}/03version.txt"
    SELECTED_TYPE_FILE="${FIRMWARE_ROOT}/04type.txt"
     SELECTED_URL_FILE="${FIRMWARE_ROOT}/05selected_url.txt"
  DOWNLOADED_FILE_FILE="${FIRMWARE_ROOT}/06downloaded_file.txt"
           DEVICE_FILE="${FIRMWARE_ROOT}/07device_file.txt"




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
	echo "$ROLE" > "$SELECTED_ROLE_FILE"
	echo "$VERSION" > "$SELECTED_VERSION_FILE"
	echo "$TYPE" >"$SELECTED_TYPE_FILE"
    echo "$CHOSEN_FILE" >"$SELECTED_URL_FILE"
}

#############################################################################
# choose_meshcore_firmware
# Interactively select MeshCore firmware (device → role → version → type)  
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
	local ROLE=''
	local VERSION=''
    local TYPE=''
	[[ -f "$SELECTED_DEVICE_FILE"  ]] && DEVICE="$(<"$SELECTED_DEVICE_FILE")"
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
			local DEVICE=''
			while [[ -z $DEVICE ]]; do
				sleep 0.1
				echo; echo "[1] Select device:"
				select DEVICE in "${DEVICES[@]}"; do [[ -n ${DEVICE:-} ]] && break; done < /dev/tty
			done
			echo "$DEVICE"
		fi
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
	
	mkdir -p ${DOWNLOAD_DIR}/${VERSION}/

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
            echo "Only one device detected – selecting it automatically: $detected_dev"
			echo "$detected_dev" > "$DEVICE_FILE"
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
				echo "$detected_dev" > "$DEVICE_FILE"
				return
            fi
        fi
        echo "Invalid selection – please try again."
    done
}

# --------------------------------------------------
# MAIN
# --------------------------------------------------

rm -f  \
  "$SELECTED_DEVICE_FILE"      \
  "$SELECTED_ROLE_FILE"        \
  "$SELECTED_VERSION_FILE"     \
  "$SELECTED_TYPE_FILE"        \
  "$SELECTED_URL_FILE"
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

