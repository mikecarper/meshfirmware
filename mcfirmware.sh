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
VENDORLIST="elecrow|heltec|lilygo|seeed|seed|studio|rak|wireless|wisblock|wismesh|raspberry|pi|pico|waveshare|promicro|uniteng|sensecap|wio|xiao"
RADIOLIST="sx1262|sx126x|sx1276|sx127x"
NORESET="no-reset"
READMAC="read-mac"
READFLASH="read-flash"
WRITEFLASH="write-flash"
ERASEFLASH="erase-flash"
HARDRESET="hard-reset"
LOCKEDSERVICE=""

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
      | sed -E 's/^[[:space:]]*[Vv]//' \
      | awk -F'[.-]' '{ if ($1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/) print $1"."$2 }' \
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
      | grep -E "^[[:space:]]*[Vv]?(${re})(\.|$)" 2>/dev/null \
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
			# Keep only newest two branches (X.Y)
			local -a VERSIONS_SHOW=()
			filter_last_two_branches VERSIONS VERSIONS_SHOW
		
			while [[ -z $VERSION ]]; do
				sleep 0.1
				echo; echo "[3] Select version:"
				select VERSION in "${VERSIONS_SHOW[@]}"; do [[ -n $VERSION ]] && break; done < /dev/tty
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
	echo "$ARCHITECTURE" > "$ARCHITECTURE_FILE"
	echo "$ERASE_URL" > "$ERASE_URL_FILE"

	echo "$VERSION" > "$SELECTED_VERSION_FILE"
	echo "$TYPE" > "$SELECTED_TYPE_FILE"
    echo "$CHOSEN_FILE" > "$SELECTED_URL_FILE"
}

pick_matching_device() {
	local usb_string="$1"
	local -n _DEVICES="$2"   # bash 4.3+ nameref to the array

	local usb_slug base core n cand1 cand2 cand3 name
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

		if is_good_tail "$cand3" && contains_word "$usb_slug" "$cand3"; then
			MATCH="${_DEVICES[$i]}"; MATCH_IDX=$((i+1)); return 0
		elif is_good_tail "$cand2" && contains_word "$usb_slug" "$cand2"; then
			MATCH="${_DEVICES[$i]}"; MATCH_IDX=$((i+1)); return 0
		elif is_good_tail "$cand1" && contains_word "$usb_slug" "$cand1"; then
			MATCH="${_DEVICES[$i]}"; MATCH_IDX=$((i+1)); return 0
		elif contains_word "$usb_slug" "$base"; then
			MATCH="${_DEVICES[$i]}"; MATCH_IDX=$((i+1)); return 0
		fi
	done

	# optional aliases
	case "$usb_slug" in
		*station_g2*) MATCH="UnitEng Station G2"; MATCH_IDX=31; return 0 ;;
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
		ERASE_URL=$( _jq1 --arg d "$DEVICE" ".device[]|select(.name==\$d)|.erase // empty" )
		[[ -n $ERASE_URL ]] && ERASE_URL="https://flasher.meshcore.dev/firmware/$ERASE_URL"
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
				echo
				echo "[2] Select role for $DEVICE:"
				select ROLE in "${ROLES[@]}"; do [[ -n ${ROLE:-} ]] && break; done < /dev/tty
			done
		fi
	fi

    # ---------------- step 3 – version ------------------------------------
	local -a VERSIONS=()
	mapfile -t VERSIONS < <( _jq1 --arg d "$DEVICE" --arg r "$ROLE" ".device[] | select(.name==\$d) | .firmware[] | select(.role==\$r) | .version | keys[]" | sort -ru )
	if ((${#VERSIONS[@]} == 0)); then
		choose_version_from_releases "$DEVICE" "$ROLE" "$ARCHITECTURE" "$ERASE_URL" ;
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
				echo; echo "[3] Select version:"
				select VERSION in "${VERSIONS_SHOW[@]}"; do [[ -n ${VERSION:-} ]] && break; done < /dev/tty
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
	local dest_file=$2
	local verify=$3
	local VERSION
	[[ -f "$SELECTED_VERSION_FILE" ]] && VERSION="$(<"$SELECTED_VERSION_FILE")"
	local bytes
	local basename
	basename=${url##*/}           # -> file.tar.gz?version=3
	basename=${basename%%[\?#]*}  # -> file.tar.gz   (removes ?version=3 or #fragment)
	local dest="${DOWNLOAD_DIR}/${VERSION}/${basename}"
	mkdir -p "${DOWNLOAD_DIR}/${VERSION}/"
	
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
		echo "Downloading firmware to $dest"
		wget -q --retry-connrefused --waitretry=1 -O "$dest" "$url" || return 1

		bytes=$(stat -c%s "$dest" 2>/dev/null);
		if (( bytes < MIN_BYTES_LOCAL )); then
			echo "Download too small ($bytes bytes < $MIN_BYTES_LOCAL); removing $dest" >&2
			rm -f "$dest"
			return 1
		fi

		echo "Downloaded $dest – $bytes bytes OK"
	else
		bytes=$(stat -c%s "$dest" 2>/dev/null);
		echo "Already downloaded $dest – $bytes bytes OK"
	fi
	
	# --------------------------------------------------
    # If the download is a ZIP, extract only the largest file
    # --------------------------------------------------
    #if file "$dest" | grep -q 'Zip archive data'; then
    #    echo "Archive detected; extracting largest file …"
    #    local largest
    #    largest=$(
    #        unzip -l "$dest" |
    #        awk 'NF>=4 && $1~/^[0-9]+$/ {size=$1; $1=$2=$3=""; sub(/^   */,""); print size "|" $0}' |
    #        sort -t'|' -k1,1n | tail -n1 | cut -d'|' -f2-
    #    )

    #    if [[ -z "$largest" ]]; then
    #        echo "ERROR: no entries in ZIP archive." >&2
    #        return 1
    #    fi

    #    unzip -oq "$dest" "$largest" -d "${DOWNLOAD_DIR}/${VERSION}/"
    #    dest="${DOWNLOAD_DIR}/${VERSION}/${largest}"   # point to extracted file
    #    echo "Extracted $largest"
    #fi

    echo "$dest" > "$dest_file"
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
            #echo "Only one device detected – selecting it automatically: $detected_dev - ${labels[0]}"
			echo "$detected_dev" > "$DEVICE_PORT_FILE"
			echo "${labels[0]}" > "$DEVICE_PORT_NAME_FILE"
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
				echo "${labels[choice-1]}" > "$DEVICE_PORT_NAME_FILE"
				return
            fi
        fi
        echo "Invalid selection – please try again."
    done
}

check_tty_lock() {
    local dev="$1"
    local lock="/var/lock/$(basename "$dev").lock"

    # open FD 3 on the lock file for the lifetime of this shell
    exec 3>"$lock" || return 1
    # try to acquire non-blocking lock
    if ! flock -n 3; then
        # still locked by someone else
        return 0
    fi
    # we own the lock; release immediately and close FD
    flock -u 3
    exec 3>&-
    # not locked by others
    return 1
}

get_locked_service() {
    local device_name=""
    [[ -f "$DEVICE_PORT_FILE" ]] && device_name="$(<"$DEVICE_PORT_FILE")"

    if [[ -z "$device_name" ]]; then
        # nothing to check yet
        return 0
    fi

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
		echo "No process found locking ${device_name}."  > /dev/tty
		return 0
	fi
	#echo "User(s): $users"

	# For each user, get all their PIDs.
	local pids
	pids=$(ps -u "$users" -o pid= | tr -s ' ' | tr '\n' ' ')

	local found_service=""
	#local last_pid=""
	for pid in $pids; do
		echo "PID: $pid" > /dev/tty

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
		echo "Service: $service"  > /dev/tty

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


esptool_set_variables() {

	echo "Checking the esptool version"
	ver="$( pipx run esptool version | grep -m1 -Eo '[0-9]+(\.[0-9]+)+' )"
	major="${ver%%.*}"
	
	if [[ "$major" =~ ^[0-9]+$ ]] && (( major >= 5 )); then
	  # X: esptool >= 5
	  NORESET="no-reset"
	  READMAC="read-mac"
	  READFLASH="read-flash"
	  WRITEFLASH="write-flash"
	  ERASEFLASH="erase-flash"
	  HARDRESET="hard-reset"
	else
	  NORESET="no_reset"
	  READMAC="read_mac"
	  READFLASH="read_flash"
	  WRITEFLASH="write_flash"
	  ERASEFLASH="erase_flash"
	  HARDRESET="hard_reset"
	fi

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
	
	# Probe for ESP32
	local ESPTOOL_CMD=""
	get_espcmd

	if ! timeout 5s $ESPTOOL_CMD --port "${DEVICE_PORT}" --after "$NORESET" --baud 1200 "$READMAC" 2>/dev/null; then
		echo "esptool failed, checking if a service has the port locked"
		# Stop the service.
		LOCKEDSERVICE=$(get_locked_service)
		if [ -n "$LOCKEDSERVICE" ] && [ "$LOCKEDSERVICE" != "None" ]; then
			echo "Stopping service $LOCKEDSERVICE..."
			sudo systemctl stop "$LOCKEDSERVICE"
			sleep 3
			timeout 5s $ESPTOOL_CMD --port "${DEVICE_PORT}" --after "$NORESET" --baud 1200 "$READMAC" 2>/dev/null || true
		fi
	fi

	[[ -f "$DEVICE_PORT_FILE"     ]] && DEVICE_PORT="$(<"$DEVICE_PORT_FILE")"

	if timeout 5s $ESPTOOL_CMD --port "$DEVICE_PORT" --after "$NORESET" --baud 1200 "$READMAC" 2>&1 | perl -pe 's/\e\[[0-9;]*[A-Za-z]//g' | sed '/^Warning: Deprecated/d' | grep -qi -m1 'MAC'; then
		echo "ESP chip responded; getting existing firmware"
		sleep 1
		$ESPTOOL_CMD --port "$DEVICE_PORT" --after "$NORESET" --baud 921600 "$READFLASH" 0x10000 0x70000 "$DOWNLOAD_DIR/CURRENT.BAK" 2>&1 | perl -pe 's/\e\[[0-9;]*[A-Za-z]//g' | sed '/^Warning: Deprecated/d'

		AUTODETECT_DEVICE=$( detect_device_from_fw "$DOWNLOAD_DIR/CURRENT.BAK" )
	
	else
		# ---- Y: timed-out or grep found no match -------------------------
		echo "nrf52 device"
		list_usb_block_devs
		
		if ! scan_and_maybe_mount; then
			echo "No USB mass-storage device found, sending 1200-baud reset..."
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
    if (/(?<![A-Za-z0-9])
          ([A-Z][A-Za-z0-9]*(?:[ _-][A-Za-z0-9]+){0,3})
          (?=[^A-Za-z0-9_]*Espressif[^A-Za-z0-9_]*Systems)/six) {
      print "$1\n"; exit
    }
  ' "$f" 2>/dev/null
}

# prints one line with fallback to .pio/libdeps/… segment
print_fw_line() {
  local label="$1" file="$2" val
  val="$(extract_name_from_firmware "$file")"
  if [[ -z "$val" ]]; then
    val="$(LC_ALL=C grep -aom1 -P '\.pio/libdeps/\K[^/\n]{1,100}' "$file" 2>/dev/null || true)"
  fi
  printf '    %s %s\n' "$label" "${val:-unknown}"
}

# wrapper that returns just the detected name (same logic as print_fw_line)
detect_device_from_fw() {
  local f="$1" v
  v="$(extract_name_from_firmware "$f")"
  [[ -z "$v" ]] && v="$(LC_ALL=C grep -aom1 -P '\.pio/libdeps/\K[^/\n]{1,100}' "$f" 2>/dev/null || true)"
  printf '%s\n' "${v:-unknown}"
}

# --------------------------------------------------
# MAIN
# --------------------------------------------------

mkdir -p "$FIRMWARE_ROOT"

rm -f  \
  "$SELECTED_DEVICE_FILE"   \
  "$ARCHITECTURE_FILE"      \
  "$ERASE_URL_FILE"         \
  "$SELECTED_ROLE_FILE"     \
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
choose_serial

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
[[ $URL_PATH != /* ]] && URL_PATH="/$URL_PATH"
URL="https://flasher.meshcore.dev${URL_PATH}"


download_and_verify "$URL" "$DOWNLOADED_FILE_FILE" 1




[[ -f "$ARCHITECTURE_FILE"    ]] && ARCHITECTURE="$(<"$ARCHITECTURE_FILE")"
[[ -f "$DEVICE_PORT_FILE"     ]] && DEVICE_PORT="$(<"$DEVICE_PORT_FILE")"
[[ -f "$DOWNLOADED_FILE_FILE" ]] && DOWNLOADED_FILE="$(<"$DOWNLOADED_FILE_FILE")"
[[ -f "$SELECTED_DEVICE_FILE" ]] && DEVICE="$(<"$SELECTED_DEVICE_FILE")"

echo "Architecture: $ARCHITECTURE"
if [[ "$ARCHITECTURE" =~ esp32 ]]; then

	get_espcmd
	[[ -f "$ESPTOOL_FILE"     ]] && ESPTOOL_CMD="$(<"$ESPTOOL_FILE")"
	export ESPTOOL_PORT=$DEVICE_PORT
	echo "Setting device ${DEVICE} on ${DEVICE_PORT} into bootloader mode via baud 1200"
	if ! $ESPTOOL_CMD --port "${DEVICE_PORT}" --after "$NORESET" --baud 1200 "$READMAC" 2>/dev/null; then
		echo "esptool failed, checking if a service has the port locked"
		# Stop the service.
		LOCKEDSERVICE=$(get_locked_service)
		if [ -n "$LOCKEDSERVICE" ] && [ "$LOCKEDSERVICE" != "None" ]; then
			echo "Stopping service $LOCKEDSERVICE..."
			sudo systemctl stop "$LOCKEDSERVICE"
			sleep 3
			$ESPTOOL_CMD --port "${DEVICE_PORT}" --after "$NORESET" --baud 1200 "$READMAC" 2>/dev/null || true
		fi
	fi
	
	echo
	echo
	echo "ESP chip responded; getting existing firmware"
	sleep 0.5
	echo "$ESPTOOL_CMD --port $DEVICE_PORT --baud 921600 $READFLASH 0x10000 0x70000 $DOWNLOAD_DIR/CURRENT.BAK"
	$ESPTOOL_CMD --port "$DEVICE_PORT" --after "$NORESET" --baud 921600 "$READFLASH" 0x10000 0x70000 "$DOWNLOAD_DIR/CURRENT.BAK" 2>/dev/null || true
	echo
	print_fw_line "    Device firmware:" "$DOWNLOAD_DIR/CURRENT.BAK"
	print_fw_line "Downloaded firmware:" "$DOWNLOADED_FILE"
	
	[[ -f "$SELECTED_TYPE_FILE"    ]] && TYPE="$(<"$SELECTED_TYPE_FILE")"
	echo
	echo "Commands that will be ran."
	
	if [[ "$TYPE" == "flash-wipe" ]]; then

		echo "$ESPTOOL_CMD --port ${DEVICE_PORT} --after $NORESET --baud 115200 $ERASEFLASH"
		echo "$ESPTOOL_CMD --port ${DEVICE_PORT} --after $HARDRESET --baud 115200 $WRITEFLASH 0x0000 \"${DOWNLOADED_FILE}\""
		read -r -p "Press Enter to ERASE and INSTALL the ${DEVICE} firmware on port ${DEVICE_PORT}"
		$ESPTOOL_CMD --port "${DEVICE_PORT}" --after "$NORESET" --baud 115200 "$ERASEFLASH"
		sleep 1
		$ESPTOOL_CMD --port "${DEVICE_PORT}" --after "$HARDRESET" --baud 115200 "$WRITEFLASH" 0x0000 "${DOWNLOADED_FILE}"
	else
		echo "$ESPTOOL_CMD --port ${DEVICE_PORT} --after $HARDRESET --baud 115200 $WRITEFLASH 0x10000 \"${DOWNLOADED_FILE}\""
		read -r -p "Press Enter to UPDATE the ${DEVICE} firmware on port ${DEVICE_PORT}"
		$ESPTOOL_CMD --port "${DEVICE_PORT}" --after "$HARDRESET" --baud 115200 "$WRITEFLASH" 0x10000 "${DOWNLOADED_FILE}"
	fi
	
else
	echo "nrf52 device"
	echo "Downloaded firmware: $DOWNLOADED_FILE"

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
	
	echo "Getting the latest version of adafruit-nrfutil"
	pipx run adafruit-nrfutil version

	echo "Running ${ACTION}..."

	if [[ $ACTION == "flash-wipe" ]]; then

		[[ -f "$ERASE_URL_FILE" ]] && ERASE_URL="$(<"$ERASE_URL_FILE")"
		download_and_verify "$ERASE_URL" "$ERASE_FILE_FILE" 0
		[[ -f "$ERASE_FILE_FILE" ]] && ERASE_FILE="$(<"$ERASE_FILE_FILE")"
		
		echo "Erasing UF2 area using $ERASE_FILE"
		sleep 1
		adafruit-nrfutil dfu serial --package "$ERASE_FILE" --touch 1200 -p ${DEVICE_PORT} -b 115200
		echo "Erase done."
		echo
	fi

	echo "Flashing firmware file $DOWNLOADED_FILE..."
	sleep 1
	adafruit-nrfutil dfu serial --package "$DOWNLOADED_FILE" --touch 1200 -p ${DEVICE_PORT} -b 115200
	echo
	echo "Firmware ${ACTION} completed for ${DEVICE} on ${DEVICE_PORT}."
fi

# Restart the stopped service.
if [ -n "$LOCKEDSERVICE" ] && [ "$LOCKEDSERVICE" != "None" ]; then
	echo "Starting service $LOCKEDSERVICE..."
	sudo systemctl start "$LOCKEDSERVICE"
fi
