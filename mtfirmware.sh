#!/usr/bin/env bash
#
: <<'EOF'

# To run this file, copy this line below and run it.
cd ~ && wget -qO - https://raw.githubusercontent.com/mikecarper/meshfirmware/refs/heads/main/mtfirmware.sh | bash

#
EOF

# Strict errors.
# Trap errors and output file and line number.
set -euo pipefail

# Ensure we always restore on exit
cleanup() {
	local usb_autosuspend_end

	# These helpers are defined later in the file, but are available for every
	# normal exit after main execution begins. Keep cleanup idempotent because an
	# ERR path invokes it before the EXIT trap invokes it again.
	if declare -F release_nrf52_owned_mount >/dev/null 2>&1; then
		release_nrf52_owned_mount || true
	fi
	if declare -F release_all_nrf52_flash_locks >/dev/null 2>&1; then
		release_all_nrf52_flash_locks || true
	fi
	if declare -F restart_locked_service_if_needed >/dev/null 2>&1; then
		restart_locked_service_if_needed || true
	fi

	usb_autosuspend_end=$(cat /sys/module/usbcore/parameters/autosuspend 2>/dev/null || true)
	if [[ -n "${USB_AUTOSUSPEND:-}" && -n "$usb_autosuspend_end" \
		&& "$usb_autosuspend_end" != "$USB_AUTOSUSPEND" ]]; then
		echo "$USB_AUTOSUSPEND" | sudo tee /sys/module/usbcore/parameters/autosuspend >/dev/null || true
	fi
	if [[ -n "${NRF52_MOUNT_STATE_FILE:-}" && -e "$NRF52_MOUNT_STATE_FILE" \
		&& ! -s "$NRF52_MOUNT_STATE_FILE" ]]; then
		rm -f -- "$NRF52_MOUNT_STATE_FILE"
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
VERSION_ARG=""
OPERATION_ARG=""
RUN_UPDATE=false

# Global variable to track the spinner index.
spinner_index=0
# Array holding the spinner characters.
spinner_chars=("-" "\\" "|" "/")

#########################
# Configuration Variables
#########################
# Define the repo
REPO_OWNER="meshtastic"
REPO_NAME="firmware"
REPO_NAME_ALT="meshtastic.github.io"
CACHE_TIMEOUT_SECONDS=$((6 * 3600)) # 6 hours
MOUNT_FOLDER="/mnt/meshDeviceSD"
NRF52_MOUNT_FOLDER="${MOUNT_FOLDER}.nrf52.${UID}.${BASHPID}"
NRF52_DFU_TIMEOUT_SECONDS=180
NRF52_MANUAL_DFU_PROMPT_SECONDS=20
NRF52_POST_FLASH_CHECK_TIMEOUT_SECONDS=60
NRF52_SELECTED_SERIAL=""
NRF52_SELECTED_PATH_STEM=""
NRF52_SELECTED_VENDOR_ID=""
NRF52_EXPECTED_VERSION=""
NRF52_FLASH_PRE_KIND=""
NRF52_FLASH_PRE_PATH=""
NRF52_FLASH_PRE_INSTANCE=""
NRF52_MOUNT_STATE_FILE="$(mktemp)"
NRF52_FLASH_LOCK_FILE="${XDG_RUNTIME_DIR:-/tmp}/mtfirmware-nrf52-${UID}.lock"
NRF52_FLASH_LOCK_FD=""
NRF52_FLASH_LOCK_DEPTH=0
USB_AUTOSUSPEND=$(cat /sys/module/usbcore/parameters/autosuspend)
if [[ "$USB_AUTOSUSPEND" -ne -1 ]]; then
	# Only disable (-1) if it isn't already
	echo "sudo needed to disable USB autosuspend and keep all USB ports active."
	echo -1 | sudo tee /sys/module/usbcore/parameters/autosuspend >/dev/null
fi

# Settings for the repo
        GITHUB_API_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases"
          REPO_API_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME_ALT}/contents"
 WEB_HARDWARE_LIST_URL="https://raw.githubusercontent.com/${REPO_OWNER}/web-flasher/refs/heads/main/public/data/hardware-list.json"
NRF52_ERASE_BASE_URL="https://flasher.meshcore.io/firmware"
NRF52_ERASE_FALLBACK_BASE_URL="https://files.brazio.org/meshcore/erase"
# Set Folders
         FIRMWARE_ROOT="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}"
          DOWNLOAD_DIR="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}/downloads"
# Vars to get passed around and cached as files.
         RELEASES_FILE="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}/releases.json"
        RESOURCES_FILE="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}/hardware-list.json"
		   BLEOTA_FILE="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}/bleota.json"
    VERSIONS_TAGS_FILE="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}/01versions_tags.txt"
  VERSIONS_LABELS_FILE="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}/02versions_labels.txt"
       CHOSEN_TAG_FILE="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}/03chosen_tag.txt"
 DOWNLOAD_PATTERN_FILE="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}/04download_pattern.txt"
      DEVICE_INFO_FILE="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}/05device_info.txt"
 DETECTED_PRODUCT_FILE="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}/06detected_product.txt"
   MATCHING_FILES_FILE="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}/07matching_files.txt"
              CMD_FILE="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}/08cmd.txt"
    SELECTED_FILE_FILE="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}/09selected_file.txt"
        OPERATION_FILE="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}/10operation.txt"
     ARCHITECTURE_FILE="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}/11architecture.txt"

for f in \
  "$VERSIONS_TAGS_FILE" \
  "$VERSIONS_LABELS_FILE" \
  "$CHOSEN_TAG_FILE" \
  "$DOWNLOAD_PATTERN_FILE" \
  "$DEVICE_INFO_FILE" \
  "$DETECTED_PRODUCT_FILE" \
  "$MATCHING_FILES_FILE" \
  "$CMD_FILE" \
  "$SELECTED_FILE_FILE" \
  "$OPERATION_FILE" \
  "$ARCHITECTURE_FILE"
do
  rm -f -- "$f"
done

#########################
# Function Definitions
#########################

spinner() {
	# Print the spinner character (using \r to overwrite the same line)
	printf "\r%s" "${spinner_chars[spinner_index]}" >/dev/tty
	# Update the index, wrapping around to 0 when reaching the end of the array.
	spinner_index=$(((spinner_index + 1) % ${#spinner_chars[@]}))
}

# Display help and usage.
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
		--version)
			shift
			VERSION_ARG="$1"
			;;
		--install)
			if [ -n "$OPERATION_ARG" ] && [ "$OPERATION_ARG" != "install" ]; then
				echo "Error: Conflicting options specified."
				exit 1
			fi
			OPERATION_ARG="install"
			;;
		--update)
			if [ -n "$OPERATION_ARG" ] && [ "$OPERATION_ARG" != "update" ]; then
				echo "Error: Conflicting options specified."
				exit 1
			fi
			OPERATION_ARG="update"
			;;
		--run)
			RUN_UPDATE=true
			;;
		-h | --help)
			show_help
			;;
		*)
			echo "Unknown option: $1"
			show_help
			;;
		esac
		shift
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
				sudo apt-get update || return 1
				PACKAGE_METADATA_UPDATED=1
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

	echo "$command_name not found - installing..."
	if [ "$#" -gt 0 ]; then
		install_packages "$@"
	else
		install_packages "$command_name"
	fi
}

ensure_pipx_uv_backend() {
	local bootstrap_pipx resolved_backend uv_binary

	ensure_command pipx
	export PATH="${HOME}/.local/bin:${PATH}"
	hash -r

	uv_binary="$(pipx environment --value PIPX_UV_BINARY 2>/dev/null || true)"
	if [[ -z "$uv_binary" || ! -x "$uv_binary" ]]; then
		bootstrap_pipx="$(command -v pipx)"
		echo "Installing a current pipx with the uv backend..." >&2
		"$bootstrap_pipx" install --force 'pipx[uv]'
		hash -r
	fi

	export PIPX_DEFAULT_BACKEND=uv
	uv_binary="$(pipx environment --value PIPX_UV_BINARY 2>/dev/null || true)"
	resolved_backend="$(pipx environment --value PIPX_RESOLVED_BACKEND 2>/dev/null || true)"
	if [[ -z "$uv_binary" || ! -x "$uv_binary" || "$resolved_backend" != "uv" ]]; then
		echo "Could not enable the pipx uv backend." >&2
		return 1
	fi
}

ensure_commands() {
	local command_name

	for command_name in "$@"; do
		ensure_command "$command_name"
	done
}

# Update the GitHub release cache if needed.
update_releases() {
	if check_internet; then
		ensure_commands curl jq

		# If we don't have a cache file or it's older than our timeout, attempt an update.
		if [ ! -f "$RELEASES_FILE" ] || [ "$(date +%s)" -ge "$(($(stat -c %Y "$RELEASES_FILE") + CACHE_TIMEOUT_SECONDS))" ]; then
			mkdir -p "$FIRMWARE_ROOT"
			echo "Updating release cache from GitHub. $RELEASES_FILE $GITHUB_API_URL"

			# Download into a temp file first
			tmpfile=$(mktemp)
			curl -s "$GITHUB_API_URL" -o "$tmpfile" || {
				echo "Failed to download release data."
				rm -f "$tmpfile"
				return
			}

			# Check if the newly downloaded file is valid JSON
			if ! errmsg=$(jq -e . "$tmpfile" 2>&1 >/dev/null); then
				echo "Downloaded file is not valid JSON:"
				echo "$errmsg"
				rm -f "$tmpfile"
				return 1
			fi

			# Filter out "download_count" keys from the JSON.
			# This jq filter defines a recursive walk function.
			filtered_tmp=$(mktemp)
			jq 'def walk(f):
                  . as $in
                  | if type=="object" then
                        reduce keys[] as $key ({}; . + { ($key): ($in[$key] | walk(f)) })
                    elif type=="array" then map(walk(f))
                    else . end;
                walk(if type=="object" then del(.download_count) else . end)' "$tmpfile" >"$filtered_tmp" || {
				echo "Failed to filter JSON."
				rm -f "$tmpfile" "$filtered_tmp"
				return
			}

			# Use the filtered JSON for further processing.
			if [ ! -f "$RELEASES_FILE" ]; then
				mv "$filtered_tmp" "$RELEASES_FILE"
				rm -f "$tmpfile"
			else
				# Compare the MD5 sums of the cached file and the newly filtered file.
				old_md5=$(md5sum "$RELEASES_FILE" | awk '{print $1}')
				new_md5=$(md5sum "$filtered_tmp" | awk '{print $1}')
				if [ "$old_md5" != "$new_md5" ]; then
					echo "Release data changed. Updating cache and removing cached version lists. $old_md5 $new_md5"
					mv "$filtered_tmp" "$RELEASES_FILE"
					rm -f "${VERSIONS_TAGS_FILE}" "${VERSIONS_LABELS_FILE}"
				else
					echo "Release data is unchanged. $old_md5 $new_md5"
					rm -f "$filtered_tmp"
				fi
				rm -f "$tmpfile"
			fi
		else
			echo "Using cached release data (updated within the last 6 hours)."
		fi
	else
		echo "No internet connection; using cached release data if available."
	fi
}

update_bleota() {
	if check_internet; then
		ensure_commands curl jq

		# If we don't have a cache file or it's older than our timeout, attempt an update.
		if [ ! -f "$BLEOTA_FILE" ] || [ "$(date +%s)" -ge "$(($(stat -c %Y "$BLEOTA_FILE") + CACHE_TIMEOUT_SECONDS))" ]; then
			mkdir -p "$FIRMWARE_ROOT"
			echo "Checking if bluetooth over the air bin files from GitHub needs to be updated. $BLEOTA_FILE $REPO_API_URL"

			# Download into a temp file first
			tmpfile=$(mktemp)
			curl -s "$REPO_API_URL" -o "$tmpfile" || {
				echo "Failed to download release data."
				rm -f "$tmpfile"
				return
			}
			
			# Check if the newly downloaded file is valid JSON
			if ! errmsg=$(jq -e . "$tmpfile" 2>&1 >/dev/null); then
				echo "Downloaded file is not valid JSON:"
				echo "$errmsg"
				rm -f "$tmpfile"
				return 1
			fi
			
			# Use the filtered JSON for further processing.
			if [ ! -f "$BLEOTA_FILE" ]; then
				mv "$tmpfile" "$BLEOTA_FILE"
			else
				# Compare the MD5 sums of the cached file and the newly filtered file.
				old_md5=$(md5sum "$BLEOTA_FILE" | awk '{print $1}')
				new_md5=$(md5sum "$tmpfile" | awk '{print $1}')
				if [ "$old_md5" != "$new_md5" ]; then
					echo "Release data changed. Updating cache and removing cached version lists. $old_md5 $new_md5"
					mv "$tmpfile" "$BLEOTA_FILE"
				else
					touch "$BLEOTA_FILE"
				fi
			fi
		fi
		firmware_dir_list=$(cat "${BLEOTA_FILE}")	

		# Get a list of firmware directories sorted in reverse order (latest first).
		firmware_folders=$(echo "$firmware_dir_list" \
		  | jq -r '.[] | select(.type=="dir") | select(.name | startswith("firmware")) | .name' \
		  | sort -r)

		attempt=1
		found_folder=""

		# Loop over each folder in firmware_folders, but only try up to 3.
		for folder in $firmware_folders; do

			folder_url="${REPO_API_URL}/${folder}"
			folder_contents=$(curl -s "$folder_url")
			
			# Filter for files that start with "bleota"
			file_urls=$(echo "$folder_contents" \
			  | jq -r '.[] | select(.type=="file") | select(.name | startswith("bleota")) | .download_url')
			
			if [ -n "$file_urls" ]; then
				found_folder="$folder"
				break
			fi
			
			attempt=$((attempt+1))
			if [ $attempt -gt 3 ]; then
				break
			fi
			echo "Attempt $attempt: Checking folder: $folder"
		done
		
		if [ -z "$found_folder" ]; then
			echo "No files starting with 'bleota' found in up to 3 firmware folders."
			exit 1
		fi
		
		# Proceed with processing of $found_folder:
		selected_file=$(cat "${SELECTED_FILE_FILE}")
		folder=$(dirname "$selected_file")
		folder_url="${REPO_API_URL}/${found_folder}"
		folder_contents=$(curl -s "$folder_url")
		file_urls=$(echo "$folder_contents" \
		  | jq -r '.[] | select(.type=="file") | select(.name | startswith("bleota")) | .download_url')

		# Download each matching file, but only if it doesn't exist already.
		for url in $file_urls; do
		  filename=$(basename "$url")
		  destination="$folder/$filename"
		  if [ ! -f "$destination" ]; then
			echo "Downloading $filename from $url..."
			curl -s -L -o "$destination" "$url"
		  fi
		done
	else
		echo "Use local versions"
		#bleota.bin
		#bleota-s3.bin
		#bleota-c3.bin
	fi
	echo ""
}

update_hardware_list() {
	# Check if RESOURCES_FILE exists and is newer than 6 hours; if not, download it.
	if [ ! -f "$RESOURCES_FILE" ] || [ "$(find "$RESOURCES_FILE" -mmin +360)" ]; then
		ensure_command curl
		echo "Downloading resources.ts from GitHub. $RESOURCES_FILE $WEB_HARDWARE_LIST_URL"
		mkdir -p "$(dirname "$RESOURCES_FILE")"
		curl -s -L "$WEB_HARDWARE_LIST_URL" -o "$RESOURCES_FILE"
	fi
}

# Retrieve release JSON data from the cache.
get_release_data() {
	if [ ! -f "$RELEASES_FILE" ]; then
		echo "No cached release data available. Exiting."
		exit 1
	fi
	cat "$RELEASES_FILE"
}

# Normalize strings (remove dashes, underscores, spaces, and convert to lowercase).
normalize() {
	echo "$1" | tr '[:upper:]' '[:lower:]' | tr -d '[:blank:]' | tr -d '-' | tr -d '_'
}

# Build the release menu and save version tags and labels.
build_release_menu() {
	local releases_json="$1"
	# We'll build a temporary list of entries in the format: date<TAB>tag<TAB>label
	local tmpfile
	tmpfile=$(mktemp)

	echo "Parsing JSON and adding built firmware entry if available."

	# Process JSON releases
	while IFS=$'\t' read -r tag prerelease draft body created_at; do
		spinner
		# Determine suffix based on the tag.
		suffix=""
		# Strip time from created_at date
		date="${created_at}"
		suffix="$date"

		if [[ "$tag" =~ [Aa]lpha ]]; then
			suffix="$suffix (alpha)"
		elif [[ "$tag" =~ [Bb]eta ]]; then
			suffix="$suffix (beta)"
		elif [[ "$tag" =~ [Rr][Cc] ]]; then
			suffix="$suffix (rc)"
		fi

		# Override suffix based on draft or prerelease flags.
		if [ "$draft" = "true" ]; then
			suffix="$suffix (draft)"
		elif [ "$prerelease" = "true" ]; then
			suffix="$suffix (pre-release)"
		fi

		tag="${tag#v}"

		label=$(printf "%-14s" "$tag")
		label="$label $suffix"

		# Check for the warning emoji in body.
		if echo "$body" | grep -q -- '[WARN]'; then
			label="! $label"
		else
			label="  $label"
		fi

		# Write the entry to the temporary file.
		echo -e "${date}\t${tag}\t${label}" >> "$tmpfile"
		spinner
	done < <(echo "$releases_json" | jq -r '.[] | [.tag_name, .prerelease, .draft, .body, .created_at] | @tsv')

    # Check if any subdirectory name in FIRMWARE_ROOT (skip "downloads") is not in the tag_names from above.
	for folder in "$FIRMWARE_ROOT"/*; do
		# Skip if not a directory.
		[ -d "$folder" ] || continue
		folder_name=$(basename "$folder")
		
		# Skip the downloads folder.
		if [ "$folder_name" = "downloads" ]; then
			continue
		fi
		
		# Convert folder name to lowercase for matching.
		folder_lower=$(echo "$folder_name" | tr '[:upper:]' '[:lower:]')
		if [[ "$folder_lower" == v* ]]; then
			folder_lower="${folder_lower:1}"
		fi
		
		# Check if this folder name is present (case-insensitive) anywhere in $tmpfile.
		if ! grep -qi "$folder_lower" "$tmpfile"; then		
			# Find the first firmware-* file in the folder.
			first_file=$(find "$folder" -maxdepth 1 -type f -iname "firmware-*" | head -n 1)
			if [ -n "$first_file" ]; then
				mtime=$(date -u -d "$(stat -c %y "$first_file")" +"%Y-%m-%dT%H:%M:%SZ")
			else
				# Fallback: if no firmware-* file is found, use the folder's modification time.
				mtime=$(date -u -d "$(stat -c %y "$folder")" +"%Y-%m-%dT%H:%M:%SZ")
			fi
			
			# Build the label: version tag, then date, then "(nightly)"
			label="! ${folder_name} ${mtime} (nightly)"
			
			# Write the entry to the temporary file.
			# Format: date<TAB>tag<TAB>label
			echo -e "${mtime}\t${folder_name}\t${label}" >> "$tmpfile"
		fi
	done

	# Sort all entries by date in descending order (newest first)
	local sorted_entries
	sorted_entries=$(sort -r "$tmpfile")
	rm "$tmpfile"

	# Build arrays from the sorted entries.
	declare -a versions_tags=()
	declare -a versions_labels=()

	while IFS=$'\t' read -r date tag label; do
		versions_tags+=("$tag")
		versions_labels+=("$label")
	done <<< "$sorted_entries"

	# Save the arrays for later use.
	printf "%s\n" "${versions_tags[@]}" >"${VERSIONS_TAGS_FILE}"
	printf "%s\n" "${versions_labels[@]}" >"${VERSIONS_LABELS_FILE}"
	printf "\r"
}

# Allow the user to select a firmware release version.
select_release() {
	local versions_tags versions_labels chosen_index auto_selected i selection selection_num
	local term_width max_len col_label_width col_width num_per_row num_entries index_width
	local label formatted pre_colored stable_colored
	local yellow green cyan reset

	# Use tput to set color codes.
	red=$(tput setaf 1)    # Red for unreleased versions.
	yellow=$(tput setaf 3) # Yellow for pre-releases.
	green=$(tput setaf 2)  # Green for the first stable entry.
	cyan=$(tput setaf 6)   # Cyan for the latest stable (without "!" or pre-release).
	reset=$(tput sgr0)     # Reset.

	# Load cached arrays from file.
	readarray -t versions_tags <"$VERSIONS_TAGS_FILE"
	readarray -t versions_labels <"$VERSIONS_LABELS_FILE"

	# Determine the latest stable candidate: the first entry that does NOT start with "!" and does NOT contain "(pre-release)".
	local latest_stable_index=-1
	for i in "${!versions_labels[@]}"; do
		label="${versions_labels[$i]}"
		if [[ "$label" != "!"* ]] && [[ "$label" != *"(pre-release)"* ]]; then
			latest_stable_index=$i
			break
		fi
	done

	if [ -n "$VERSION_ARG" ]; then
		for i in "${!versions_tags[@]}"; do
			if [[ "${versions_tags[$i]}" == *${VERSION_ARG}* ]]; then
				auto_selected="${versions_labels[$i]}"
				chosen_index=$i
				break
			fi
		done
		if [ -z "$auto_selected" ]; then
			echo "No release version found matching --version $VERSION_ARG"
			exit 1
		fi
	else
		echo "Available firmware release versions:"

		# Determine the current terminal width.
		term_width=$(tput cols)

		# Find the maximum label length so we know how wide to make each label field.
		max_len=0
		for label in "${versions_labels[@]}"; do
			if ((${#label} > max_len)); then
				max_len=${#label}
			fi
		done

		# Figure out how many digits we need for the highest index (the total count).
		num_entries=${#versions_labels[@]}
		index_width=${#num_entries} # Number of digits in the total count.

		# Decide how wide we want the label portion itself (allow a little extra padding).
		col_label_width=$((max_len + 2))

		# The total column width = index portion + ") " + label portion + space.
		col_width=$((index_width + 2 + col_label_width + 1))

		# How many columns fit in our adjusted terminal width?
		num_per_row=$((term_width / col_width))
		if [ $num_per_row -lt 1 ]; then
			num_per_row=1
		fi

		# Flags to track whether we've already colored a pre-release or a stable entry.
		pre_colored=0
		stable_colored=0

		# Print the list in dynamically determined columns.
        # --- 1) Collect all formatted entries into an array ---
        declare -a formatted_entries=()

		for i in "${!versions_labels[@]}"; do
			label="${versions_labels[$i]}"
			formatted=$(printf "%*d) %-*s " "$index_width" $((i + 1)) "$col_label_width" "$label")

			# If the label contains "nightly" (case-insensitive), color it red.
			if [[ "$label" =~ [Nn]ightly ]]; then
				formatted="${red}${formatted}${reset}"
			# If this entry is the latest stable candidate, color it cyan.
			elif [ "$i" -eq "$latest_stable_index" ]; then
				formatted="${cyan}${formatted}${reset}"
			# Otherwise, apply yellow to the first pre-release and green to the first stable entry.
			elif [[ "$label" == *"(pre-release)"* ]] && [ $pre_colored -eq 0 ]; then
				formatted="${yellow}${formatted}${reset}"
				pre_colored=1
			elif [[ "$label" != *"(pre-release)"* ]] && [ $stable_colored -eq 0 ]; then
				formatted="${green}${formatted}${reset}"
				stable_colored=1
			fi

			# Print the (possibly colored) entry.
			formatted_entries+=( "$formatted" )
		done

        # --- Now print that array in reverse order ---
        total=${#formatted_entries[@]}
        rowcount=0
        #num_per_row=${num_per_row:-1}

        for (( idx=total-1; idx>=0; idx-- )); do
            # Print the (possibly colored) entry.
            printf "%s" "${formatted_entries[$idx]}"
            (( rowcount++ )) || true
            # Every time we hit 'num_per_row' entries in a row, insert a newline.
            if (( rowcount % num_per_row == 0 )); then
                echo ""
            fi
        done

        # If the last row wasn't full, make sure we end on a newline.
        if (( rowcount % num_per_row != 0 )); then
            echo ""
        fi

		echo ""
		while true; do
			read -r -p "Enter the number of your selection [1-$num_entries]: " selection </dev/tty
			if [[ "$selection" =~ ^[0-9]+$ ]]; then
				selection_num=$((10#$selection))
				if (( selection_num >= 1 && selection_num <= num_entries )); then
					break
				fi
			fi
			echo "Invalid selection. Please enter a number from 1 to $num_entries."
		done
		chosen_index=$((selection_num - 1))
	fi
	tag="${versions_tags[$chosen_index]}"

	# Save the selected tag to the cached file.
	echo "${tag}" > "${CHOSEN_TAG_FILE}"
}

# Download firmware assets for the chosen release.
download_assets() {
	local releases_json chosen_tag download_pattern assets StreamOutput
	releases_json=$(get_release_data)
	chosen_tag=$(cat "${CHOSEN_TAG_FILE}")
	download_pattern="-${chosen_tag}"

	mapfile -t assets < <(
		echo "$releases_json" | jq -r --arg TAG "$chosen_tag" '
        .[] | select((.tag_name | ltrimstr("v")) == $TAG) | .assets[] |
        select(.name | test("^firmware-"; "i")) |
        select(.name | test("debug"; "i") | not) |
        {name: .name, url: .browser_download_url} | @base64'
	)
	mkdir -p "$DOWNLOAD_DIR"
	
	# Search for lingering temporary files in the DOWNLOAD_DIR
	tmp_files=$(find "$DOWNLOAD_DIR" -maxdepth 1 -type f -name '*.tmp*')
	if [ -n "$tmp_files" ]; then
		echo "Found temporary files in $DOWNLOAD_DIR:"
		echo "$tmp_files"
		echo "Cleaning them up..."
		find "$DOWNLOAD_DIR" -maxdepth 1 -type f -name '*.tmp*' -delete
	fi

	if [ ${#assets[@]} -eq 0 ]; then
		echo "No firmware assets found for release $chosen_tag matching criteria."
		exit 1
	fi

	StreamOutput=0
	for asset in "${assets[@]}"; do
		local decoded asset_name asset_url local_file
		decoded=$(echo "$asset" | base64 --decode)
		asset_name=$(echo "$decoded" | jq -r '.name')
		asset_url=$(echo "$decoded" | jq -r '.url')
		local_file="${DOWNLOAD_DIR}/${asset_name}"
		if [ -f "$local_file" ]; then
			echo "Already downloaded $asset_name "
			StreamOutput=1
			printf "\r"
			tput cuu1
		else
			if [ $StreamOutput -eq 1 ]; then
				echo ""
				StreamOutput=0
			fi
			tmp_file=$(mktemp --tmpdir="$DOWNLOAD_DIR" "${asset_name}.tmp.XXXXXX")
			echo "Downloading $asset_name $asset_url"
			if curl -SL --progress-bar -o "$tmp_file" "$asset_url"; then
			    mv "$tmp_file" "$local_file"
			else
				echo "Download failed for $asset_name"
				rm -f "$tmp_file"
			fi
			printf "\r"
			tput cuu1
			tput cuu1
			tput el
		fi
	done
	if [ $StreamOutput -eq 1 ]; then
		echo ""
	fi
	echo "$download_pattern" >"${DOWNLOAD_PATTERN_FILE}"
}

# Unzip downloaded firmware assets into the appropriate folder structure.
unzip_assets() {
	local chosen_tag download_pattern asset product target_dir releases_json StreamOutput
	chosen_tag=$(cat "${CHOSEN_TAG_FILE}")
	download_pattern=$(cat "${DOWNLOAD_PATTERN_FILE}")
	releases_json=$(get_release_data)

	mapfile -t assets < <(
		echo "$releases_json" | jq -r --arg TAG "$chosen_tag" '
        .[] | select((.tag_name | sub("^v";"")) == $TAG) | .assets[] |
        select(.name | test("^firmware-"; "i")) |
        select(.name | test("debug"; "i") | not) |
        {name: .name} | @base64'
	)

	StreamOutput=0
	for asset in "${assets[@]}"; do
		local decoded asset_name
		decoded=$(echo "$asset" | base64 --decode)
		asset_name=$(echo "$decoded" | jq -r '.name')
		local_file="${DOWNLOAD_DIR}/${asset_name}"
		if [[ "$asset_name" =~ ^firmware-([^-\ ]+)-(.+)\.zip$ ]]; then
			product="${BASH_REMATCH[1]}"
			target_dir="${FIRMWARE_ROOT}/${chosen_tag}/${product}"
			mkdir -p "$target_dir"
			if [ -z "$(ls -A "$target_dir" 2>/dev/null)" ]; then
				if [ $StreamOutput -eq 1 ]; then
					echo ""
				fi

				echo "Unzipping $asset_name into $target_dir..."
				unzip -o "$local_file" -d "$target_dir"
				StreamOutput=0
			else
				if [ $StreamOutput -eq 0 ]; then
					echo "Files already exist for "
					echo "$asset_name "
					StreamOutput=1
				else
					echo "$asset_name "
				fi
				printf "\r"
				tput cuu1
			fi
		else
			echo "Asset $asset_name does not match expected naming convention. Skipping unzip."
		fi
	done
	if [ $StreamOutput -eq 1 ]; then
		echo ""
	fi
}

# Detect the connected USB device.
serial_port_from_detection() {
	local detection="${1:-}"
	local port

	if [[ "$detection" == *"-> "* ]]; then
		port="${detection##*-> }"
	else
		port="$detection"
	fi
	printf '%s' "$port" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
}

detect_device() {
	# /dev/ttyACM0
	local selected_port

	detected_dev=$(pick_serial_port)
	echo "$detected_dev" >"${DEVICE_INFO_FILE}"
	normalize "$detected_dev" >"${DETECTED_PRODUCT_FILE}"

	# Save the physical USB identity at the same moment the user chooses the
	# device. A tty number can be reused while releases download or menus are
	# open, so discovering identity later could bind flashing to another board.
	NRF52_SELECTED_SERIAL=""
	NRF52_SELECTED_PATH_STEM=""
	NRF52_SELECTED_VENDOR_ID=""
	selected_port="$(serial_port_from_detection "$detected_dev")"
	if [[ -n "$selected_port" && -e "$selected_port" ]]; then
		capture_nrf52_selected_identity "$selected_port" >/dev/null 2>&1 || true
	fi
}

pick_serial_port() {
  local -a ports=()
  local -a labels=()
  local p idlabel i choice choice_num auto

  # Gather candidates (prefer ACM before USB)
  while IFS= read -r p; do
    ports+=("$p")
  done < <(
    for g in /dev/ttyACM* /dev/ttyUSB*; do
      [[ -e "$g" ]] && printf '%s\n' "$g"
    done | sort -V
  )

  if ((${#ports[@]} == 0)); then
    echo "No /dev/ttyACM* or /dev/ttyUSB* devices found." >&2
    return 0
  fi

  # Single hit? Just return it.
  if ((${#ports[@]} == 1)); then
    printf '%s\n' "${ports[0]}"
    return 0
  fi
  
  echo "Making sure python meshtastic is ready to go (can take 2 minutes first time)" >&2
  pipx run meshtastic --version >/dev/null 2>&1;
	echo "Checking each device" >&2

	# Build nice labels using /dev/serial/by-id if present
	local oldest_meshtastic_idx=""
	local oldest_meshtastic_ver=""
		local version_key
	local devdevice metadata version role hwModel

	for i in "${!ports[@]}"; do
	  spinner
	  p="${ports[$i]}"
	  idlabel=""

	  if [[ -d /dev/serial/by-id ]]; then
		while IFS= read -r link; do
		  [[ -L "$link" && "$(readlink -f "$link")" == "$p" ]] || continue

			devdevice="$(readlink -f "$link")"
			spinner
			spinner
			metadata="$(probe_meshtastic_metadata "$devdevice" 2>/dev/null || true)"
			spinner

		  version="$(echo "$metadata" | awk -F': ' '/^firmware_version:/ {print $2; exit}')"
		  role="$(echo "$metadata" | awk -F': ' '/^role:/ {print $2; exit}')"
		  hwModel="$(echo "$metadata" | awk -F': ' '/^hw_model:/ {print $2; exit}')"
		  linkbase=$(basename "$link")

		  if [[ -n "$version" ]]; then
			idlabel="${hwModel} || Meshtastic ${role} ${version}"

			# Normalize version into a sortable key:
			#   2.6.11 -> 000002000006000011
			# Handles optional leading "v"
			version_key="$(
			  echo "$version" \
				| sed 's/^[^0-9]*//' \
				| awk -F. '{
					a=($1==""?0:$1)
					b=($2==""?0:$2)
					c=($3==""?0:$3)
					printf "%06d%06d%06d\n", a, b, c
				  }'
			)"

			if [[ -z "$oldest_meshtastic_idx" ]]; then
			  oldest_meshtastic_idx="$i"
			  oldest_meshtastic_ver="$version_key"
			elif [[ "$version_key" < "$oldest_meshtastic_ver" ]]; then
			  oldest_meshtastic_idx="$i"
			  oldest_meshtastic_ver="$version_key"
			fi
		  else
			idlabel="$linkbase"
		  fi

		  break
		done < <(find /dev/serial/by-id -mindepth 1 -maxdepth 1 -type l 2>/dev/null)
	  fi

	  labels+=("$idlabel -> $p")
	done
	printf "\r" >&2

	# Auto selection:
	# 1) oldest Meshtastic version if any were detected
	# 2) otherwise prefer first ACM
	# 3) otherwise first USB
	if [[ -n "$oldest_meshtastic_idx" ]]; then
	  auto=$((oldest_meshtastic_idx + 1))
	else
	  for i in "${!ports[@]}"; do
		if [[ "${ports[$i]}" =~ ^/dev/ttyACM[0-9]+$ ]]; then
		  auto=$((i + 1))
		  break
		fi
	  done
	  [[ -z "$auto" ]] && auto=1
	fi

  echo "Select serial port (0 = Auto):" >&2
  printf '  0) Auto -> %s\n' "${labels[$((auto - 1))]}" >&2
  for i in "${!labels[@]}"; do
    printf '  %2d) %s\n' "$((i + 1))" "${labels[$i]}" >&2
  done

  while true; do
    read -rp "Choice [0-${#ports[@]}]: " choice
    [[ -z "$choice" ]] && choice=0
    if [[ "$choice" =~ ^[0-9]+$ ]]; then
      choice_num=$((10#$choice))
      if (( choice_num >= 0 && choice_num <= ${#ports[@]} )); then
        break
      fi
    fi
    echo "Invalid choice. Please enter a number from 0 to ${#ports[@]}." >&2
  done

	if (( choice_num == 0 )); then
	  printf '%s\n' "${labels[$((auto - 1))]}"
	else
	  printf '%s\n' "${labels[$((choice_num - 1))]}"
	fi
}

# Match the firmware files against the detected device.
match_firmware_files() {
	local chosen_tag download_pattern detected_product
	chosen_tag=$(cat "${CHOSEN_TAG_FILE}")
	download_pattern=$(cat "${DOWNLOAD_PATTERN_FILE}")
	detected_product="$(normalize "$(cat "${DETECTED_PRODUCT_FILE}")")"
	detected_info_file=$(cat "${DEVICE_INFO_FILE}")
	device_name=$(echo "$detected_info_file" | awk -F'-> ' '{print $1}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
	device_port_name=$(echo "$detected_info_file" | awk -F'-> ' '{print $2}')
	echo "$device_port_name"
	
	USBproducts="$(
	  lsusb -v 2>/dev/null | awk '
		/iProduct/ {
		  line = $0
		  if (line ~ /Controller/) next
		  if (line ~ / LAN/) next
		  if (line ~ / Hub/) next

		  sub(/.*2[[:space:]]+/, "", line)
		  sub(/[[:space:]].*/, "", line)

		  print tolower(line)
		}
	  ' || true
	)"

	found=0
	USBproduct=""

	while IFS= read -r usb; do
	  [[ -z "$usb" ]] && continue
	  usb_norm="$(normalize "$usb")"

	  while IFS= read -r line; do
		[[ -z "$line" ]] && continue
		detected_norm="$(normalize "$line")"

		if [[ "$detected_norm" == *"$usb_norm"* ]] || [[ "$usb_norm" == *"$detected_norm"* ]]; then
		  found=1
		  USBproduct="$usb_norm"
		  break
		fi
	  done <<< "$detected_info_file"

	  (( found )) && break
	done <<< "$USBproducts"

		
	declare -A product_files
	declare -A product_files_full

	while IFS= read -r -d '' file; do
		local fname prod prodNorm base
		fname="$(basename "$file")"

		if [[ "$fname" =~ ^(firmware-)(.*)${download_pattern//v/}(-update)?(\.factory)?\.(bin|uf2|zip)$ ]]; then
			prod="${BASH_REMATCH[2]}"
			prodNorm="$(normalize "$prod")"

			if [[ $prodNorm =~ ^(.+?)(tft|inkhud|eink)$ ]]; then
				base="${BASH_REMATCH[1]}"
			else
				base="$prodNorm"
			fi

			product_files["$base"]+="$file"$'\n'
			product_files_full["$base"]+="$prod"$'\n'
		fi
		spinner
	done < <(find "$FIRMWARE_ROOT/${chosen_tag}" -type f \( -iname "firmware-*" \) -print0)

	matching_keys=()
	if [[ -n "${detected_product:-}" ]] && ((${#product_files[@]} > 0)); then
		for prod in "${!product_files[@]}"; do
			local norm_prod
			norm_prod="$(normalize "$prod")"

			if [[ "$norm_prod" == *"$detected_product"* ]] || [[ "$detected_product" == *"$norm_prod"* ]]; then
				printf '\r'
				echo "Firmware file match on: $(printf '%s\n' "${product_files_full[$prod]}" | head -n1)"
				matching_keys+=("$prod")
			fi
			spinner
		done
	fi

	if [ -z "${matching_files+x}" ] || [ ${#matching_files[@]} -eq 0 ]; then
		IFS=$'\n' read -r -d '' -a matching_files < <(
			for key in "${matching_keys[@]}"; do
				echo "${product_files[$key]}"
				spinner
			done
			printf '\0'
		)
	fi

	printf "\r"
	if [ ${#matching_files[@]} -eq 0 ] && [ -n "$USBproduct" ]; then
		echo "Doing a deep search for $USBproduct in $FIRMWARE_ROOT/${chosen_tag}/*"
		# Capture all matching file paths (each on a new line)
		found_files=$(grep -aFrin --exclude="*-ota.zip" "$USBproduct" "$FIRMWARE_ROOT/${chosen_tag}" | cut -d: -f1 || true)

		if [ -z "$found_files" ]; then
			echo "No firmware files match the detected product ($detected_product) ($USBproduct). Exiting."
			exit 1
		fi
		
		# Filter the found files so that only files whose basename starts with "firmware-" are kept.
		found_files=$(echo "$found_files" | while IFS= read -r line; do
			base=$(basename "$line")
			if [[ "$base" == firmware-* ]]; then
				echo "$line"
			fi
		done)

		# Populate matching_files array with all found file paths.
		IFS=$'\n' read -r -d '' -a matching_files < <(
			echo "$found_files"
			printf '\0'
		)

	fi

	# If no matches are found for the device, fall back to all firmware files in the chosen tag.
	if (( ${#matching_files[@]} == 0 )); then
		echo "No firmware matched for the detected device: $detected_product"
		mapfile -t matching_files < <(
			find "$FIRMWARE_ROOT/${chosen_tag}" -type f \( -iname "firmware-*" \) -print0 |
			while IFS= read -r -d '' file; do
				printf '%s\t%s\n' "$(basename "$file")" "$file"
				spinner >&2
			done |
			LC_ALL=C sort -f -V -k1,1 -k2,2 |
			cut -f2-
		)
		printf "\r" >&2
	fi

	# Sort and de-dupe whatever branch produced matching_files
	readarray -t matching_files < <(
		for file in "${matching_files[@]}"; do
			[[ -z "$file" ]] && continue

			base="${file##*/}"

			if [[ "$base" =~ ^firmware-(.*)-${download_pattern//v/}(-update)?(\.factory)?\.(bin|uf2|zip)$ ]]; then
				prod="${BASH_REMATCH[1]}"
			else
				prod="$base"
			fi

			sort_key="$(normalize "$prod")"

			case "$base" in
				*.factory.bin) rank=2 ;;
				*.bin)         rank=1 ;;
				*.uf2)         rank=3 ;;
				*.zip)         rank=4 ;;
				*)             rank=9 ;;
			esac

			printf '%s\t%02d\t%s\n' "$sort_key" "$rank" "$file"
		done |
		LC_ALL=C sort -t $'\t' -k1,1 -k2,2n -k3,3f |
		awk -F'\t' '!seen[$3]++ { print $3 }'
	)

	printf "%s\n" "${matching_files[@]}" >"${MATCHING_FILES_FILE}"
}

# Determine whether to perform an update or install operation.
choose_operation() {
	readarray -t matching_files <"${MATCHING_FILES_FILE}"
	selected_file=$(cat "${SELECTED_FILE_FILE}")
	architecture=$(cat "${ARCHITECTURE_FILE}")

	local operation
	operation="update"
	if [ -n "$OPERATION_ARG" ]; then
		operation="$OPERATION_ARG"
	else
		if echo "$architecture" | grep -qi "esp32"; then
			if [[ "$selected_file" == *"-update"* ]]; then
				operation="update"
			elif [[ "$selected_file" == *".factory"* ]]; then 
				operation="install"
			else
				operation="update"
			fi
		fi
	fi

	echo "$operation" >"${OPERATION_FILE}"
	if ! is_nrf52_serial_dfu_candidate "$architecture" "$selected_file"; then
		echo "Operation chosen: $operation"
	fi
}

# Let the user select which firmware file to use if multiple are found.
select_firmware_file() {
    local selected_file file_choice file_choice_num count_candidates idx_width
    local detected_info_file device_port_name
    local -a matching_files=()
    local -a firmware_candidates=()

    readarray -t matching_files < "${MATCHING_FILES_FILE}"

    if (( ${#matching_files[@]} == 0 )); then
        echo "No matching files found." >&2
        exit 1
    fi

    for f in "${matching_files[@]}"; do
        [[ -z "$f" ]] && continue
        if [[ "$(basename "$f")" =~ \.(bin|uf2|hex)$ ]]; then
            firmware_candidates+=("$f")
        fi
    done

    if (( ${#firmware_candidates[@]} > 0 )); then
        readarray -t firmware_candidates < <(
            for f in "${firmware_candidates[@]}"; do
                printf '%s\t%s\n' "$(basename "$f")" "$f"
            done |
            LC_ALL=C sort -f -V -k1,1 -k2,2 |
            cut -f2-
        )
    fi

    if (( ${#firmware_candidates[@]} == 1 )); then
        echo "Auto-selecting firmware candidate: $(basename "${firmware_candidates[0]}")"
        selected_file="${firmware_candidates[0]}"

    elif (( ${#firmware_candidates[@]} > 1 )); then
        echo "Multiple matching firmware candidate files found:"
        echo "  0. Pick from all matching files"

        count_candidates=${#firmware_candidates[@]}
        idx_width=${#count_candidates}

        for i in "${!firmware_candidates[@]}"; do
            printf " %${idx_width}d. %s\n" \
                "$((i + 1))" \
                "$(basename "${firmware_candidates[$i]}")"
        done

        detected_info_file="$(cat "${DEVICE_INFO_FILE}")"
        device_port_name="$(echo "$detected_info_file" | awk -F'-> ' '{print $2}')"
        echo "Current Device Info: $device_port_name"

        while true; do
            read -r -p "Select which firmware file to use [0-${#firmware_candidates[@]}]: " file_choice </dev/tty
            if [[ "$file_choice" =~ ^[0-9]+$ ]]; then
                file_choice_num=$((10#$file_choice))
                if (( file_choice_num >= 0 && file_choice_num <= ${#firmware_candidates[@]} )); then
                    break
                fi
            fi
            echo "Invalid selection. Please enter a number from 0 to ${#firmware_candidates[@]}."
        done

        if (( file_choice_num == 0 )); then
            selected_file="$(prompt_from_file_list "Select which matching file to use" "${matching_files[@]}")"
        else
            selected_file="${firmware_candidates[$((file_choice_num - 1))]}"
        fi
    else
        selected_file="$(prompt_from_file_list "Select which matching file to use" "${matching_files[@]}")"
    fi
	echo "$selected_file picked"

    echo "$selected_file" > "${SELECTED_FILE_FILE}"
}

# prompt_for_firmware:
#   Prompts the user to select from all files in the chosen tag directory.
prompt_for_firmware() {
	local chosen_tag count_choice count_choice_num i
	local -a file_list

	chosen_tag="$(cat "${CHOSEN_TAG_FILE}")"

	# Load all files under the chosen tag directory into an array
	if [[ ! -d "$FIRMWARE_ROOT/$chosen_tag" ]]; then
		echo "Firmware directory not found: $FIRMWARE_ROOT/$chosen_tag" >&2
		exit 1
	fi

	readarray -t file_list < <(
		find "$FIRMWARE_ROOT/$chosen_tag" -type f | sort
	)

	if [ "${#file_list[@]}" -eq 0 ]; then
		echo "No firmware files found in: $FIRMWARE_ROOT/$chosen_tag" >&2
		exit 1
	fi

	if [ "${#file_list[@]}" -eq 1 ]; then
		printf '%s\n' "${file_list[0]}"
		return 0
	fi

	echo "Multiple matching firmware files found:" >&2
	for i in "${!file_list[@]}"; do
		printf '  %d) %s\n' "$((i + 1))" "$(basename "${file_list[$i]}")" >&2
	done

	while true; do
		read -r -p "Select which firmware file to use [1-${#file_list[@]}]: " count_choice </dev/tty
		if [[ "$count_choice" =~ ^[0-9]+$ ]]; then
			count_choice_num=$((10#$count_choice))
			if (( count_choice_num >= 1 && count_choice_num <= ${#file_list[@]} )); then
				break
			fi
		fi
		echo "Invalid selection. Please enter a number from 1 to ${#file_list[@]}." >&2
	done

	# Return the selected full file path
	printf '%s\n' "${file_list[$((count_choice_num - 1))]}"
}

# Prompt from a provided file list
prompt_from_file_list() {
    local prompt_text="${1:-Select which firmware file to use}"
    shift

    local count_choice count_choice_num i
    local -a file_list=("$@")

    if (( ${#file_list[@]} == 0 )); then
        echo "No files available to choose from." >&2
        exit 1
    fi

    if (( ${#file_list[@]} == 1 )); then
        printf '%s\n' "${file_list[0]}"
        return 0
    fi

    echo "Multiple matching firmware files found:" >&2
    for i in "${!file_list[@]}"; do
        printf '  %d) %s\n' "$((i + 1))" "$(basename "${file_list[$i]}")" >&2
    done

    while true; do
        read -r -p "$prompt_text [1-${#file_list[@]}]: " count_choice </dev/tty
        if [[ "$count_choice" =~ ^[0-9]+$ ]]; then
            count_choice_num=$((10#$count_choice))
            if (( count_choice_num >= 1 && count_choice_num <= ${#file_list[@]} )); then
                break
            fi
        fi
        echo "Invalid selection. Please enter a number from 1 to ${#file_list[@]}." >&2
    done

    printf '%s\n' "${file_list[$((count_choice_num - 1))]}"
}

# Prepare the update/install script and adjust parameters if necessary.
prepare_script() {
	local selected_file script_to_run operation chosen_tag abs_script abs_selected
	selected_file=$(cat "${SELECTED_FILE_FILE}")
	operation=$(cat "${OPERATION_FILE}")
	chosen_tag=$(cat "${CHOSEN_TAG_FILE}")
	detected_dev=$(cat "${DEVICE_INFO_FILE}")
	device_port_name="$(serial_port_from_detection "$detected_dev")"
	architecture=$(cat "${ARCHITECTURE_FILE}")
	
	script_to_run=""
	abs_selected=""
	if [ "$selected_file" ]; then
		if echo "$architecture" | grep -qi "esp32"; then
			if [ "$operation" = "update" ]; then
				script_to_run="$(dirname "$selected_file")/device-update.sh"
			elif [ "$operation" = "install" ]; then
				pipx install esptool
				script_to_run="$(dirname "$selected_file")/device-install.sh"
				tmpfile="$(mktemp)"
				awk '
				{
				  lines[NR] = $0
				}

				# Collect indices of lines that start with $ESPTOOL_CMD and do not already have --after
				/^[[:space:]]*\$ESPTOOL_CMD/ {
				  if ($0 !~ /--after/) {
					esp_idx[++esp_count] = NR
				  }
				}

				END {
				  if (esp_count > 0) {
					for (k = 1; k <= esp_count; k++) {
					  i = esp_idx[k]
					  if (k < esp_count) {
						# all but last: add --after no-reset
						sub(/^[[:space:]]*\$ESPTOOL_CMD/, "& --after no-reset", lines[i])
					  } else {
						# last: add --after hard-reset
						sub(/^[[:space:]]*\$ESPTOOL_CMD/, "& --after hard-reset", lines[i])
					  }
					}
				  }

				  for (i = 1; i <= NR; i++) {
					print lines[i]
				  }
				}
				' "$script_to_run" > "$tmpfile"

				mv "$tmpfile" "$script_to_run"
			fi
		fi
		abs_selected="$(cd "$(dirname "$selected_file")" && pwd)/$(basename "$selected_file")"
	fi

	abs_script=""
	if [ "$script_to_run" ]; then
		if [ ! -x "$script_to_run" ]; then
			chmod +x "$script_to_run"
		fi
		abs_script="$(cd "$(dirname "$script_to_run")" && pwd)/$(basename "$script_to_run")"
	fi

	printf "%s\n" "$abs_script" "$abs_selected" >"${CMD_FILE}"
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
	# If the input contains "-> ", extract the part after it; otherwise, use the whole input.
	if [[ "$1" == *"-> "* ]]; then
		device_name=$(echo "$1" | awk -F'-> ' '{print $2}')
	else
		device_name="$1"
	fi
	# Accept an optional argument for the device; default to /dev/ttyACM0.
	#local device_name="/dev/ttyACM0"
	#echo "Device: $device_name"
	
	if check_tty_lock "$device_name"; then
		return 0
	fi

	# Get all users locking the device (skip the header line)
		echo "Finding the service that has $device_name locked" > /dev/tty
		local users
		ensure_command lsof
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

detect_esp() {
	selected_file=$(cat "${SELECTED_FILE_FILE}")
	chosen_tag=$(cat "${CHOSEN_TAG_FILE}")
	architecture=""
	echo "$architecture" > "${ARCHITECTURE_FILE}"
	
	if echo "$selected_file" | grep -qi "esp32"; then
		architecture="esp32"
		
		echo "$architecture" > "${ARCHITECTURE_FILE}"
		return
	fi

	if grep -E -q "${chosen_tag}.*nightly" "$VERSIONS_LABELS_FILE"; then
		update_hardware_list
		echo "Searching for the hardware type; is this ESP32?"

		# Get just the filename.
		base=$(basename "$selected_file")
		# Remove the "firmware-" prefix.
		result=${base#firmware-}
		# Remove the trailing -update.bin
		result=${result%-update.bin}
		
		# Build a pattern that should be removed at the end.
		pattern="-$chosen_tag.bin"
		# Remove the trailing pattern.
		result=${result%"$pattern"}
		
		# Build a pattern that should be removed at the end.
		pattern="-$chosen_tag"
		# Remove the trailing pattern.
		result=${result%"$pattern"}
		
		norm_device=$(normalize "$result")
		json_data=$( cat "$RESOURCES_FILE" )
		
		# Convert the JSON string to an array of objects and loop over each
		echo "$json_data" | jq -c '.[]' | while read -r entry; do
			# Extract platformioTarget and displayName using jq
			pt=$(echo "$entry" | jq -r '.platformioTarget')
			dn=$(echo "$entry" | jq -r '.displayName')

			# Normalize values (assuming you have a normalize function or just convert to lowercase)
			norm_pt=$(normalize "$pt")
			norm_dn=$(normalize "$dn")

			# If either normalized field matches the normalized device name, extract the architecture
			if [[ "$norm_pt" == *"$norm_device"* ]] || [[ "$norm_device" == *"$norm_pt"* ]] || [[ "$norm_dn" == *"$norm_device"* ]] || [[ "$norm_device" == *"$norm_dn"* ]]; then
				architecture=$(echo "$entry" | jq -r '.architecture')
				echo "$architecture" > "${ARCHITECTURE_FILE}"
				break
			fi
			spinner
		done
		printf "\r"
	fi
}

udev_device_property() {
	local device=$1
	local property=$2

	command -v udevadm >/dev/null 2>&1 || return 0
	udevadm info --query=property --name="$device" 2>/dev/null \
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

	# Match the same physical USB device across its CDC and mass-storage
	# interfaces. Keep the PCI portion intact and remove only the final USB
	# interface component (for example, :1.0) after the -usb- marker.
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

nrf52_device_identity_rank() {
	local candidate=$1
	local expected_serial="${2:-}"
	local expected_path_stem="${3:-}"
	local expected_vendor_id="${4:-}"
	local candidate_bus candidate_serial candidate_path_stem candidate_interface
	local candidate_vendor_id
	local interface_bonus=0

	candidate_bus="$(udev_device_property "$candidate" ID_BUS)"
	if [[ "$candidate_bus" != "usb" ]]; then
		printf '%s\n' 0
		return 0
	fi
	candidate_serial="$(normalize_usb_serial_identity \
		"$(udev_device_property "$candidate" ID_SERIAL_SHORT)")"
	expected_serial="$(normalize_usb_serial_identity "$expected_serial")"
	candidate_vendor_id="$(normalize_usb_serial_identity \
		"$(udev_device_property "$candidate" ID_VENDOR_ID)")"
	expected_vendor_id="$(normalize_usb_serial_identity "$expected_vendor_id")"
	candidate_path_stem="$(nrf52_usb_path_stem \
		"$(udev_device_property "$candidate" ID_PATH)")"
	if [[ -z "$candidate_path_stem" || -z "$expected_vendor_id" \
		|| "$candidate_vendor_id" != "$expected_vendor_id" ]]; then
		printf '%s\n' 0
		return 0
	fi
	candidate_interface="$(udev_device_property "$candidate" ID_USB_INTERFACE_NUM)"
	if [[ "$candidate_interface" =~ ^0+$ ]]; then
		interface_bonus=10
	fi

	# The physical USB path is the strongest match across re-enumeration. Require
	# the selected USB vendor even when a bootloader omits its serial, and reject
	# a conflicting published serial. Serial plus vendor and a real USB path is
	# the fallback for VMs that move a device to another virtual USB path.
	if [[ -n "$expected_path_stem" \
		&& "$candidate_path_stem" == "$expected_path_stem" ]]; then
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
	else
		printf '%s\n' 0
	fi
}

capture_nrf52_selected_identity() {
	local port=$1
	local live_port

	live_port="$(readlink -f "$port" 2>/dev/null || true)"
	[[ -n "$live_port" && -e "$live_port" ]] || {
		echo "The selected nRF52 serial port is no longer present: $port" >&2
		return 1
	}
	NRF52_SELECTED_SERIAL="$(normalize_usb_serial_identity \
		"$(udev_device_property "$live_port" ID_SERIAL_SHORT)")"
	NRF52_SELECTED_PATH_STEM="$(nrf52_usb_path_stem \
		"$(udev_device_property "$live_port" ID_PATH)")"
	NRF52_SELECTED_VENDOR_ID="$(normalize_usb_serial_identity \
		"$(udev_device_property "$live_port" ID_VENDOR_ID)")"
	if [[ -z "$NRF52_SELECTED_PATH_STEM" || -z "$NRF52_SELECTED_VENDOR_ID" ]]; then
		echo "Cannot preserve a stable USB identity for $port; refusing nRF52 flashing." >&2
		return 1
	fi
}

is_uf2_mount_dir() {
	local mount_dir=$1

	[[ -d "$mount_dir" ]] || return 1
	[[ -f "$mount_dir/INFO_UF2.TXT" || -f "$mount_dir/CURRENT.UF2" || -f "$mount_dir/INDEX.HTM" ]]
}

nrf52_uf2_mount_source() {
	local mount_dir=$1
	local source

	source="$(findmnt -rn -o SOURCE --target "$mount_dir" 2>/dev/null | head -n1)"
	[[ -n "$source" ]] || return 1
	printf '%s\n' "$source"
}

record_nrf52_owned_mount() {
	local source=$1
	local mount_dir=$2

	[[ -n "${NRF52_MOUNT_STATE_FILE:-}" ]] || return 1
	printf '%s\t%s\n' "$source" "$mount_dir" >"$NRF52_MOUNT_STATE_FILE"
}

release_nrf52_owned_mount() {
	local source mount_dir current_source
	local source_resolved current_resolved

	[[ -n "${NRF52_MOUNT_STATE_FILE:-}" && -s "$NRF52_MOUNT_STATE_FILE" ]] || return 1
	IFS=$'\t' read -r source mount_dir <"$NRF52_MOUNT_STATE_FILE"
	[[ -n "$source" && -n "$mount_dir" ]] || return 1

	if ! mountpoint -q "$mount_dir"; then
		rm -f -- "$NRF52_MOUNT_STATE_FILE"
		return 0
	fi
	current_source="$(nrf52_uf2_mount_source "$mount_dir" || true)"
	source_resolved="$(readlink -f "$source" 2>/dev/null || true)"
	current_resolved="$(readlink -f "$current_source" 2>/dev/null || true)"
	if [[ "$current_source" != "$source" \
		&& ( -z "$source_resolved" || "$current_resolved" != "$source_resolved" ) ]]; then
		echo "Refusing to unmount $mount_dir because its source changed from $source to ${current_source:-unknown}." >&2
		return 1
	fi
	if ! sudo umount -- "$mount_dir"; then
		echo "Could not unmount script-owned nRF52 UF2 volume at $mount_dir." >&2
		return 1
	fi
	rm -f -- "$NRF52_MOUNT_STATE_FILE"
	sudo rmdir -- "$mount_dir" 2>/dev/null || true
}

find_mounted_uf2_dir() {
	local expected_serial=$1
	local expected_path_stem=$2
	local expected_vendor_id=$3
	local source mount_dir rank best_rank=0
	local -a matches=()
	local -A seen_sources=()

	while read -r source mount_dir; do
		[[ -n "$source" && -n "$mount_dir" && -e "$source" ]] || continue
		is_uf2_mount_dir "$mount_dir" || continue
		rank="$(nrf52_device_identity_rank "$source" \
			"$expected_serial" "$expected_path_stem" "$expected_vendor_id")"
		[[ "$rank" =~ ^[0-9]+$ ]] || continue
		(( rank > 0 )) || continue
		if (( rank > best_rank )); then
			best_rank=$rank
			matches=("$mount_dir")
			seen_sources=(["$source"]=1)
		elif (( rank == best_rank )) && [[ -z "${seen_sources[$source]+x}" ]]; then
			matches+=("$mount_dir")
			seen_sources["$source"]=1
		fi
	done < <(findmnt -rn -o SOURCE,TARGET 2>/dev/null)

	if ((${#matches[@]} == 1)); then
		printf '%s\n' "${matches[0]}"
		return 0
	fi
	if ((${#matches[@]} > 1)); then
		echo "Refusing ambiguous UF2 mounts for the selected nRF52: ${matches[*]}" >&2
		return 2
	fi
	return 1
}

find_uf2_mount_dir() {
	local expected_serial=$1
	local expected_path_stem=$2
	local expected_vendor_id=$3
	local mounted_dir mounted_status=0
	local device_name type fstype rank best_rank=0
	local -a matches=()

	if [[ -z "$expected_path_stem" || -z "$expected_vendor_id" ]]; then
		echo "A stable selected nRF52 identity is required before searching for UF2 storage." >&2
		return 1
	fi
	if mounted_dir="$(find_mounted_uf2_dir \
		"$expected_serial" "$expected_path_stem" "$expected_vendor_id")"; then
		printf '%s\n' "$mounted_dir"
		return 0
	else
		mounted_status=$?
		(( mounted_status == 2 )) && return 2
	fi

	while read -r device_name type fstype; do
		[[ -n "$device_name" ]] || continue
		[[ "$type" == "disk" || "$type" == "part" ]] || continue
		[[ "$fstype" == "vfat" || "$fstype" == "msdos" || "$fstype" == "exfat" ]] || continue
		rank="$(nrf52_device_identity_rank "$device_name" \
			"$expected_serial" "$expected_path_stem" "$expected_vendor_id")"
		[[ "$rank" =~ ^[0-9]+$ ]] || continue
		(( rank > 0 )) || continue
		if (( rank > best_rank )); then
			best_rank=$rank
			matches=("$device_name")
		elif (( rank == best_rank )); then
			matches+=("$device_name")
		fi
	done < <(lsblk -nrpo NAME,TYPE,FSTYPE 2>/dev/null)

	if ((${#matches[@]} != 1)); then
		if ((${#matches[@]} > 1)); then
			echo "Refusing ambiguous UF2 block devices for the selected nRF52: ${matches[*]}" >&2
		fi
		return 1
	fi
	if mountpoint -q "$NRF52_MOUNT_FOLDER"; then
		if ! release_nrf52_owned_mount; then
			echo "$NRF52_MOUNT_FOLDER is already mounted but is not a script-owned nRF52 UF2 volume." >&2
			return 1
		fi
	fi

	sudo mkdir -p "$NRF52_MOUNT_FOLDER"
	if ! sudo mount "${matches[0]}" "$NRF52_MOUNT_FOLDER" 2>/dev/null; then
		echo "Could not mount the selected nRF52 UF2 device ${matches[0]}." >&2
		return 1
	fi
	if ! record_nrf52_owned_mount "${matches[0]}" "$NRF52_MOUNT_FOLDER"; then
		sudo umount -- "$NRF52_MOUNT_FOLDER" 2>/dev/null || true
		echo "Could not record ownership of the selected nRF52 UF2 mount." >&2
		return 1
	fi
	if is_uf2_mount_dir "$NRF52_MOUNT_FOLDER"; then
		printf '%s\n' "$NRF52_MOUNT_FOLDER"
		return 0
	fi
	echo "The selected USB block device did not contain a UF2 bootloader volume." >&2
	release_nrf52_owned_mount || true
	return 1
}

list_serial_devs() {
	local path

	for path in /dev/ttyACM* /dev/ttyUSB*; do
		[[ -e "$path" ]] && printf '%s\n' "$path"
	done | sort -V
}

find_nrf52_serial_port_by_identity() {
	local expected_serial=$1
	local expected_path_stem=$2
	local expected_vendor_id=$3
	local preferred_port="${4:-}"
	local candidate live_candidate rank best_rank=0
	local -a candidates=() matches=()
	local -A seen_candidates=()

	if [[ -z "$expected_path_stem" || -z "$expected_vendor_id" ]]; then
		return 1
	fi
	[[ -n "$preferred_port" ]] && candidates+=("$preferred_port")
	while IFS= read -r candidate; do
		[[ -n "$candidate" ]] && candidates+=("$candidate")
	done < <(list_serial_devs)

	for candidate in "${candidates[@]}"; do
		live_candidate="$(readlink -f "$candidate" 2>/dev/null || true)"
		[[ -n "$live_candidate" && -e "$live_candidate" ]] || continue
		[[ -z "${seen_candidates[$live_candidate]+x}" ]] || continue
		seen_candidates["$live_candidate"]=1
		rank="$(nrf52_device_identity_rank "$live_candidate" \
			"$expected_serial" "$expected_path_stem" "$expected_vendor_id")"
		[[ "$rank" =~ ^[0-9]+$ ]] || continue
		(( rank > 0 )) || continue
		if (( rank > best_rank )); then
			best_rank=$rank
			matches=("$live_candidate")
		elif (( rank == best_rank )); then
			matches+=("$live_candidate")
		fi
	done

	if ((${#matches[@]} == 1)); then
		printf '%s\n' "${matches[0]}"
		return 0
	fi
	if ((${#matches[@]} > 1)); then
		echo "Refusing ambiguous serial ports for the selected nRF52: ${matches[*]}" >&2
		return 2
	fi
	return 1
}

is_nrf52_arch() {
	echo "${1:-}" | grep -Eqi 'nrf52|nrf52840'
}

is_nrf52_serial_dfu_candidate() {
	local architecture=$1
	local firmware_file=$2
	local folder leaf stem metadata_file

	if is_nrf52_arch "$architecture"; then
		return 0
	fi

	leaf="$(basename "$firmware_file")"
	case "${leaf,,}" in
		*.uf2|*.hex|*.zip) ;;
		*) return 1 ;;
	esac

	folder="$(dirname "$firmware_file")"
	stem="${leaf%.*}"
	metadata_file="${folder}/${stem}.mt.json"
	if [[ -f "$metadata_file" ]] &&
		grep -Eiq '"(architecture|mcu)"[[:space:]]*:[[:space:]]*"nrf52(840)?"' "$metadata_file" &&
		grep -Eiq '"requiresDfu"[[:space:]]*:[[:space:]]*true' "$metadata_file"; then
		return 0
	fi

	if echo "$folder" | grep -Eqi 'nrf52|nrf52840'; then
		return 0
	fi

	[[ -f "${folder}/${stem}-ota.zip" ]]
}

get_firmware_metadata_display_name() {
	local firmware_file=$1
	local folder leaf stem metadata_file

	folder="$(dirname "$firmware_file")"
	leaf="$(basename "$firmware_file")"
	stem="${leaf%.*}"
	metadata_file="${folder}/${stem}.mt.json"

	if [[ -f "$metadata_file" ]]; then
		sed -nE 's/.*"displayName"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' "$metadata_file" | head -n 1
	fi
}

nrf52_firmware_version_from_artifact() {
	local firmware_file=$1

	if [[ ! -f "$firmware_file" ]]; then
		echo "Cannot inspect the selected nRF52 firmware artifact: $firmware_file" >&2
		return 1
	fi
	if [[ -z "${PYTHON:-}" || ! -x "$PYTHON" ]]; then
		echo "A Python interpreter is required to inspect the selected nRF52 firmware artifact." >&2
		return 1
	fi

	"$PYTHON" - "$firmware_file" <<'PY'
import json
import pathlib
import re
import struct
import sys
import zipfile


MAX_IMAGE_SIZE = 16 * 1024 * 1024
UF2_BLOCK_SIZE = 512
UF2_MAGIC_START0 = 0x0A324655
UF2_MAGIC_START1 = 0x9E5D5157
UF2_MAGIC_END = 0x0AB16F30
UF2_FLAG_NOFLASH = 0x00000001


def fail(message):
    print(f"Cannot derive the selected nRF52 firmware version: {message}", file=sys.stderr)
    raise SystemExit(1)


def checked_size(data, description):
    if not data:
        fail(f"{description} is empty")
    if len(data) > MAX_IMAGE_SIZE:
        fail(f"{description} is larger than {MAX_IMAGE_SIZE} bytes")
    return data


def decode_uf2(data):
    if len(data) % UF2_BLOCK_SIZE:
        fail("the UF2 length is not a whole number of 512-byte blocks")

    records = {}
    advertised_counts = set()
    block_count = len(data) // UF2_BLOCK_SIZE
    for offset in range(0, len(data), UF2_BLOCK_SIZE):
        block = data[offset : offset + UF2_BLOCK_SIZE]
        start0, start1, flags, target, payload_size, block_number, total_blocks = struct.unpack_from(
            "<7I", block, 0
        )
        end_magic = struct.unpack_from("<I", block, 508)[0]
        if (start0, start1, end_magic) != (
            UF2_MAGIC_START0,
            UF2_MAGIC_START1,
            UF2_MAGIC_END,
        ):
            fail(f"invalid UF2 magic in block {offset // UF2_BLOCK_SIZE}")
        if payload_size == 0 or payload_size > 476:
            fail(f"invalid UF2 payload size {payload_size}")
        if total_blocks:
            advertised_counts.add(total_blocks)
        if block_number in records:
            fail(f"duplicate UF2 block number {block_number}")
        records[block_number] = (flags, target, block[32 : 32 + payload_size])

    if len(advertised_counts) > 1:
        fail("UF2 blocks disagree about the total block count")
    if advertised_counts and next(iter(advertised_counts)) != block_count:
        fail("UF2 advertised block count does not match its file length")
    if set(records) != set(range(block_count)):
        fail("UF2 block numbers are incomplete")

    flash_records = sorted(
        (target, payload)
        for flags, target, payload in records.values()
        if not (flags & UF2_FLAG_NOFLASH)
    )
    if not flash_records:
        fail("UF2 contains no flash payload")

    image = bytearray()
    previous_end = None
    for target, payload in flash_records:
        if previous_end is not None:
            if target < previous_end:
                fail("UF2 flash payloads overlap")
            if target > previous_end:
                image.append(0)
        image.extend(payload)
        previous_end = target + len(payload)
    return checked_size(bytes(image), "decoded UF2 image")


def decode_intel_hex(data):
    memory = {}
    address_base = 0
    saw_eof = False
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        fail("Intel HEX is not ASCII")

    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        if saw_eof:
            fail(f"Intel HEX contains data after EOF on line {line_number}")
        if not line.startswith(":"):
            fail(f"Intel HEX line {line_number} has no record marker")
        try:
            record = bytes.fromhex(line[1:])
        except ValueError:
            fail(f"Intel HEX line {line_number} is not hexadecimal")
        if len(record) < 5 or len(record) != record[0] + 5 or sum(record) & 0xFF:
            fail(f"Intel HEX line {line_number} has an invalid length or checksum")
        count = record[0]
        address = (record[1] << 8) | record[2]
        record_type = record[3]
        payload = record[4 : 4 + count]
        if record_type == 0x00:
            absolute = address_base + address
            for index, value in enumerate(payload):
                location = absolute + index
                if location in memory and memory[location] != value:
                    fail(f"Intel HEX has conflicting data at address 0x{location:X}")
                memory[location] = value
        elif record_type == 0x01:
            if count or address:
                fail("Intel HEX EOF record is malformed")
            saw_eof = True
        elif record_type == 0x02:
            if count != 2 or address:
                fail("Intel HEX extended-segment record is malformed")
            address_base = int.from_bytes(payload, "big") << 4
        elif record_type == 0x04:
            if count != 2 or address:
                fail("Intel HEX extended-linear record is malformed")
            address_base = int.from_bytes(payload, "big") << 16
        elif record_type not in (0x03, 0x05):
            fail(f"Intel HEX uses unsupported record type 0x{record_type:02X}")

    if not saw_eof or not memory:
        fail("Intel HEX has no complete application image")

    image = bytearray()
    previous = None
    for address in sorted(memory):
        if previous is not None and address != previous + 1:
            image.append(0)
        image.append(memory[address])
        previous = address
    return checked_size(bytes(image), "decoded Intel HEX image")


def image_from_zip(path):
    try:
        with zipfile.ZipFile(path) as archive:
            manifests = [entry for entry in archive.infolist() if entry.filename == "manifest.json"]
            if len(manifests) != 1 or manifests[0].file_size > 1024 * 1024:
                fail("DFU ZIP must contain one reasonably sized manifest.json")
            try:
                manifest = json.loads(archive.read(manifests[0]))
                image_name = manifest["manifest"]["application"]["bin_file"]
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                fail("DFU ZIP manifest has no valid application bin_file")
            if not isinstance(image_name, str):
                fail("DFU ZIP application bin_file is not a string")
            image_path = pathlib.PurePosixPath(image_name)
            if image_path.is_absolute() or ".." in image_path.parts:
                fail("DFU ZIP application bin_file has an unsafe path")
            images = [entry for entry in archive.infolist() if entry.filename == image_name]
            if len(images) != 1 or images[0].is_dir():
                fail("DFU ZIP does not contain exactly one declared application image")
            if images[0].file_size > MAX_IMAGE_SIZE:
                fail("DFU ZIP application image is unreasonably large")
            return checked_size(archive.read(images[0]), "DFU application image")
    except zipfile.BadZipFile:
        fail("selected ZIP is not a valid DFU archive")


artifact = pathlib.Path(sys.argv[1])
try:
    raw = checked_size(artifact.read_bytes(), "selected artifact")
except OSError as error:
    fail(f"could not read {artifact}: {error}")

suffix = artifact.suffix.lower()
if suffix == ".uf2":
    image = decode_uf2(raw)
elif suffix == ".hex":
    image = decode_intel_hex(raw)
elif suffix == ".zip":
    image = image_from_zip(artifact)
elif suffix == ".bin":
    image = raw
else:
    fail(f"unsupported artifact type {suffix or '<none>'}")

stem = artifact.name[: -len(artifact.suffix)] if artifact.suffix else artifact.name
for ending in ("-serial-dfu", "-ota", "-update", ".factory"):
    if stem.lower().endswith(ending):
        stem = stem[: -len(ending)]
filename_match = re.search(
    r"-(v?[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9A-Za-z][0-9A-Za-z._+-]{0,31})?)$",
    stem,
)
filename_version = filename_match.group(1).lstrip("vV") if filename_match else ""

boundary_left = rb"(?<![0-9A-Za-z])"
boundary_right = rb"(?![0-9A-Za-z])"
if filename_version and re.search(
    boundary_left + re.escape(filename_version.encode("ascii")) + boundary_right,
    image,
    re.IGNORECASE,
):
    print(filename_version)
    raise SystemExit(0)

# Normal Meshtastic builds embed APP_VERSION as major.minor.patch plus a git
# identifier. A fourth component of at least four characters excludes ordinary
# library versions and IPv4 literals. If a renamed custom artifact disagrees
# with its filename, this embedded value is the only truthful runtime version.
full_pattern = re.compile(
    boundary_left
    + rb"v?([0-9]+\.[0-9]+\.[0-9]+\.[0-9A-Za-z][0-9A-Za-z_-]{3,31})"
    + boundary_right,
    re.IGNORECASE,
)
embedded_versions = sorted(
    {match.group(1).decode("ascii") for match in full_pattern.finditer(image)},
    key=str.lower,
)
if len(embedded_versions) != 1:
    if not embedded_versions:
        fail("no corroborated Meshtastic APP_VERSION was found in the application image")
    fail("multiple possible APP_VERSION strings were found: " + ", ".join(embedded_versions))

embedded_version = embedded_versions[0]
if filename_version and embedded_version.lower() != filename_version.lower():
    print(
        f"Warning: selected artifact name says {filename_version}, but its application "
        f"image embeds {embedded_version}; verifying the flashed runtime against the "
        "embedded version.",
        file=sys.stderr,
    )
print(embedded_version)
PY
}

choose_nrf52_flash_action() {
	local device_name=$1
	local device_port_name=$2
	local choice choice_num

	while true; do
		echo "Choose firmware action for ${device_name} on ${device_port_name}:" >&2
		echo "  1) flash-update       (write only)" >&2
		echo "  2) flash-wipe + flash (erase, then write)" >&2
		read -r -p "Selection [1/2]: " choice </dev/tty
		if [[ "$choice" =~ ^[0-9]+$ ]]; then
			choice_num=$((10#$choice))
			case "$choice_num" in
				1) printf '%s\n' "flash-update"; return 0 ;;
				2) printf '%s\n' "flash-wipe"; return 0 ;;
			esac
		fi
		echo "Invalid choice. Please enter 1 or 2." >&2
	done
}

resolve_nrf52_reference_package() {
	local firmware_file=$1
	local folder leaf stem candidate

	folder="$(dirname "$firmware_file")"
	leaf="$(basename "$firmware_file")"

	if [[ "$leaf" == *.zip ]]; then
		printf '%s\n' "$firmware_file"
		return 0
	fi

	stem="${leaf%.*}"
	candidate="${folder}/${stem}-ota.zip"
	if [[ -f "$candidate" ]]; then
		printf '%s\n' "$candidate"
		return 0
	fi

	echo "Could not find matching nRF52 OTA package for metadata: ${candidate}" >&2
	return 1
}

convert_uf2_to_intel_hex() {
	local uf2_file=$1
	local hex_file=$2

	"$PYTHON" - "$uf2_file" "$hex_file" <<'PY'
import pathlib
import struct
import sys

uf2_path = pathlib.Path(sys.argv[1])
hex_path = pathlib.Path(sys.argv[2])
data = uf2_path.read_bytes()

MAGIC0 = 0x0A324655
MAGIC1 = 0x9E5D5157
MAGIC_END = 0x0AB16F30
blocks = {}

for offset in range(0, max(0, len(data) - 511), 512):
    block = data[offset:offset + 512]
    if len(block) != 512:
        continue
    start0, start1 = struct.unpack_from("<II", block, 0)
    end_magic, = struct.unpack_from("<I", block, 508)
    if start0 != MAGIC0 or start1 != MAGIC1 or end_magic != MAGIC_END:
        continue
    target, payload_size = struct.unpack_from("<II", block, 12)
    if payload_size <= 0 or payload_size > 476:
        continue
    blocks[target] = block[32:32 + payload_size]

if not blocks:
    raise SystemExit(f"No UF2 payload blocks were found in {uf2_path}")

def record(record_type, address, payload=b""):
    values = bytes([len(payload), (address >> 8) & 0xFF, address & 0xFF, record_type]) + payload
    checksum = (-sum(values)) & 0xFF
    return ":" + values.hex().upper() + f"{checksum:02X}"

lines = []
current_upper = None
for base in sorted(blocks):
    payload = blocks[base]
    for index in range(0, len(payload), 16):
        chunk = payload[index:index + 16]
        address = base + index
        upper = (address >> 16) & 0xFFFF
        if upper != current_upper:
            lines.append(record(4, 0, bytes([(upper >> 8) & 0xFF, upper & 0xFF])))
            current_upper = upper
        lines.append(record(0, address & 0xFFFF, chunk))

lines.append(":00000001FF")
hex_path.write_text("\n".join(lines) + "\n", encoding="ascii")
PY
}

get_nrf52_dfu_metadata() {
	local reference_package=$1

	"$PYTHON" - "$reference_package" <<'PY'
import json
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as zf:
    with zf.open("manifest.json") as manifest_file:
        manifest = json.load(manifest_file)

init = manifest["manifest"]["application"]["init_packet_data"]
sd_req = init.get("softdevice_req") or []
print(
    str(init["application_version"]),
    str(init["device_revision"]),
    str(init["device_type"]),
    ",".join(f"0x{int(value):X}" for value in sd_req),
)
PY
}

resolve_nrf52_dfu_package() {
	local firmware_file=$1
	local reference_file=${2:-$firmware_file}
	local reference_package folder leaf stem hex_file zip_file input_file metadata app_version dev_revision dev_type sd_req is_erase_file

	if [[ "$firmware_file" == *.zip ]]; then
		printf '%s\n' "$firmware_file"
		return 0
	fi

	reference_package="$(resolve_nrf52_reference_package "$reference_file")"
	folder="$(dirname "$firmware_file")"
	leaf="$(basename "$firmware_file")"
	is_erase_file=false
	if [[ "$leaf" == Meshtastic_nRF52_factory_erase_v3_S140_*.uf2 ]]; then
		is_erase_file=true
	fi

	if ! $is_erase_file && [[ -f "$reference_package" ]]; then
		echo "Using existing nRF52 OTA DFU package: $reference_package" >&2
		printf '%s\n' "$reference_package"
		return 0
	fi

	stem="${leaf%.*}"
	hex_file="${folder}/${stem}.serial-dfu.hex"
	zip_file="${folder}/${stem}.serial-dfu.zip"

	if [[ -f "$zip_file" && "$zip_file" -nt "$firmware_file" && "$zip_file" -nt "$reference_package" ]]; then
		printf '%s\n' "$zip_file"
		return 0
	fi

	input_file="$firmware_file"
	if [[ "$firmware_file" == *.uf2 ]]; then
		echo "Converting UF2 to Intel HEX: $hex_file" >&2
		convert_uf2_to_intel_hex "$firmware_file" "$hex_file"
		input_file="$hex_file"
	fi

	read -r app_version dev_revision dev_type sd_req < <(get_nrf52_dfu_metadata "$reference_package")
	if [[ -z "${sd_req:-}" ]]; then
		echo "No SoftDevice requirement was found in $reference_package" >&2
		return 1
	fi

	echo "Generating nRF52 serial DFU package: $zip_file" >&2
	pipx run adafruit-nrfutil dfu genpkg \
		--application "$input_file" \
		--application-version "$app_version" \
		--dev-revision "$dev_revision" \
		--dev-type "$dev_type" \
		--sd-req "$sd_req" \
		"$zip_file" >&2

	printf '%s\n' "$zip_file"
}

resolve_nrf52_uf2_file() {
	local firmware_file=$1
	local folder leaf stem candidate

	folder="$(dirname "$firmware_file")"
	leaf="$(basename "$firmware_file")"

	if [[ "$leaf" == *.uf2 ]]; then
		printf '%s\n' "$firmware_file"
		return 0
	fi

	stem="${leaf%.*}"
	stem="${stem%-ota}"
	for candidate in "${folder}/${stem}.uf2" "${folder}/${stem%-ota}.uf2"; do
		if [[ -f "$candidate" ]]; then
			printf '%s\n' "$candidate"
			return 0
		fi
	done

	echo "Could not find matching nRF52 UF2 file for USB storage flashing: $firmware_file" >&2
	return 1
}

find_nrf52_erase_uf2() {
	local firmware_file=$1
	local reference_file=${2:-$firmware_file}
	local folder reference_package app_version dev_revision dev_type sd_req erase_version erase_file
	folder="$(dirname "$firmware_file")"

	reference_package="$(resolve_nrf52_reference_package "$reference_file")"
	read -r app_version dev_revision dev_type sd_req < <(get_nrf52_dfu_metadata "$reference_package")

	case ",${sd_req}," in
		*,0x123,*) erase_version="7.3.0" ;;
		*,0xB6,*)  erase_version="6.1.0" ;;
		*)
			echo "Warning: unknown nRF52 SoftDevice requirement '$sd_req' in $reference_package; using newest erase UF2." >&2
			;;
	esac

	if [[ -n "${erase_version:-}" ]]; then
		erase_file="${folder}/Meshtastic_nRF52_factory_erase_v3_S140_${erase_version}.uf2"
		if [[ -f "$erase_file" ]]; then
			echo "Selected erase UF2 from OTA manifest softdevice_req ${sd_req}: $(basename "$erase_file")" >&2
			printf '%s\n' "$erase_file"
			return 0
		fi
		echo "Warning: manifest requests S140_${erase_version}, but $erase_file was not found; using newest erase UF2." >&2
	fi

	find "$folder" -maxdepth 1 -type f -name 'Meshtastic_nRF52_factory_erase_v3_S140_*.uf2' |
		sort -V |
		tail -n 1
}

nrf52_erase_zip_name() {
	local reference_file=$1
	local reference_package app_version dev_revision dev_type sd_req

	reference_package="$(resolve_nrf52_reference_package "$reference_file")"
	read -r app_version dev_revision dev_type sd_req < <(get_nrf52_dfu_metadata "$reference_package")

	case ",${sd_req}," in
		*,0x123,*) printf '%s\n' "FLASH_ERASE_nrf52_softdevice_v7.zip" ;;
		*,0xB6,*)  printf '%s\n' "FLASH_ERASE_nrf52_softdevice_v6.zip" ;;
		*)
			echo "No nRF52 erase ZIP mapping for softdevice_req '${sd_req}' in ${reference_package}." >&2
			return 1
			;;
	esac
}

download_nrf52_erase_zip() {
	local erase_name=$1
	local target_folder=$2
	local dest tmp_file bytes base_url url downloaded

	mkdir -p "$target_folder"
	dest="${target_folder}/${erase_name}"

	if [[ -f "$dest" ]] && unzip -p "$dest" manifest.json >/dev/null 2>&1; then
		echo "Using existing nRF52 erase package: $dest" >&2
		printf '%s\n' "$dest"
		return 0
	fi

	ensure_command curl
	downloaded=false
	for base_url in "$NRF52_ERASE_BASE_URL" "$NRF52_ERASE_FALLBACK_BASE_URL"; do
		url="${base_url}/${erase_name}"
		tmp_file="$(mktemp "${dest}.tmp.XXXXXX")"
		echo "Downloading nRF52 erase package: $erase_name" >&2
		if ! curl -fsSL --retry 3 --connect-timeout 10 -o "$tmp_file" "$url"; then
			rm -f "$tmp_file"
			continue
		fi

		bytes=$(stat -c%s "$tmp_file" 2>/dev/null || printf '0')
		if (( bytes < 50000 )); then
			echo "Downloaded nRF52 erase package is too small (${bytes} bytes): $url" >&2
			rm -f "$tmp_file"
			continue
		fi
		if ! unzip -p "$tmp_file" manifest.json >/dev/null 2>&1; then
			echo "Downloaded nRF52 erase package is not a valid DFU ZIP: $url" >&2
			rm -f "$tmp_file"
			continue
		fi

		downloaded=true
		break
	done

	if ! $downloaded; then
		echo "Failed to download nRF52 erase package: $erase_name" >&2
		return 1
	fi

	mv "$tmp_file" "$dest"
	printf '%s\n' "$dest"
}

resolve_nrf52_erase_package() {
	local firmware_file=$1
	local reference_file=${2:-$firmware_file}
	local folder erase_name

	folder="$(dirname "$firmware_file")"
	erase_name="$(nrf52_erase_zip_name "$reference_file")" || return 1
	echo "Selected nRF52 erase package from OTA manifest: $erase_name" >&2
	download_nrf52_erase_zip "$erase_name" "$folder"
}

ensure_serial_port_rw() {
	local device_port_name=$1

	if [[ -r "$device_port_name" && -w "$device_port_name" ]]; then
		return 0
	fi

	echo "Serial port $device_port_name requires elevated access." >&2
	echo "Current permissions: $(ls -l "$device_port_name")" >&2
	echo "Prompting for sudo so flashing can continue..." >&2
	sudo -v
	sudo chmod a+rw "$device_port_name"
}

nrf52_endpoint_instance() {
	local path=$1

	[[ -e "$path" ]] || return 1
	stat -Lc '%d:%i' "$path" 2>/dev/null
}

capture_nrf52_pre_flash_endpoint() {
	local kind=$1
	local path=$2
	local instance

	instance="$(nrf52_endpoint_instance "$path")" || {
		echo "Cannot snapshot the selected nRF52 ${kind} endpoint before flashing: $path" >&2
		return 1
	}
	NRF52_FLASH_PRE_KIND="$kind"
	NRF52_FLASH_PRE_PATH="$path"
	NRF52_FLASH_PRE_INSTANCE="$instance"
}

nrf52_pre_flash_endpoint_changed() {
	local current_instance

	[[ -n "$NRF52_FLASH_PRE_KIND" && -n "$NRF52_FLASH_PRE_PATH" \
		&& -n "$NRF52_FLASH_PRE_INSTANCE" ]] || return 1
	current_instance="$(nrf52_endpoint_instance "$NRF52_FLASH_PRE_PATH" || true)"
	[[ -z "$current_instance" || "$current_instance" != "$NRF52_FLASH_PRE_INSTANCE" ]]
}

nrf52_candidate_proves_transition() {
	local kind=$1
	local path=$2
	local instance

	instance="$(nrf52_endpoint_instance "$path" || true)"
	[[ -n "$instance" ]] || return 1
	[[ "$kind" != "$NRF52_FLASH_PRE_KIND" \
		|| "$path" != "$NRF52_FLASH_PRE_PATH" \
		|| "$instance" != "$NRF52_FLASH_PRE_INSTANCE" ]]
}

nrf52_runtime_version_from_port() {
	local port=$1
	local metadata

	command -v timeout >/dev/null 2>&1 || return 1
	metadata="$(timeout 8s pipx run meshtastic --port "$port" \
		--device-metadata 2>/dev/null || true)"
	printf '%s\n' "$metadata" | awk -F': *' '
		/^[[:space:]]*firmware_version:/ {
			value=$2
			gsub(/^[[:space:]"]+|[[:space:]"]+$/, "", value)
			print value
			exit
		}'
}

nrf52_versions_match() {
	local actual="${1,,}"
	local expected="${2,,}"

	actual="${actual#v}"
	expected="${expected#v}"
	[[ -n "$actual" && -n "$expected" ]] || return 1
	[[ "$actual" == "$expected" \
		|| "$actual" == "$expected".* || "$actual" == "$expected"-* \
		|| "$actual" == "$expected"_* ]]
}

resolve_nrf52_runtime_serial_port() {
	local preferred_port=$1
	local timeout_sec=${2:-20}
	local expected_serial=$3
	local expected_path_stem=$4
	local expected_vendor_id=$5
	local deadline matched_port

	deadline=$((SECONDS + timeout_sec))
	while (( SECONDS < deadline )); do
		if matched_port="$(find_nrf52_serial_port_by_identity \
			"$expected_serial" "$expected_path_stem" "$expected_vendor_id" \
			"$preferred_port")"; then
			printf '%s\n' "$matched_port"
			return 0
		fi
		sleep 0.25
	done

	echo "Timed out waiting for the selected nRF52 USB identity to return as a serial port." >&2
	return 1
}

check_nrf52_after_flash() {
	local stage=$1
	local preferred_port=${2:-}
	local expected_serial=$3
	local expected_path_stem=$4
	local expected_vendor_id=$5
	local timeout_sec=${6:-$NRF52_POST_FLASH_CHECK_TIMEOUT_SECONDS}
	local deadline uf2_mount serial_port source actual_version="" last_version=""
	local transitioned=false saw_uf2=false

	echo "Checking device after ${stage}..."
	if [[ -z "$NRF52_FLASH_PRE_KIND" || -z "$NRF52_FLASH_PRE_PATH" \
		|| -z "$NRF52_FLASH_PRE_INSTANCE" ]]; then
		echo "Post-${stage} check has no pre-flash endpoint snapshot; refusing an unproven success." >&2
		return 1
	fi
	deadline=$((SECONDS + timeout_sec))
	while (( SECONDS < deadline )); do
		if nrf52_pre_flash_endpoint_changed; then
			transitioned=true
		fi
		if serial_port="$(find_nrf52_serial_port_by_identity \
			"$expected_serial" "$expected_path_stem" "$expected_vendor_id" \
			"$preferred_port")"; then
			if nrf52_candidate_proves_transition serial "$serial_port"; then
				transitioned=true
			fi
			if $transitioned; then
				if [[ "$stage" != "firmware" ]]; then
					echo "Post-${stage} check: matching serial endpoint re-enumerated at $serial_port."
					return 0
				fi
				actual_version="$(nrf52_runtime_version_from_port "$serial_port" || true)"
				[[ -z "$actual_version" ]] || last_version="$actual_version"
				if nrf52_versions_match "$actual_version" "$NRF52_EXPECTED_VERSION"; then
					echo "Post-${stage} check: application ${actual_version} is running at $serial_port."
					return 0
				fi
			fi
		fi
		if uf2_mount="$(find_uf2_mount_dir \
			"$expected_serial" "$expected_path_stem" "$expected_vendor_id")"; then
			saw_uf2=true
			source="$(nrf52_uf2_mount_source "$uf2_mount" || true)"
			if [[ -n "$source" ]] && nrf52_candidate_proves_transition block "$source"; then
				transitioned=true
			fi
			if $transitioned && [[ "$stage" != "firmware" ]]; then
				echo "Post-${stage} check: UF2 endpoint re-enumerated at $uf2_mount."
				return 0
			fi
		fi
		sleep 1
	done

	if ! $transitioned; then
		echo "Post-${stage} check: the selected nRF52 endpoint never re-enumerated after ${timeout_sec}s." >&2
	elif [[ "$stage" == "firmware" && -n "$last_version" ]]; then
		echo "Post-${stage} check: application version '$last_version' did not match expected '${NRF52_EXPECTED_VERSION:-unknown}'." >&2
	elif [[ "$stage" == "firmware" && "$saw_uf2" == true ]]; then
		echo "Post-${stage} check: the device returned only to UF2 bootloader mode, not a verified application." >&2
	else
		echo "Post-${stage} check: no verified application response was received after ${timeout_sec}s." >&2
	fi
	return 1
}

nrf52_validate_uf2_mount_identity() {
	local mount_dir=$1
	local expected_serial=$2
	local expected_path_stem=$3
	local expected_vendor_id=$4
	local source rank

	mountpoint -q "$mount_dir" || return 1
	is_uf2_mount_dir "$mount_dir" || return 1
	source="$(nrf52_uf2_mount_source "$mount_dir")" || return 1
	[[ -e "$source" ]] || return 1
	rank="$(nrf52_device_identity_rank "$source" \
		"$expected_serial" "$expected_path_stem" "$expected_vendor_id")"
	[[ "$rank" =~ ^[0-9]+$ ]] && (( rank > 0 )) || return 1
	printf '%s\n' "$source"
}

ensure_nrf52_flash_lock_file() {
	if [[ ! -e "$NRF52_FLASH_LOCK_FILE" ]]; then
		(umask 077; set -o noclobber; : >"$NRF52_FLASH_LOCK_FILE") 2>/dev/null || true
	fi
	if [[ ! -f "$NRF52_FLASH_LOCK_FILE" || -L "$NRF52_FLASH_LOCK_FILE" \
		|| ! -O "$NRF52_FLASH_LOCK_FILE" ]]; then
		echo "Refusing unsafe nRF52 flash lock path: $NRF52_FLASH_LOCK_FILE" >&2
		return 1
	fi
}

acquire_nrf52_flash_lock() {
	if (( ${NRF52_FLASH_LOCK_DEPTH:-0} > 0 )); then
		NRF52_FLASH_LOCK_DEPTH=$((NRF52_FLASH_LOCK_DEPTH + 1))
		return 0
	fi

	ensure_nrf52_flash_lock_file || return 1
	NRF52_FLASH_LOCK_FD=""
	exec {NRF52_FLASH_LOCK_FD}>>"$NRF52_FLASH_LOCK_FILE" || return 1
	if ! flock -w 30 "$NRF52_FLASH_LOCK_FD"; then
		echo "Timed out waiting for another nRF52 flash operation to finish." >&2
		exec {NRF52_FLASH_LOCK_FD}>&-
		NRF52_FLASH_LOCK_FD=""
		return 1
	fi
	NRF52_FLASH_LOCK_DEPTH=1
}

release_nrf52_flash_lock() {
	if (( ${NRF52_FLASH_LOCK_DEPTH:-0} <= 0 )); then
		NRF52_FLASH_LOCK_DEPTH=0
		return 0
	fi

	NRF52_FLASH_LOCK_DEPTH=$((NRF52_FLASH_LOCK_DEPTH - 1))
	if (( NRF52_FLASH_LOCK_DEPTH > 0 )); then
		return 0
	fi
	if [[ -n "${NRF52_FLASH_LOCK_FD:-}" ]]; then
		flock -u "$NRF52_FLASH_LOCK_FD" || true
		exec {NRF52_FLASH_LOCK_FD}>&-
		NRF52_FLASH_LOCK_FD=""
	fi
}

release_all_nrf52_flash_locks() {
	if (( ${NRF52_FLASH_LOCK_DEPTH:-0} > 0 )); then
		NRF52_FLASH_LOCK_DEPTH=1
		release_nrf52_flash_lock
	else
		NRF52_FLASH_LOCK_DEPTH=0
	fi
}

prepare_meshtastic_cli_for_verification() {
	echo "Preparing the Meshtastic CLI for post-flash verification..."
	if command -v timeout >/dev/null 2>&1; then
		if ! timeout --foreground 180s pipx run meshtastic --version >/dev/null; then
			echo "Could not prepare the Meshtastic CLI before flashing." >&2
			return 1
		fi
	elif ! pipx run meshtastic --version >/dev/null; then
		echo "Could not prepare the Meshtastic CLI before flashing." >&2
		return 1
	fi
}

begin_nrf52_flash_operation() {
	local expected_version=$1

	if [[ -z "$expected_version" ]]; then
		echo "Cannot verify the flashed application because the selected firmware version is empty." >&2
		return 1
	fi
	prepare_meshtastic_cli_for_verification || return 1
	acquire_nrf52_flash_lock || return 1
	NRF52_EXPECTED_VERSION="$expected_version"
}

end_nrf52_flash_operation() {
	release_nrf52_flash_lock
}

copy_nrf52_uf2_to_storage() {
	local uf2_file=$1
	local stage=$2
	local expected_serial=$3
	local expected_path_stem=$4
	local expected_vendor_id=$5
	local mount_dir source

	if [[ ! -f "$uf2_file" || "${uf2_file,,}" != *.uf2 ]]; then
		echo "UF2 storage flashing requires a .uf2 file: $uf2_file" >&2
		return 1
	fi

	# The main workflow holds this lock from identity re-resolution through
	# post-flash verification. Keep this helper safe when called independently,
	# and nest without releasing an operation-wide lock owned by its caller.
	acquire_nrf52_flash_lock || return 1

	if ! mount_dir="$(find_uf2_mount_dir \
		"$expected_serial" "$expected_path_stem" "$expected_vendor_id")"; then
		echo "No UF2 USB storage volume was found for ${stage}." >&2
		release_nrf52_flash_lock || true
		return 1
	fi
	if ! source="$(nrf52_validate_uf2_mount_identity "$mount_dir" \
		"$expected_serial" "$expected_path_stem" "$expected_vendor_id")"; then
		echo "The selected UF2 mount changed identity before ${stage}; refusing the copy." >&2
		release_nrf52_flash_lock || true
		return 1
	fi
	if ! capture_nrf52_pre_flash_endpoint block "$source"; then
		release_nrf52_flash_lock || true
		return 1
	fi

	echo "Using UF2 storage device at $mount_dir"
	echo "Copying $(basename "$uf2_file") for ${stage}..."
	if ! sudo cp -v -- "$uf2_file" "$mount_dir/"; then
		echo "Copying the ${stage} UF2 to the selected device failed." >&2
		release_nrf52_flash_lock || true
		return 1
	fi
	if ! sync -f "$mount_dir"; then
		echo "The selected UF2 volume reported an error while flushing ${stage} data." >&2
		release_nrf52_flash_lock || true
		return 1
	fi
	release_nrf52_flash_lock
}

nrf52_dfu_output_confirms_success() {
	local output_file=$1
	local exit_code=$2
	local terminal_line

	(( exit_code == 0 )) || return 1
	# adafruit-nrfutil 0.5.x can catch a transport exception, print a traceback,
	# and still exit zero. Require its exact terminal success line and reject
	# every fatal marker observed from that false-success path.
	terminal_line="$(LC_ALL=C awk 'NF { line=$0 } END { sub(/\r$/, "", line); print line }' \
		"$output_file")"
	[[ "$terminal_line" == "Device programmed." ]] || return 1
	if grep -Eiq \
		'Failed to upgrade target|Traceback \(most recent call last\)|Timed out waiting for acknowledgement|No data received' \
		"$output_file"; then
		return 1
	fi
}

run_nrf52_dfu_attempt() {
	local package_file=$1
	local device_port_name=$2
	local exit_code prompt_done_file prompt_pid output_file

	if [[ ! -e "$device_port_name" ]]; then
		echo "Serial port $device_port_name is not present." >&2
		return 1
	fi

	ensure_serial_port_rw "$device_port_name" || return 1
	capture_nrf52_pre_flash_endpoint serial "$device_port_name" || return 1
	echo "pipx run adafruit-nrfutil dfu serial --package $package_file --touch 1200 -p $device_port_name -b 115200"
	prompt_done_file="$(mktemp)"
	output_file="$(mktemp)"
	rm -f "$prompt_done_file"
	(
		sleep "$NRF52_MANUAL_DFU_PROMPT_SECONDS"
		if [[ ! -e "$prompt_done_file" ]]; then
			echo
			echo "nrfutil is still waiting for the bootloader."
			echo "Put the device into DFU mode manually now; leave this script and nrfutil running."
			echo "The nrfutil timeout is ${NRF52_DFU_TIMEOUT_SECONDS}s."
		fi
	) &
	prompt_pid=$!

	set +e
	if command -v timeout >/dev/null 2>&1; then
		timeout --foreground "${NRF52_DFU_TIMEOUT_SECONDS}s" \
			pipx run adafruit-nrfutil dfu serial --package "$package_file" \
			--touch 1200 -p "$device_port_name" -b 115200 \
			2>&1 | tee "$output_file"
		exit_code=${PIPESTATUS[0]}
	else
		pipx run adafruit-nrfutil dfu serial --package "$package_file" \
			--touch 1200 -p "$device_port_name" -b 115200 \
			2>&1 | tee "$output_file"
		exit_code=${PIPESTATUS[0]}
	fi
	touch "$prompt_done_file"
	kill "$prompt_pid" 2>/dev/null || true
	wait "$prompt_pid" 2>/dev/null || true
	rm -f "$prompt_done_file"
	set -e

	if (( exit_code == 124 )); then
		echo "nRF52 serial DFU timed out after ${NRF52_DFU_TIMEOUT_SECONDS}s on $device_port_name with package $package_file." >&2
		rm -f "$output_file"
		return 1
	fi

	if ! nrf52_dfu_output_confirms_success "$output_file" "$exit_code"; then
		if (( exit_code == 0 )); then
			echo "adafruit-nrfutil did not confirm that the selected nRF52 was programmed." >&2
		else
			echo "nRF52 serial DFU failed with status $exit_code on $device_port_name with package $package_file." >&2
		fi
		rm -f "$output_file"
		return 1
	fi

	rm -f "$output_file"
	NRF52_LAST_DFU_PORT="$device_port_name"
	return 0
}

run_nrf52_serial_dfu() {
	local package_file=$1
	local device_port_name=$2
	local matched_port result=0

	acquire_nrf52_flash_lock || return 1
	if ! matched_port="$(find_nrf52_serial_port_by_identity \
		"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
		"$NRF52_SELECTED_VENDOR_ID" "$device_port_name")"; then
		echo "The selected nRF52 USB identity is not available as a serial DFU port." >&2
		release_nrf52_flash_lock || true
		return 1
	fi
	if ! run_nrf52_dfu_attempt "$package_file" "$matched_port"; then
		result=1
	fi
	release_nrf52_flash_lock || true
	return "$result"
}

record_stopped_service() {
	local service=$1

	[[ -n "$service" && "$service" != "None" ]] || return 0
	if [[ " ${lockedService:-} " != *" $service "* ]]; then
		lockedService="${lockedService:+$lockedService }$service"
	fi
}

stop_service_names() {
	local services=$1
	local service
	local -a service_list=()

	[[ -n "$services" && "$services" != "None" ]] || return 0
	read -r -a service_list <<< "$services"
	((${#service_list[@]})) || return 0

	# Record the services before asking systemd to stop them. systemctl can stop
	# one unit and still return failure for another; recording only after the
	# command succeeds would leave the already-stopped unit out of EXIT cleanup.
	for service in "${service_list[@]}"; do
		record_stopped_service "$service"
	done
	echo "Stopping service $services..."
	sudo systemctl stop "${service_list[@]}"
}

probe_meshtastic_metadata() {
	(
		local device=$1
		local probe_services=""
		local probe_status=0
		# These service helpers use dynamic scope. Keeping lockedService local
		# makes each chooser probe independent and lets its EXIT trap restore
		# only the services stopped for this port. The explicit subshell also
		# prevents this local trap from replacing the script-wide EXIT cleanup.
		local lockedService=""

		probe_services="$(get_locked_service "$device")"
		if [[ -n "$probe_services" && "$probe_services" != "None" ]]; then
			lockedService="$probe_services"
			trap 'restart_locked_service_if_needed >/dev/null 2>&1 || true' EXIT
			stop_service_names "$probe_services" >/dev/null 2>&1 || return 1
		fi

		timeout 12 pipx run meshtastic --port "$device" --device-metadata \
			2>/dev/null || probe_status=$?
		if [[ -n "$lockedService" && "$lockedService" != "None" ]]; then
			restart_locked_service_if_needed >/dev/null 2>&1 || return 1
		fi
		trap - EXIT
		return "$probe_status"
	)
}

stop_nrf52_serial_probe_services() {
	local service

	for service in ModemManager brltty gpsd; do
		if systemctl is-active --quiet "$service" 2>/dev/null; then
			stop_service_names "$service"
		fi
	done
}

stop_services_for_selected_port() {
	local selected_port=$1
	local stop_nrf52_probers=${2:-false}
	local selected_locked_services=""

	selected_locked_services="$(get_locked_service "$selected_port")"
	lockedService="$selected_locked_services"
	if [[ -n "$lockedService" && "$lockedService" != "None" ]]; then
		stop_service_names "$lockedService"
	fi
	if $stop_nrf52_probers; then
		stop_nrf52_serial_probe_services
	fi
}

restart_locked_service_if_needed() {
	local -a service_list=()

	if [ -n "${lockedService:-}" ] && [ "$lockedService" != "None" ]; then
		echo "Starting service $lockedService..."
		read -r -a service_list <<< "$lockedService"
		sudo systemctl start "${service_list[@]}"
		lockedService=""
	fi
}

prompt_nrf52_reboot_retry() {
	local reply

	echo
	echo "nRF52 flashing did not complete."
	echo "Reboot/reset the device now. If it comes up as USB storage, the next try will use UF2 copy first."
	while true; do
		read -r -p "Press Enter after reboot to try again, or type E to exit: " reply </dev/tty
		case "$reply" in
			"")
				return 0
				;;
			[Ee])
				restart_locked_service_if_needed
				return 1
				;;
			*)
				echo "Please press Enter to retry or type E to exit."
				;;
		esac
	done
}

# Run the firmware update/install script.
run_update_script() {
	local cmd user_choice PYTHON ESPTOOL_CMD device_name metadata_display_name nrf52_action nrf52_serial_dfu
	local app_package erase_package app_uf2 erase_uf2 nrf52_uf2_mount matched_nrf52_port
	local picked_detection nrf52_selected_at_run=false nrf52_identity_flash=false
	local selected_firmware_version=""
	mapfile -t cmd_array <"$CMD_FILE"
	abs_script="${cmd_array[0]}"
	abs_selected="${cmd_array[1]}"
	cmd="${cmd_array[*]}"
	detected_dev=$(cat "${DEVICE_INFO_FILE}")
	device_name=$(echo "$detected_dev" | awk -F'-> ' '{print $1}' | sed -E 's/^Bus [0-9]+ Device [0-9]+: ID [[:alnum:]]+:[[:alnum:]]+ //')
	device_name=$(echo "$device_name" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | tr -s '[:space:]')
	architecture=$(cat "${ARCHITECTURE_FILE}")
	operation=$(cat "${OPERATION_FILE}")
	basename_selected="$(basename "$abs_selected")"
	device_port_name="$(serial_port_from_detection "$detected_dev")"
	if is_nrf52_serial_dfu_candidate "$architecture" "$abs_selected"; then
		nrf52_serial_dfu=true
	else
		nrf52_serial_dfu=false
	fi
	if ! echo "$architecture" | grep -qi "esp32"; then
		nrf52_identity_flash=true
	fi
	metadata_display_name="$(get_firmware_metadata_display_name "$abs_selected")"
	if [[ -n "$metadata_display_name" && (-z "$device_name" || "$device_name" == "$device_port_name" || "$device_name" == /dev/*) ]]; then
		device_name="$metadata_display_name"
	fi
	
	if [[ -z "${device_port_name:-}" ]]; then
		picked_detection="$(pick_serial_port)"
		device_port_name="$(serial_port_from_detection "$picked_detection")"
		while [[ -z "${device_port_name:-}" ]]; do
			read -r -p "No serial port selected. Enter to pick, Q to quit, or type a device path: " reply

			case "$reply" in
				[Qq])
					echo "Cancelled."
					return 1
					;;
				"")
					picked_detection="$(pick_serial_port)"
					device_port_name="$(serial_port_from_detection "$picked_detection")"
					;;
				*)
					if [[ -c "$reply" ]]; then
						device_port_name="$reply"
					elif [[ -e "$reply" ]]; then
						echo "Path exists but is not a serial device: $reply"
					else
						echo "Path does not exist: $reply"
					fi
					;;
				esac
		done
		nrf52_selected_at_run=true
	fi

	if echo "$architecture" | grep -qi "esp32"; then
		update_bleota

		echo "Command to run for firmware $operation:"
		echo "$abs_script -p ${device_port_name} -f $basename_selected"
	elif $nrf52_serial_dfu; then
		nrf52_action="$(choose_nrf52_flash_action "$device_name" "$device_port_name")"
		operation="$nrf52_action"
	else
		echo "$basename_selected"
	fi

	if $RUN_UPDATE || $nrf52_serial_dfu; then
		user_choice="y"
	else
		read -r -p "Would you like to $operation the firmware? (y/N): " user_choice </dev/tty
		user_choice=${user_choice:-N}
	fi
	if ! [[ "$user_choice" =~ ^[Yy]$ ]]; then
		echo "Script done. Firmware was NOT UPDATED"
		exit 0
	fi
		# Ensure pipx & meshtastic are installed.
		ensure_command pipx

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
			install_packages python3 pipx
			PYTHON=$(command -v python3) || {
				echo "Failed to install python3"
				exit 1
		}
	fi

	# Determine the esptool command.
	if echo "$architecture" | grep -qi "esp32"; then
		ESPTOOL_CMD="pipx run esptool"
	fi
	if $nrf52_identity_flash; then
		# Usually detect_device() captured this identity before release selection
		# and downloads. If no port existed then, capture only at the later explicit
		# selection above, never by silently rebinding a stale tty number here.
		if $nrf52_selected_at_run; then
			if ! capture_nrf52_selected_identity "$device_port_name"; then
				return 1
			fi
		fi
		if [[ -z "$NRF52_SELECTED_PATH_STEM" || -z "$NRF52_SELECTED_VENDOR_ID" ]]; then
			echo "No stable USB identity was saved when the device was selected; refusing flashing." >&2
			return 1
		fi
		if ! selected_firmware_version="$(
			nrf52_firmware_version_from_artifact "$abs_selected"
		)"; then
			echo "Refusing nRF52 flashing without an application version proven by the selected artifact." >&2
			return 1
		fi
		# Do all potentially slow pipx setup before taking the destructive-operation
		# lock. Once held, keep the lock through identity re-resolution, flashing,
		# and post-flash application verification.
		if ! begin_nrf52_flash_operation "$selected_firmware_version"; then
			return 1
		fi
		if matched_nrf52_port="$(find_nrf52_serial_port_by_identity \
			"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
			"$NRF52_SELECTED_VENDOR_ID" "$device_port_name")"; then
			device_port_name="$matched_nrf52_port"
		elif nrf52_uf2_mount="$(find_uf2_mount_dir \
			"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
			"$NRF52_SELECTED_VENDOR_ID")"; then
			echo "The selected USB identity is present as UF2 storage at $nrf52_uf2_mount."
		else
			echo "The device selected before release download is no longer present on its saved USB identity." >&2
			end_nrf52_flash_operation || true
			return 1
		fi
	fi

	# Check if any services are locking up the device
	echo "$detected_dev"
	stop_services_for_selected_port "$device_port_name" "$nrf52_identity_flash"

	
	# Optionally make a backup of the config.
	basename_device_port_name="$(basename "$device_port_name")"
	backup_config_name="config_backup.${architecture}.${device_name}.${basename_device_port_name}.$(date +%s).yaml"
	backup_config_name_sanitized=$(echo "$backup_config_name" | tr '/' '_' | tr ' ' '_')
	read -rp "Create a backup configuration before flashing? [y/N]: " do_backup
	case "$do_backup" in
	  [Yy])
		echo "Making a backup of the configuration."
		echo "Attempting to create backup..."
		while true; do
			if timeout 30s pipx run meshtastic --port "${device_port_name}" --export-config > "${backup_config_name_sanitized}"; then
				echo "Backup configuration created: ${backup_config_name_sanitized}"
				break
			else
				echo "Warning: Timed out waiting for connection completion. Config backup not done." >&2
				read -rp "Press Enter to try again or type 'skip' to skip the creation: " response
				if [ "$response" = "skip" ]; then
					echo "Skipping config backup."
					rm -f "${backup_config_name_sanitized}"
					break
				fi
				sleep 1
			fi
		done
		;;
	  *)
		echo "Skipping config backup."
		;;
	esac

	# Execute update for ESP32, nRF52 serial DFU, or block-device UF2 devices.
	if echo "$architecture" | grep -qi "esp32"; then
		export ESPTOOL_PORT=$device_port_name
		echo "Setting device into bootloader mode via baud 1200"
		$ESPTOOL_CMD --port "${device_port_name}" --baud 1200 --after no_reset read_mac  || true
		sleep 1
		# Change directory to the script's folder.
		pushd "$(dirname "$abs_selected")" > /dev/null || { echo "Failed to change directory"; exit 1; }
		
		if [ "$operation" = "update" ]; then
			echo "Running: $ESPTOOL_CMD --baud 115200 write-flash 0x10000 \"$basename_selected\""
			$ESPTOOL_CMD --baud 115200 write-flash 0x10000 "$basename_selected"
		elif [ "$operation" = "install" ]; then
			echo "Running: \"$abs_script\"  -p \"${device_port_name}\" -f \"$basename_selected\""
			"$abs_script" -p "${device_port_name}" -f "$basename_selected"
		fi

		echo ""
		echo "If you see no errors above then"
		echo "Firmware $operation for ESP32 device ${device_name} completed on port ${device_port_name}."
		popd > /dev/null
		if [ -f "${backup_config_name_sanitized}" ]; then
			echo "Configuration can be restored using this if it was wiped out"
			echo "pipx run meshtastic --configure \"${backup_config_name_sanitized}\""
		fi

	elif $nrf52_serial_dfu; then
		while true; do
		if matched_nrf52_port="$(find_nrf52_serial_port_by_identity \
			"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
			"$NRF52_SELECTED_VENDOR_ID" "$device_port_name")"; then
			device_port_name="$matched_nrf52_port"
		fi
		NRF52_LAST_DFU_PORT="$device_port_name"
		app_uf2="$(resolve_nrf52_uf2_file "$abs_selected" || true)"
		nrf52_uf2_mount="$(find_uf2_mount_dir \
			"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
			"$NRF52_SELECTED_VENDOR_ID" || true)"

		if [[ -n "$nrf52_uf2_mount" && -n "$app_uf2" ]]; then
			echo "nRF52 USB storage mode detected at $nrf52_uf2_mount; using UF2 copy."

			if [[ "$nrf52_action" == "flash-wipe" ]]; then
				erase_uf2="$(find_nrf52_erase_uf2 "$abs_selected" "$abs_selected")"
				if [[ -z "$erase_uf2" ]]; then
					echo "No Meshtastic nRF52 erase UF2 file was found next to $abs_selected" >&2
					exit 1
				fi

				echo "Erasing UF2 area using $erase_uf2"
				sleep 1
				if ! copy_nrf52_uf2_to_storage "$erase_uf2" "erase" \
					"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
					"$NRF52_SELECTED_VENDOR_ID"; then
					echo "Failed to erase ${device_name} using UF2 storage." >&2
					exit 1
				fi
				if ! check_nrf52_after_flash "erase" "$device_port_name" \
					"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
					"$NRF52_SELECTED_VENDOR_ID"; then
					exit 1
				fi
				echo "Erase done."
				echo
			fi

			nrf52_uf2_mount="$(find_uf2_mount_dir \
				"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
				"$NRF52_SELECTED_VENDOR_ID" || true)"
			if [[ -n "$nrf52_uf2_mount" ]]; then
				echo "Flashing firmware file $app_uf2"
				sleep 1
				if ! copy_nrf52_uf2_to_storage "$app_uf2" "firmware" \
					"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
					"$NRF52_SELECTED_VENDOR_ID"; then
					echo "Firmware ${nrf52_action} failed for ${device_name} using UF2 storage." >&2
					exit 1
				fi
				if ! check_nrf52_after_flash "firmware" "$device_port_name" \
					"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
					"$NRF52_SELECTED_VENDOR_ID"; then
					exit 1
				fi
				echo
				echo "Firmware ${nrf52_action} completed for ${device_name} using UF2 storage."
			else
				echo "UF2 storage did not reappear; falling back to nrfutil for firmware flash."
				app_package="$(resolve_nrf52_dfu_package "$abs_selected" "$abs_selected")"
				echo "Flashing firmware file $app_package"
				sleep 1
				if ! run_nrf52_serial_dfu "$app_package" "$device_port_name"; then
					echo "Firmware ${nrf52_action} failed for ${device_name} on ${device_port_name}." >&2
					if prompt_nrf52_reboot_retry; then
						continue
					fi
					exit 1
				fi
					if ! check_nrf52_after_flash "firmware" "$device_port_name" \
						"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
						"$NRF52_SELECTED_VENDOR_ID"; then
					exit 1
				fi
				echo
				echo "Firmware ${nrf52_action} completed for ${device_name} on ${device_port_name}."
			fi

			if [ -f "${backup_config_name_sanitized}" ]; then
				echo "Configuration can be restored using this if it was wiped out"
				echo "pipx run meshtastic --configure \"${backup_config_name_sanitized}\""
			fi
			restart_locked_service_if_needed
			end_nrf52_flash_operation
			return 0
		fi

		if [[ -n "$nrf52_uf2_mount" && -z "$app_uf2" ]]; then
			echo "nRF52 USB storage mode was detected, but no app UF2 was found; falling back to nrfutil." >&2
		else
			echo "No nRF52 UF2 USB storage volume detected; using nrfutil serial DFU."
		fi

		echo "Getting the latest version of adafruit-nrfutil"
		pipx run adafruit-nrfutil version
		echo "Running ${nrf52_action}..."

		app_package="$(resolve_nrf52_dfu_package "$abs_selected" "$abs_selected")"

		if [[ "$nrf52_action" == "flash-wipe" ]]; then
			erase_package="$(resolve_nrf52_erase_package "$abs_selected" "$abs_selected")" || exit 1
			echo "Erasing UF2 area using $erase_package"
			sleep 1
			if ! run_nrf52_serial_dfu "$erase_package" "$device_port_name"; then
				nrf52_uf2_mount="$(find_uf2_mount_dir \
					"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
					"$NRF52_SELECTED_VENDOR_ID" || true)"
				erase_uf2="$(find_nrf52_erase_uf2 "$abs_selected" "$abs_selected" || true)"
				if [[ -n "$nrf52_uf2_mount" && -n "$erase_uf2" ]]; then
					echo "nrfutil failed, but UF2 storage is available; retrying erase with UF2 copy."
					if ! copy_nrf52_uf2_to_storage "$erase_uf2" "erase" \
						"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
						"$NRF52_SELECTED_VENDOR_ID"; then
						echo "Failed to erase ${device_name} using UF2 storage." >&2
						exit 1
					fi
				else
					echo "Failed to erase ${device_name} on ${device_port_name}." >&2
					if prompt_nrf52_reboot_retry; then
						continue
					fi
					exit 1
				fi
			fi
			if ! check_nrf52_after_flash "erase" "$device_port_name" \
				"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
				"$NRF52_SELECTED_VENDOR_ID"; then
				exit 1
			fi
			echo "Erase done."
			if matched_nrf52_port="$(resolve_nrf52_runtime_serial_port \
				"${NRF52_LAST_DFU_PORT:-$device_port_name}" 20 \
				"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
				"$NRF52_SELECTED_VENDOR_ID")"; then
				device_port_name="$matched_nrf52_port"
			fi
			nrf52_uf2_mount="$(find_uf2_mount_dir \
				"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
				"$NRF52_SELECTED_VENDOR_ID" || true)"
			if [[ -n "$nrf52_uf2_mount" && -n "$app_uf2" ]]; then
				echo "UF2 storage mode detected after erase; using UF2 copy for firmware flash."
				echo "Flashing firmware file $app_uf2"
				sleep 1
				if ! copy_nrf52_uf2_to_storage "$app_uf2" "firmware" \
					"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
					"$NRF52_SELECTED_VENDOR_ID"; then
					echo "Firmware ${nrf52_action} failed for ${device_name} using UF2 storage." >&2
					exit 1
				fi
				if ! check_nrf52_after_flash "firmware" "$device_port_name" \
					"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
					"$NRF52_SELECTED_VENDOR_ID"; then
					exit 1
				fi
				echo
				echo "Firmware ${nrf52_action} completed for ${device_name} using UF2 storage."
				if [ -f "${backup_config_name_sanitized}" ]; then
					echo "Configuration can be restored using this if it was wiped out"
					echo "pipx run meshtastic --configure \"${backup_config_name_sanitized}\""
				fi
				restart_locked_service_if_needed
				end_nrf52_flash_operation
				return 0
			fi
			echo "Using serial port ${device_port_name} for firmware flash after erase."
			echo
		fi

		echo "Flashing firmware file $app_package"
		sleep 1
		if ! run_nrf52_serial_dfu "$app_package" "$device_port_name"; then
			nrf52_uf2_mount="$(find_uf2_mount_dir \
				"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
				"$NRF52_SELECTED_VENDOR_ID" || true)"
			if [[ -n "$nrf52_uf2_mount" && -n "$app_uf2" ]]; then
				echo "nrfutil failed, but UF2 storage is available; retrying firmware flash with UF2 copy."
				if ! copy_nrf52_uf2_to_storage "$app_uf2" "firmware" \
					"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
					"$NRF52_SELECTED_VENDOR_ID"; then
					echo "Firmware ${nrf52_action} failed for ${device_name} using UF2 storage." >&2
					exit 1
				fi
			else
				echo "Firmware ${nrf52_action} failed for ${device_name} on ${device_port_name}." >&2
				if prompt_nrf52_reboot_retry; then
					continue
				fi
				exit 1
			fi
		fi
		if ! check_nrf52_after_flash "firmware" "$device_port_name" \
			"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
			"$NRF52_SELECTED_VENDOR_ID"; then
			exit 1
		fi
		echo
		echo "Firmware ${nrf52_action} completed for ${device_name} on ${device_port_name}."
		if [ -f "${backup_config_name_sanitized}" ]; then
			echo "Configuration can be restored using this if it was wiped out"
			echo "pipx run meshtastic --configure \"${backup_config_name_sanitized}\""
		fi
		break
		done

	else
		attempt=0
		max_attempts=3
		nrf52_uf2_mount=""
		if [[ -z "$NRF52_SELECTED_PATH_STEM" || -z "$NRF52_SELECTED_VENDOR_ID" ]]; then
			echo "No stable USB identity was saved when the UF2 device was selected; refusing flashing." >&2
			exit 1
		fi
		if [[ "${abs_selected,,}" != *.uf2 ]]; then
			echo "This USB-storage flash path requires a .uf2 firmware file: $abs_selected" >&2
			exit 1
		fi

		while [ $attempt -lt $max_attempts ]; do
			if nrf52_uf2_mount="$(find_uf2_mount_dir \
				"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
				"$NRF52_SELECTED_VENDOR_ID")"; then
				break
			fi
			if ! matched_nrf52_port="$(find_nrf52_serial_port_by_identity \
				"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
				"$NRF52_SELECTED_VENDOR_ID" "$device_port_name")"; then
				echo "The selected USB identity is not available as serial or UF2 storage." >&2
				attempt=$((attempt + 1))
				[[ $attempt -ge $max_attempts ]] || sleep 5
				continue
			fi
			device_port_name="$matched_nrf52_port"
			echo "Setting device into bootloader mode via pipx run meshtastic --enter-dfu --port ${device_port_name}"
			if ! pipx run meshtastic --enter-dfu --port "${device_port_name}"; then
				echo "The selected device did not accept the enter-DFU command." >&2
			fi
			sleep 5
			if nrf52_uf2_mount="$(find_uf2_mount_dir \
				"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
				"$NRF52_SELECTED_VENDOR_ID")"; then
				break
			fi

			echo "Error: The selected device did not appear as matching UF2 storage."
			attempt=$((attempt + 1))
			if [ $attempt -lt $max_attempts ]; then
				echo "Retrying ($attempt/$max_attempts)..."
				sleep 5
			fi
		done

		if [ -z "$nrf52_uf2_mount" ]; then
			echo "Error: The selected device failed to enter UF2 mode after $max_attempts attempts."
			exit 1
		fi

		echo "Matched the selected UF2 device at $nrf52_uf2_mount."
		if ! copy_nrf52_uf2_to_storage "$abs_selected" "firmware" \
			"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
			"$NRF52_SELECTED_VENDOR_ID"; then
			echo "Firmware $operation failed for ${device_name} using UF2 storage." >&2
			exit 1
		fi
		if ! check_nrf52_after_flash "firmware" "$device_port_name" \
			"$NRF52_SELECTED_SERIAL" "$NRF52_SELECTED_PATH_STEM" \
			"$NRF52_SELECTED_VENDOR_ID"; then
			exit 1
		fi
		echo ""
		echo "Firmware $operation for ${device_name} completed using verified UF2 storage."
		if [ -f "${backup_config_name_sanitized}" ]; then
			echo "Configuration can be restored using this if it was wiped out"
			echo "pipx run meshtastic --configure \"${backup_config_name_sanitized}\""
		fi

	fi

	# Restart the stopped service.
	restart_locked_service_if_needed
	if $nrf52_identity_flash; then
		end_nrf52_flash_operation
	fi
}

##################
# Main Execution #
##################
parse_args "$@"
ensure_pipx_uv_backend
update_releases

detect_device        # ${DEVICE_INFO_FILE} ${DETECTED_PRODUCT_FILE}

# Build the release menu and allow selection.
release_json=$(get_release_data)
build_release_menu "$release_json" # ${VERSIONS_TAGS_FILE} ${VERSIONS_LABELS_FILE}
select_release                     # ${CHOSEN_TAG_FILE}

chosen_tag=$(cat "${CHOSEN_TAG_FILE}")
if grep -E -q "${chosen_tag}.*nightly" "$VERSIONS_LABELS_FILE"; then
    download_pattern="-${chosen_tag}"
    echo "Nightly build selected; skipping download and unzip."
    echo "$download_pattern" >"${DOWNLOAD_PATTERN_FILE}"
else
    download_assets   # ${DOWNLOAD_PATTERN_FILE}
    unzip_assets
fi

match_firmware_files # ${MATCHING_FILES_FILE}
select_firmware_file # ${SELECTED_FILE_FILE}
detect_esp			 # ${ARCHITECTURE_FILE}
choose_operation     # ${OPERATION_FILE}
prepare_script       # ${CMD_FILE}
run_update_script
