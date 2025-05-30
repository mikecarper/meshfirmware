#!/usr/bin/env bash
#
: <<'EOF'

# To run this file, copy this line below and run it.
cd ~ && wget -qO - https://raw.githubusercontent.com/mikecarper/meshfirmware/refs/heads/main/firmware.sh | bash

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
USB_AUTOSUSPEND=$(cat /sys/module/usbcore/parameters/autosuspend)
if [[ "$USB_AUTOSUSPEND" -ne -1 ]]; then
	# Only disable (-1) if it isn’t already
	echo "sudo needed to disable USB autosuspend and keep all USB ports active."
	echo -1 | sudo tee /sys/module/usbcore/parameters/autosuspend >/dev/null
fi

# Settings for the repo
        GITHUB_API_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases"
          REPO_API_URL="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME_ALT}/contents"
 WEB_HARDWARE_LIST_URL="https://raw.githubusercontent.com/${REPO_OWNER}/web-flasher/refs/heads/main/public/data/hardware-list.json"
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

# Update the GitHub release cache if needed.
update_releases() {
	if check_internet; then
		# Ensure jq is present
		if ! command -v jq >/dev/null 2>&1; then
		    echo "jq not found – installing…"
		    if ! sudo apt-get -y install jq; then         # first try: install directly
		        echo "Package lists may be stale; updating and retrying…"
		        sudo apt-get update
		        sudo apt-get -y install jq
		    fi
		fi

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
		if echo "$body" | grep -q -- '⚠️'; then
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
	local versions_tags versions_labels chosen_index auto_selected i selection
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

		# Prompt for the user's selection.
		echo ""
		read -r -p "Enter the number of your selection: " selection </dev/tty
		if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt "$num_entries" ]; then
			echo "Invalid selection. Exiting."
			exit 1
		fi
		chosen_index=$((selection - 1))
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
detect_device() {
	# /dev/ttyACM0
	local lsusb_output filtered_device_lines detected_raw detected_line detected_dev fallback newpath search_full
	lsusb_output=$(lsusb)
	mapfile -t all_device_lines < <(echo "$lsusb_output" | sed -n 's/.*ID [0-9a-fA-F]\{4\}:[0-9a-fA-F]\{4\} //p')
	filtered_device_lines=()
	for line in "${all_device_lines[@]}"; do
		if ! echo "$line" | grep -qiE "hub|ethernet|mouse|keyboard"; then
			filtered_device_lines+=("$line")
		fi
	done

    echo ""
	if [ "${#filtered_device_lines[@]}" -eq 0 ]; then
		# Prompt user to either re-scan or quit.
        echo "USB devices found:"
		echo "$lsusb_output" | sed -n 's/.*ID [0-9a-fA-F]\{4\}:[0-9a-fA-F]\{4\} //p'
		read -rp "Press Enter to look again or q to quit: " choice < /dev/tty
		if [[ "$choice" =~ ^[Qq]$ ]]; then
			echo "Exiting."
			exit 0
		else
			detect_device  # Call itself again.
			return
		fi
	fi
	if [ "${#filtered_device_lines[@]}" -eq 1 ]; then
		detected_raw="${filtered_device_lines[0]}"
		# Determine detected_dev for the single device:
		search_full=$(echo "$detected_raw" | tr ' ' '_' | tr '(' '_' | tr ')' '_' | tr ',' '_')
		#echo "$search_full" > /dev/tty
		detected_dev=""
		for link in /dev/serial/by-id/*; do
			if [[ $(basename "$link") == *"$search_full"* ]]; then
				detected_dev=$(readlink -f "$link")
				break
			fi
		done
		
		if [ -z "$detected_dev" ]; then
			fallback=$(echo "$detected_raw" | cut -d' ' -f2- | tr ' ' '_' | tr '(' '_' | tr ')' '_' | tr ',' '_') 
			#echo "$fallback" > /dev/tty
			for link in /dev/serial/by-id/*; do
				if [[ $(basename "$link") == *"$fallback"* ]]; then
					detected_dev=$(readlink -f "$link")
					break
				fi
			done
		fi
		
		if [ -z "$detected_dev" ]; then
			third_fallback=$(echo "$detected_raw" | tr ' ' '_' | tr '(' '_' | tr ')' '_' | tr '/' '_' | tr ',' '_' | sed 's/^/usb-/')
			#echo "$third_fallback" > /dev/tty
			for link in /dev/serial/by-id/*; do
				if [[ $(basename "$link") == *"$third_fallback"* ]]; then
					detected_dev=$(readlink -f "$link")
					break
				fi
			done
		fi
	else
		# Multiple devices detected; ensure meshtastic is available.
		newpath=0
		source "$HOME/.bashrc"
		if ! command -v pipx &>/dev/null; then
			echo "Installing pipx"
			sudo apt -y install pipx
		fi
		if ! command -v meshtastic &>/dev/null; then
			pipx install "meshtastic[cli]"
			newpath=1
		fi
		if [ $newpath -eq 1 ]; then
			pipx ensurepath
			# shellcheck disable=SC1091
			source "$HOME/.bashrc"
		fi

		
		declare -a detected_devs menu_options
		declare -gA seen_dev=()
		echo "Multiple USB devices detected:"
		for idx in "${!filtered_device_lines[@]}"; do
			local device_info search_full detected_dev version
			device_info="${filtered_device_lines[$idx]}"
			# Determine detected_dev for this device:
			search_full=$(echo "$device_info" | tr ' ' '_')
			detected_dev="" 

			for link in /dev/serial/by-id/*; do
				if [[ $(basename "$link") == *"$search_full"* ]]; then
					detected_dev=$(readlink -f "$link")
					if [[ -z ${seen_dev[$detected_dev]+_} ]]; then
						break
					fi
					detected_dev=""
				fi
			done
			

			if [ -z "$detected_dev" ]; then
				fallback=$(echo "$device_info" | cut -d' ' -f2- | tr ' ' '_')
				for link in /dev/serial/by-id/*; do
					if [[ $(basename "$link") == *"$fallback"* ]]; then
						detected_dev=$(readlink -f "$link")
						if [[ -z ${seen_dev[$detected_dev]+_} ]]; then
							break
						fi
						detected_dev=""
					fi
				done
			fi
			
			if [ -z "$detected_dev" ]; then
				third_fallback=$(echo "$device_info" | tr ' ' '_' | tr '/' '_' | sed 's/^/usb-/')
				for link in /dev/serial/by-id/*; do
					if [[ $(basename "$link") == *"$third_fallback"* ]]; then
						detected_dev=$(readlink -f "$link")
						if [[ -z ${seen_dev[$detected_dev]+_} ]]; then
							break
						fi
						detected_dev=""
					fi
				done
			fi
			
			# mark as taken so later iterations won’t reuse it
			if [[ -n "$detected_dev" ]]; then 
				seen_dev["$detected_dev"]=1
			fi

			detected_devs[idx]="$detected_dev"
			# If we found a detected_dev, try to get its firmware version.
			if [ -n "$detected_dev" ]; then
				lockedService=$(get_locked_service "$detected_dev")
				if [ -n "$lockedService" ] && [ "$lockedService" != "None" ]; then
					spinner
					#echo "Stopping $lockedService"
					sudo systemctl stop "$lockedService"
				fi
				spinner
				# Run meshtastic --device-metadata and extract the firmware_version.
				# Redirect stderr to hide extra log messages.
				# Attempt to get the firmware version with a 10 second timeout.
				version=$(timeout 12 meshtastic --port "$detected_dev" --device-metadata 2>/dev/null | awk -F': ' '/^firmware_version:/ {print $2; exit}' || true)
				if [ -z "$version" ]; then
					version="unknown version"
				fi

				if [ -n "$lockedService" ] && [ "$lockedService" != "None" ]; then
					spinner
					#echo "Starting $lockedService"
					sudo systemctl start "$lockedService"
				fi
				spinner
			else
				version="unknown"
			fi
			menu_options[idx]="${device_info} -> ${detected_dev} (${version})"
		done
		# Print the menu with version information.
		printf "\r"
		for idx in "${!menu_options[@]}"; do
			printf "%d) %s\n" $((idx + 1)) "${menu_options[$idx]}"
		done
		# Prompt user selection.
		while true; do
			read -r -p "Please select a device [1-${#menu_options[@]}]: " selection </dev/tty
			if [[ "$selection" =~ ^[1-9][0-9]*$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "${#menu_options[@]}" ]; then
				detected_raw="${filtered_device_lines[$((selection - 1))]}"
				detected_dev="${detected_devs[$((selection - 1))]}"
				break
			else
				echo "Invalid selection. Try again."
			fi
		done
	fi


	detected_line=$(echo "$lsusb_output" | grep -i "$detected_raw" | head -n1)
	
	echo "$detected_line -> $detected_dev" >"${DEVICE_INFO_FILE}"
	normalize "$detected_raw" >"${DETECTED_PRODUCT_FILE}"
}

# Match the firmware files against the detected device.
match_firmware_files() {
	local chosen_tag download_pattern detected_product
	chosen_tag=$(cat "${CHOSEN_TAG_FILE}")
	download_pattern=$(cat "${DOWNLOAD_PATTERN_FILE}")
	detected_product=$(cat "${DETECTED_PRODUCT_FILE}")
	detected_info_file=$(cat "${DEVICE_INFO_FILE}")
	device_name=$(echo "$detected_info_file" | awk -F'-> ' '{print $1}' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
	device_port_name=$(echo "$detected_info_file" | awk -F'-> ' '{print $2}')
	# Remove everything up to (and including) "ID "
	temp="${device_name#*ID }"
	# Remove the first word from the remainder (the device ID) plus the following space.
	result="${temp#* }"
	echo "$result -> $device_port_name"
	
	USBproduct=$(lsusb -v 2>/dev/null |
		grep -A 20 "${device_name}" |
		grep "iProduct" |
		grep -vi "Controller" |
		sed -n 's/.*2[[:space:]]\+\([^[:space:]]\+\).*/\1/p' |
		head -n 1 |
		tr '[:upper:]' '[:lower:]')
	
	declare -A product_files
	declare -A product_files_full

	while IFS= read -r -d '' file; do
		local fname prod prodNorm
		fname=$(basename "$file")
		# Updated regex: group 1 is the prefix, group 2 is the product part.
		if [[ "$fname" =~ ^(firmware-)(.*)${download_pattern//v/}(-update)?\.(bin|uf2|zip)$ ]]; then
			prod="${BASH_REMATCH[2]}"
			prodNorm=$(normalize "$prod")
			
			# strip any tft|inkhud|eink suffix for grouping
			if [[ $prodNorm =~ ^(.+?)(tft|inkhud|eink)$ ]]; then
			  base=${BASH_REMATCH[1]}
			else
			  base=$prodNorm
			fi
			
			product_files["$base"]+="$file"$'\n'
			product_files_full["$base"]+="$prod"$'\n'
		fi
		spinner
	done < <( find "$FIRMWARE_ROOT/${chosen_tag}" -type f \( -iname "firmware-*" \) -print0 )

	matching_keys=()
	if [ -z "${product_files+x}" ] || [ ${#product_files[@]} -eq 0 ]; then
		for prod in "${!product_files[@]}"; do
			local norm_prod
			norm_prod=$(normalize "$prod")
			if [[ "$norm_prod" == *"$detected_product"* ]] || [[ "$detected_product" == *"$norm_prod"* ]]; then
				printf "\r"
				echo "Firmware file match on: $(echo "${product_files_full[$prod]}" | head -n1)"
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
	if [ ${#matching_files[@]} -eq 0 ]; then
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

	# If no matches are found for the device, fall back to *all* firmware files in the chosen tag.
	if [ "${#matching_files[@]}" -eq 0 ]; then
		echo "No firmware matched for the detected device: $detected_product"
		mapfile -t matching_files < <(
			find "$FIRMWARE_ROOT/${chosen_tag}" -type f \( -iname "firmware-*" \) -print0
				while IFS= read -r -d '' file; do
					# Print "basename<tab>full_path"
					echo -e "$(basename "$file")\t$file"
				done | sort -f -k1,1 | cut -f2-
		)
	fi
	
	# Post-process the matching_files array to remove duplicate entries.
	readarray -t matching_files < <(printf "%s\n" "${matching_files[@]}" | sort -u)

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
			else
				operation="install"
			fi
		fi
	fi

	echo "$operation" >"${OPERATION_FILE}"
	echo "Operation chosen: $operation"
}

# Let the user select which firmware file to use if multiple are found.
select_firmware_file() {
	local matching_files count selected_file file_choice firmware_candidates=()
	readarray -t matching_files <"${MATCHING_FILES_FILE}"
	count=${#matching_files[@]}

	if [ "$count" -eq 0 ]; then
		echo "No matching firmware files found."
		exit 1
	fi

	# If only one file, no choice needed:
	if [ "$count" -eq 1 ]; then
		selected_file="${matching_files[0]}"
	else

		for f in "${matching_files[@]}"; do
			if [[ "$(basename "$f")" =~ \.(bin|uf2)$ ]]; then
				firmware_candidates+=("$f")
			fi
		done
		# Sort the firmware_candidates array.
		readarray -t firmware_candidates < <(printf '%s\n' "${firmware_candidates[@]}" | sort)

		# If exactly one firmware candidate, auto-select it.
		if [ ${#firmware_candidates[@]} -eq 1 ]; then
			echo "Auto-selecting firmware candidate: $(basename "${firmware_candidates[0]}")"
			selected_file="${firmware_candidates[0]}"
		elif [ ${#firmware_candidates[@]} -gt 1 ]; then
			echo "Multiple matching firmware candidates files found:"
			# Figure out how many lines we'll print.
			count_candidates=${#firmware_candidates[@]}
			# The number of digits in that count — e.g., 2 if 10..99, 3 if 100..999
			idx_width=${#count_candidates}

			for i in "${!firmware_candidates[@]}"; do
				# Print each line so that indices are right-aligned to idx_width.
				printf "%${idx_width}d. %s\n" \
					$((i + 1)) \
					"$(basename "${firmware_candidates[$i]}")"
			done
			read -r -p "Select which firmware file to use [1-${#firmware_candidates[@]}]: " file_choice </dev/tty
			if ! [[ "$file_choice" =~ ^[0-9]+$ ]] ||
				[ "$file_choice" -lt 1 ] ||
				[ "$file_choice" -gt "${#firmware_candidates[@]}" ]; then
				echo "Invalid selection. Exiting."
				exit 1
			fi
			selected_file="${firmware_candidates[$((file_choice - 1))]}"
		else
			# No .bin was found, so we prompt the user for all matching files.
			selected_file="$(prompt_for_firmware)"
		fi

	fi

	echo "$selected_file" >"${SELECTED_FILE_FILE}"
}

# prompt_for_firmware:
#   Prompts the user to select from all matching_files in interactive mode.
prompt_for_firmware() {
	local file_list=("${matching_files[@]}")
	local count_choice
	echo "Multiple matching firmware files found:"
	for i in "${!file_list[@]}"; do
		echo "$((i + 1)). $(basename "${file_list[$i]}")"
	done
	read -r -p "Select which firmware file to use [1-${#file_list[@]}]: " count_choice </dev/tty
	if ! [[ "$count_choice" =~ ^[0-9]+$ ]] ||
		[ "$count_choice" -lt 1 ] ||
		[ "$count_choice" -gt "${#file_list[@]}" ]; then
		echo "Invalid selection. Exiting."
		exit 1
	fi
	# Return the selected file path
	echo "${file_list[$((count_choice - 1))]}"
}

# Prepare the update/install script and adjust parameters if necessary.
prepare_script() {
	local selected_file script_to_run operation chosen_tag abs_script abs_selected
	selected_file=$(cat "${SELECTED_FILE_FILE}")
	operation=$(cat "${OPERATION_FILE}")
	chosen_tag=$(cat "${CHOSEN_TAG_FILE}")
	detected_dev=$(cat "${DEVICE_INFO_FILE}")
	device_port_name=$(echo "$detected_dev" | awk -F'-> ' '{print $2}')
	architecture=$(cat "${ARCHITECTURE_FILE}")
	
	script_to_run=""
	abs_selected=""
	if [ "$selected_file" ]; then
		if [ "$operation" = "update" ]; then
			script_to_run="$(dirname "$selected_file")/device-update.sh"
		elif [ "$operation" = "install" ]; then
			script_to_run="$(dirname "$selected_file")/device-install.sh"
		fi
		abs_selected="$(cd "$(dirname "$selected_file")" && pwd)/$(basename "$selected_file")"
	fi

	# Adjust baud rate for ESP32 firmware.
	if echo "$architecture" | grep -qi "esp32"; then
		if [ -f "$script_to_run" ]; then
			# Changes for update
			if [[ "$script_to_run" == *update* ]]; then
				# Ensure the baud rate is set correctly
				sed -i 's/--baud 115200/--baud 1200/g' "$script_to_run"

				# Remove any existing --port argument
				sed -i 's/--port [^ ]* //g' "$script_to_run"

				# Add the new --port argument before --baud 1200, using a different delimiter (|)
				sed -i "s|--baud 1200|--port ${device_port_name} --baud 1200 |g" "$script_to_run"
			else
				# Changes for install
				if ! grep -q '^.*sleep 5$' "$script_to_run"; then
				
					# Create a temporary diff file.
					diff_file=$(mktemp)

					cat << 'EOF' > "$diff_file"
index bacf48f..c75bcd9 100755
--- a/device-install.sh
+++ b/device-install.sh
@@ -56,6 +56,7 @@ else
        echo "Error: esptool not found"
        exit 1
 fi
+ESPTOOL_CMD="$ESPTOOL_CMD --baud 1200"

 set -e
 
 # Usage info
@@ -190,13 +191,21 @@ if [ -f "${FILENAME}" ] && [ -n "${FILENAME##*"update"*}" ]; then
                exit 1
        fi

-       echo "Trying to flash ${FILENAME}, but first erasing and writing system information"
+       echo ""
+       echo "First erasing the flash"
        $ESPTOOL_CMD erase_flash
+       sleep 5
+       echo ""
+       echo "Trying to flash ${FILENAME} at offset 0x00"
        $ESPTOOL_CMD write_flash 0x00 "${FILENAME}"
+       sleep 7
+       echo ""
        echo "Trying to flash ${OTAFILE} at offset ${OTA_OFFSET}"
-       $ESPTOOL_CMD write_flash $OTA_OFFSET "${OTAFILE}"
+       $ESPTOOL_CMD write_flash ${OTA_OFFSET} "${OTAFILE}"
+       sleep 9
+       echo ""
        echo "Trying to flash ${SPIFFSFILE}, at offset ${OFFSET}"
-       $ESPTOOL_CMD write_flash $OFFSET "${SPIFFSFILE}"
+       $ESPTOOL_CMD write_flash ${OFFSET} "${SPIFFSFILE}"

 else
        show_help
EOF
					# Apply the diff to $script_to_run
					patch --fuzz=3 --ignore-whitespace "$script_to_run" < "$diff_file"

					# Remove the temporary diff file.
					rm -f "$diff_file"
				fi
			fi

		else
			echo "No $(basename "$script_to_run") found. Skipping baud rate change."
		fi
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

list_block_devs() {
	lsblk -nrpo NAME | sort; 
}

# Run the firmware update/install script.
run_update_script() {
	local cmd user_choice PYTHON ESPTOOL_CMD newpath device_name
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
	device_port_name=$(echo "$detected_dev" | awk -F'-> ' '{print $2}')

	if echo "$architecture" | grep -qi "esp32"; then
		update_bleota

		echo "Command to run for firmware $operation:"
		echo "$abs_script -p ${device_port_name} -f $basename_selected"
	else
		echo "$basename_selected"
	fi

	if $RUN_UPDATE; then
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
	if ! command -v pipx &>/dev/null; then
		echo "Installing pipx"
		sudo apt -y install pipx
	fi
	if ! command -v meshtastic &>/dev/null; then
		pipx install "meshtastic[cli]"
		pipx ensurepath
		# shellcheck disable=SC1091
		source "$HOME/.bashrc"
	fi

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

	# Determine the esptool command.
	if echo "$architecture" | grep -qi "esp32"; then
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
	fi

	# Check if any services are locking up the device
	echo "$detected_dev"
	lockedService=$(get_locked_service "$detected_dev")
	if [ -n "$lockedService" ] && [ "$lockedService" != "None" ]; then
		echo "Stopping service $lockedService..."
		sudo systemctl stop "$lockedService"
	fi

	
	# Make a backup of the config.
	echo "Making a backup of the configuration."
	basename_device_port_name="$(basename "$device_port_name")"
	backup_config_name="config_backup.${architecture}.${device_name}.${basename_device_port_name}.$(date +%s).yaml"
	backup_config_name_sanitized=$(echo "$backup_config_name" | tr '/' '_' | tr ' ' '_')
	while true; do
		if meshtastic --port "${device_port_name}" --export-config > "${backup_config_name_sanitized}"; then
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

	# Execute update for ESP32 or non-ESP32 devices.
	if echo "$architecture" | grep -qi "esp32"; then
		export ESPTOOL_PORT=$device_port_name
		echo "Setting device into bootloader mode via baud 1200"
		$ESPTOOL_CMD --port "${device_port_name}" --baud 1200 chip_id || true
		sleep 8
		# Change directory to the script's folder.
		pushd "$(dirname "$abs_selected")" > /dev/null || { echo "Failed to change directory"; exit 1; }
		
		echo "Running: \"$abs_script\"  -p \"${device_port_name}\" -f \"$basename_selected\""
		"$abs_script" -p "${device_port_name}" -f "$basename_selected"
		echo ""
		echo "If you see no errors above then"
		echo "Firmware $operation for ESP32 device ${device_name} completed on port ${device_port_name}."
		popd > /dev/null
		if [ -f "${backup_config_name_sanitized}" ]; then
			echo "Configuration can be restored using this if it was wiped out"
			echo "meshtastic --configure \"${backup_config_name_sanitized}\""
		fi

	else
		attempt=0
		max_attempts=3
		device_id=""

		while [ $attempt -lt $max_attempts ]; do
			echo "Setting device into bootloader mode via meshtastic --enter-dfu --port ${device_port_name}"
			old_output=$(list_block_devs)

			meshtastic --enter-dfu --port "${device_port_name}" || true
			sleep 5

			new_output=$(list_block_devs)

			device_id=$(comm -13 <(echo "$old_output") <(echo "$new_output") | head -n 1)

			if [ -n "$device_id" ]; then
				break # New block device found, exit the loop.
			fi

			echo "Error: Device failed to enter DFU mode (no new block devices detected)."
			attempt=$((attempt + 1))
			if [ $attempt -lt $max_attempts ]; then
				echo "Retrying ($attempt/$max_attempts)..."
				sleep 5
			fi
		done

		if [ -z "$device_id" ]; then
			echo "Error: Device failed to enter DFU mode after $max_attempts attempts."
			exit 1
		fi

		# Check if the device is already mounted by looking in /proc/mounts.
		if grep -q "^$device_id " /proc/mounts; then
			echo "$device_id is already mounted."
		else
			echo "$device_id is not mounted. Mounting now..."
			sudo mkdir -p "$MOUNT_FOLDER"
			sudo mount "$device_id" "$MOUNT_FOLDER"
		fi

		echo "Contents of $MOUNT_FOLDER:"
		ls "$MOUNT_FOLDER"

		sudo cp -v "$abs_selected" "$MOUNT_FOLDER/"
		echo ""
		echo "Firmware $operation for ESP32 device ${device_name} completed on port ${device_port_name}."
		if [ -f "${backup_config_name_sanitized}" ]; then
			echo "Configuration can be restored using this if it was wiped out"
			echo "meshtastic --configure \"${backup_config_name_sanitized}\""
		fi

	fi

	# Restart the stopped service.
	if [ -n "$lockedService" ] && [ "$lockedService" != "None" ]; then
		echo "Starting service $lockedService..."
		sudo systemctl start "$lockedService"
	fi
}

##################
# Main Execution #
##################
parse_args "$@"
update_releases

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
detect_device        # ${DEVICE_INFO_FILE} ${DETECTED_PRODUCT_FILE}
match_firmware_files # ${MATCHING_FILES_FILE}
select_firmware_file # ${SELECTED_FILE_FILE}
detect_esp			 # ${ARCHITECTURE_FILE}
choose_operation     # ${OPERATION_FILE}
prepare_script       # ${CMD_FILE}
run_update_script
