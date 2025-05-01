#!/bin/bash
set -euo pipefail

# Directory we started in.
ORIG_DIR="$(pwd)"

# search for platformio.ini containing meshtastic
found=false
count=0
while [ $count -lt 2 ]; do
    parent="$(dirname "$PWD")"
	file=$(find "$PWD" -type f -name platformio.ini -exec grep -q "github.com/meshtastic" {} \; -print | sort -r | tail -n 1)

    if [[ -n "$file" ]]; then
		parent="$(dirname "$file")"
        found=true
		cd "$parent"
        break
    fi
    count=$((count + 1))
    # determine parent directory
    # if we’re at / (or somehow can’t go up), break out
    if [[ "$parent" == "$PWD" ]]; then
        break
    fi
    cd "$parent"
done

if ! $found; then
    echo " platformio.ini with meshtastic not found in any parent directories."
    read -rp "Would you like to clone https://github.com/meshtastic/firmware here $parent? [y/N] " ans
    case "$ans" in
        [Yy]* )
			cd "$parent"
            git clone https://github.com/meshtastic/firmware && cd firmware
            # after cloning, you probably want to repeat the search or just proceed
            if [[ -f "platformio.ini" ]] && grep -q "github.com/meshtastic" platformio.ini; then
                echo "Now in $(pwd), and platformio.ini is present."
            else
                echo "Cloned, but platformio.ini still missing or wrong."
            fi
            ;;
        * )
            echo "Exiting without cloning."
            exit 1
            ;;
    esac
fi
echo "$PWD"

# Cleanup function that returns back.
cleanup() {
  cd "$ORIG_DIR" || exit
}
# arrange for cleanup() to run on EXIT (this covers normal exit, errors, and Ctrl‑C)
trap cleanup EXIT

# Create small package (no debugging symbols)
# Add `argp` for musl
# -Os: Optimize for size; enables most -O2 optimizations.
#-ffunction-sections -fdata-sections: Place individual functions and data in their own sections. 
#   Allows the linker to later remove any sections that aren’t referenced in the final executable.
# -Wl,--gc-sections: Linker garbage collection of unused sections.
# -largp: Link against the argp library; provides command-line argument parsing.
PLATFORMIO_BUILD_FLAGS="-Os -ffunction-sections -fdata-sections -Wl,--gc-sections -largp"

VPN_INFO="$HOME/.vpnServerInfo"
# Number of attempts for each file
MAX_ATTEMPTS=60
# Timeout in seconds for scp (adjust if needed)
SCP_TIMEOUT=5

# Optionally pass the desired environment name as the first argument.
env_arg="${1:-}"

# Update git
git reset --hard
git fetch origin
git switch master 2>/dev/null || git checkout master
git reset --hard origin/master
git fetch origin
git pull
git pull --recurse-submodules


# Get environment names from platformio.ini files.
# This finds all lines that start with [env: and then strips off the prefix and trailing ].
mapfile -t envs < <(
    find . -type f -name "platformio.ini" -exec grep -h "^\[env:" {} \; \
    | sort -u \
    | sed -n 's/^\[env:\([^]]*\)].*/\1/p'
)

# Check if any environments were found.
if [ ${#envs[@]} -eq 0 ]; then
    echo "No environments found in platformio.ini files."
    exit 1
fi

selected_env=""
if [ -n "$env_arg" ]; then
    # Try to auto-select an environment that matches the provided argument (case-insensitive).
    for env in "${envs[@]}"; do
        if [[ "${env,,}" == "${env_arg,,}" ]]; then
            selected_env="$env"
            break
        fi
    done

    if [ -z "$selected_env" ]; then
        echo "Environment '$env_arg' not found in the list."
    else
        echo "Auto-selected environment: $selected_env"
    fi
fi

if [ -z "$selected_env" ]; then
    # Display a numbered menu for the user to choose an environment.
    echo "Select an environment:"
    for i in "${!envs[@]}"; do
        printf "%d) %s\n" $((i+1)) "${envs[$i]}"
    done
    
    # If .pio/libdeps exists, show the short list of already built environments—but only if there is at least one.
    if [ -d ".pio/libdeps" ]; then
        # Enable nullglob so that the array is empty if no match is found.
        shopt -s nullglob
        built_dirs=(.pio/libdeps/*/)
        if [ ${#built_dirs[@]} -gt 0 ]; then
            # Create an associative array of built environment names.
            declare -A built_envs
            for d in "${built_dirs[@]}"; do
                if [ -d "$d" ]; then
                    built_name=$(basename "$d")
                    built_envs["$built_name"]=1
                fi
            done
            # Only print the section if at least one environment matches.
            if [ ${#built_envs[@]} -gt 0 ]; then
                echo ""
                echo "Already built environments:"
                
                # Loop through the global env list. When the env name is found in built_envs, print its number, name, and last build version.
                for i in "${!envs[@]}"; do
                    env_name="${envs[$i]}"
                    if [ -n "${built_envs[$env_name]:-}" ]; then

                        # Capture the newest version folder for this env:
                        versionLastBuild=$(
                            find release -type f -path "release/*/$env_name/*" \
                              | sed -n "s|release/\([^/]*\)/$env_name/.*|\1|p" \
                              | sort -V \
                              | tail -n1
                        )

                        # Print index, env name, and last build version
                        printf "%d) %s   (last build: %s)\n" \
                            $((i+1)) "$env_name" "$versionLastBuild"
                    fi
                done
            fi
        fi
        shopt -u nullglob
    fi

    read -rp "Enter number: " selection
    if ! [[ "$selection" =~ ^[0-9]+$ ]] || [ "$selection" -lt 1 ] || [ "$selection" -gt ${#envs[@]} ]; then
        echo "Invalid selection."
        exit 1
    fi

    selected_env="${envs[$((selection-1))]}"
fi

# Now you have the selected environment in $selected_env.
# You can use it further in your script.
echo "Final environment: $selected_env"

VERSION=$(bin/buildinfo.py long)

# Get the last 20 tags (sorted by creation date descending)
mapfile -t tags < <(git tag --sort=-creatordate | head -n20 | tac)

if [ ${#tags[@]} -eq 0 ]; then
    echo "No tags found in this repository."
    exit 1
fi

echo "Select a release to check out:"
n=1
declare -A tagmap
for tag in "${tags[@]}"; do
    echo "$n) $tag"
    tagmap[$n]="$tag"
    ((n++))
done
# Add an extra option for "current"
echo "$n) v${VERSION}+ current "
read -rp "Enter selection [1-$n]: " choice

if [[ "$choice" =~ ^[0-9]+$ ]]; then
    if [ "$choice" -ge 1 ] && [ "$choice" -lt "$n" ]; then
        selected="${tagmap[$choice]}"
        echo "You selected tag: $selected"
        git reset --hard
        git config advice.detachedHead false
        git checkout "$selected"
    elif [ "$choice" -eq "$n" ]; then
        echo "You selected: $VERSION current"
    else
        echo "Invalid selection: number not in range."
        exit 1
    fi
else
    echo "Invalid input; please enter a number."
    exit 1
fi

# Determine which extra patch exists, prefer extra.bbs.patch if available.
if [ -f extra.bbs.patch ]; then
  extraPatchFile="extra.bbs.patch"
elif [ -f extra.patch ]; then
  extraPatchFile="extra.patch"
else
  extraPatchFile=""
fi

# Check for an environment-specific patch.
if [ -f "${selected_env}.patch" ]; then
  envPatchFile="${selected_env}.patch"
else
  envPatchFile=""
fi

# Prepare an array of menu options and corresponding actions.
options=()
actions=()

# --- Option 1: No modifications ---
options+=("No modifications")
actions+=("echo 'No modifications selected.'")

enableRHAction="$(cat <<'EOF'
find . -type f -name "platformio.ini" | while read -r file; do
    if grep -q -- "-DMESHTASTIC_EXCLUDE_REMOTEHARDWARE=1" "$file"; then
        echo "Processing: $file"
        sed -i 's/-DMESHTASTIC_EXCLUDE_REMOTEHARDWARE=1/-DMESHTASTIC_EXCLUDE_REMOTEHARDWARE=0/g' "$file"
    fi
done
echo "All platformio.ini files have been updated."
EOF
)"

# --- Option 2: Enable Remote Hardware ---
options+=("Enable Remote Hardware")
actions+=("$enableRHAction")

# --- Option 3: Apply extra patch only ---
if [ -n "$extraPatchFile" ]; then
    options+=("Apply $extraPatchFile")
    actions+=("echo 'Applying $extraPatchFile...' && git apply $extraPatchFile")
fi

# --- Option 4: Enable Remote Hardware + apply extra patch ---
# Only add if extra patch exists and no env patch exists,
# OR if both exist we’ll add a dedicated option later.
if [ -n "$extraPatchFile" ] && [ -z "$envPatchFile" ]; then
    options+=("Enable Remote Hardware + apply $extraPatchFile")
    actions+=("$enableRHAction
echo 'Applying $extraPatchFile...'
git apply $extraPatchFile")
fi

# --- Option 5: Enable Remote Hardware + apply extra patch + apply env patch ---
if [ -n "$extraPatchFile" ] && [ -n "$envPatchFile" ]; then
    options+=("Enable Remote Hardware + apply $extraPatchFile + apply ${envPatchFile}")
    actions+=("$enableRHAction
echo 'Applying $extraPatchFile...'
git apply $extraPatchFile
echo 'Applying ${envPatchFile}...'
git apply ${envPatchFile}")
fi

# --- Option 6: Apply env patch only ---
# Two cases: when extra patch is absent OR as an additional option if both exist.
if [ -n "$envPatchFile" ]; then
    # If extra patch is absent, this will be the only env option.
    options+=("Apply ${envPatchFile}")
    actions+=("echo 'Applying ${envPatchFile}...'
git apply ${envPatchFile}")
fi

# Display the dynamic menu.
echo "Select an option:"
for i in "${!options[@]}"; do
    printf "%d) %s\n" $((i+1)) "${options[$i]}"
done

read -rp "Enter your choice (1-${#options[@]}): " choice

# Validate the choice.
if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "${#options[@]}" ]; then
    echo "Invalid choice. Exiting."
    exit 1
fi

selected_index=$((choice - 1))
echo "Executing: ${options[$selected_index]}"
eval "${actions[$selected_index]}"



VERSION=$(bin/buildinfo.py long)
if grep -q "DMESHTASTIC_EXCLUDE_REMOTEHARDWARE=0" platformio.ini; then
    VERSION="${VERSION::-4}GPIO"
fi

# The shell vars the build tool expects to find
export APP_VERSION=$VERSION
OUTDIR="release/$VERSION/$selected_env"

rm -f "${OUTDIR:?}"/firmware* > /dev/null 2>&1 || true
if [ -d "${OUTDIR:?}" ]; then
    rm -r "${OUTDIR:?}"/* > /dev/null 2>&1 || true
fi
mkdir -p "$OUTDIR"

basename=firmware-$selected_env-$VERSION


rm -f .pio/build/"$selected_env"/firmware.*

if [ -z "$env_arg" ]; then
    read -rp "Target: $basename. Press Enter to continue..."
fi

newpath=0
if ! command -v platformio &>/dev/null; then
	pipx install "platformio"
	newpath=1
fi
if [ $newpath -eq 1 ]; then
	pipx ensurepath
	# shellcheck disable=SC1091
	source "$HOME/.bashrc"
fi

platformio pkg update -e "$selected_env"
echo "Building for $selected_env with PLATFORMIO_BUILD_FLAGS: > $PLATFORMIO_BUILD_FLAGS <"

pio run --environment "$selected_env" # -v
SRCELF=.pio/build/"$selected_env"/firmware.elf
cp "$SRCELF" "$OUTDIR"/"$basename".elf

if [ -f .pio/build/"$selected_env"/firmware.factory.bin ]; then
    echo "Copying ESP32 bin file"
    SRCBIN=.pio/build/"$selected_env"/firmware.factory.bin
    cp "$SRCBIN" "$OUTDIR"/"$basename".bin
fi

if [ -f .pio/build/"$selected_env"/firmware.bin ]; then
    echo "Copying ESP32 update bin file"
    SRCBIN=.pio/build/"$selected_env"/firmware.bin
    cp "$SRCBIN" "$OUTDIR"/"$basename"-update.bin
fi

if [ -f .pio/build/"$selected_env"/firmware.zip ]; then
    echo "Generating NRF52 dfu file"
    DFUPKG=.pio/build/"$selected_env"/firmware.zip
    cp "$DFUPKG" "$OUTDIR/$basename-ota.zip"
fi

if [ -f .pio/build/"$selected_env"/firmware.hex ]; then
    echo "Generating NRF52 uf2 file"
    SRCHEX=.pio/build/"$selected_env"/firmware.hex
fi

if [ -n "${SRCHEX:-}" ]; then
	bin/uf2conv.py "$SRCHEX" -c -o "$OUTDIR/$basename.uf2" -f 0xADA52840
	cp bin/*.uf2 "$OUTDIR"
else
    echo "Building Filesystem with web server for ESP32 targets"
    pio run --environment "$selected_env" -t buildfs || true
    cp .pio/build/"$selected_env"/littlefs.bin "$OUTDIR"/littlefswebui-"$selected_env"-"$VERSION".bin

    echo "Building Filesystem only for ESP32 targets"
    # Remove webserver files from the filesystem and rebuild

    if [ -d data/static ]; then
        ls -l data/static # Diagnostic list of files
        rm -rf data/static
    else
        echo "data/static not found, skipping cleanup"
    fi

    pio run --environment "$selected_env" -t buildfs || true
    cp .pio/build/"$selected_env"/littlefs.bin "$OUTDIR"/littlefs-"$selected_env"-"$VERSION".bin
fi
cp bin/device-install.* "$OUTDIR"/
cp bin/device-update.* "$OUTDIR"/

rm "$OUTDIR"/"$basename".elf

find "$OUTDIR" -maxdepth 1 -type f -exec du -h {} \; \
  | sed 's|^\./||' \
  | awk '{print $1, $2}' \
  | sort -k2 \
  | column -t

if [ -f "$VPN_INFO" ]; then
    # Trap SIGINT (Ctrl-C) to kill all child processes and exit.
    trap 'echo "Interrupted by Ctrl-C. Exiting."; kill 0; exit 1' SIGINT

    while IFS= read -r line || [ -n "$line" ]; do
        # Skip empty lines or comments
        [[ -z "$line" || "$line" =~ ^# ]] && continue

        echo ""
        echo "=== Processing: $line ==="

        # Parse optional embedded password: user:pass@host vs user@host
        if [[ "$line" =~ ^([^:]+):([^@]+)@(.+)$ ]]; then
            user="${BASH_REMATCH[1]}"
            PASSWORD="${BASH_REMATCH[2]}"
            host="${BASH_REMATCH[3]}"
            connection="$user@$host"
            echo "[DEBUG] Using embedded password for $connection" >&2
        else
            connection="$line"
            # Prompt once per connection
            read -rp "Enter password for $connection (or 'skip'): " PASSWORD < /dev/tty
            # erase prompt
            printf "\r"; tput cuu1; tput el
        fi

        # If they typed 'skip' or left it blank, we skip this connection
        if [ "$PASSWORD" = "skip" ] || [ -z "$PASSWORD" ]; then
            echo "Skipped $connection."
            continue
        fi

        # Now do the SCP loop
        for file in "$OUTDIR"/*; do
            [ -f "$file" ] || continue
            basefile=$(basename "$file")
            local_md5=$(md5sum "$file" | awk '{print $1}')
            attempt=1
            success=0

            while [ $attempt -le $MAX_ATTEMPTS ]; do
                echo -n "$attempt: $basefile -> $connection ..."
                printf "\r"

                # ensure remote dir
                sshpass -p "$PASSWORD" ssh -n -o StrictHostKeyChecking=no \
                      "$connection" "mkdir -p ~/meshfirmware/meshtastic_firmware/${VERSION}/"

                timeout --foreground $SCP_TIMEOUT \
                  sshpass -p "$PASSWORD" scp -o StrictHostKeyChecking=no \
                    "$file" "${connection}:~/meshfirmware/meshtastic_firmware/${VERSION}/" < /dev/null
                scp_status=$?

                [ $scp_status -ne 0 ] && { ((attempt++)); continue; }

                remote_md5=$(sshpass -p "$PASSWORD" ssh -n -o StrictHostKeyChecking=no \
                  "$connection" "md5sum ~/meshfirmware/meshtastic_firmware/${VERSION}/${basefile} 2>/dev/null" \
                  | awk '{print $1}')

                if [ "$local_md5" = "$remote_md5" ]; then
                    echo "$basefile copied to $connection (MD5 matched)."
                    success=1
                    break
                else
                    echo "MD5 mismatch for $basefile on $connection. Retrying..."
                    ((attempt++))
                fi
            done

            if [ $success -ne 1 ]; then
                echo "Failed to copy $basefile to $connection after $MAX_ATTEMPTS attempts."
            fi
        done

        echo "Finished processing $connection."
    done < "$VPN_INFO"
fi

echo "${ORIG_DIR:?}/firmware.sh"
if [[ -f "${ORIG_DIR:?}/firmware.sh" ]]; then
    # ensure the target directory exists
    echo "Making dir ${ORIG_DIR:?}/meshtastic_firmware/${VERSION}"
    mkdir -p "${ORIG_DIR:?}/meshtastic_firmware/${VERSION}"

    for file in "$OUTDIR"/*; do
        [[ -f "$file" ]] || continue
        basefile=${file##*/}  # same as basename
        cp -- "$file" "${ORIG_DIR:?}/meshtastic_firmware/${VERSION}/$basefile"
    done
fi
