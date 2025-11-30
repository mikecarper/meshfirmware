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
USB_AUTOSUSPEND=$(cat /sys/module/usbcore/parameters/autosuspend)

REPO_OWNER="meshcore-dev"
REPO_NAME="MeshCore"
CONFIG_URL="https://api.meshcore.nz/api/v1/config"

         FIRMWARE_ROOT="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}"
      DEVICE_PORT_FILE="${FIRMWARE_ROOT}/09device_port_file.txt"
 DEVICE_PORT_NAME_FILE="${FIRMWARE_ROOT}/10device_port_name_file.txt"
     RADIO_CONFIG_FILE="${FIRMWARE_ROOT}/meshcore_config.json"
 

BOOT_WAIT="${BOOT_WAIT:-2}" 
BAUD="${3:-115200}"
TIMEOUT="${4:-4}"


# Resolve base user/group
BASE_USER="${SUDO_USER:-$USER}"
BASE_GROUP="$(id -gn "$BASE_USER")"

if ! command -v jq >/dev/null 2>&1; then
  echo "Installing jq..."
  sudo apt update && sudo apt -y install jq
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "Installing curl..."
  sudo apt update && sudo apt -y install curl
fi
if ! command -v socat >/dev/null 2>&1; then
  echo "Installing socat..."
  sudo apt update && sudo apt -y install socat
fi
if ! command -v bc >/dev/null 2>&1; then
  echo "Installing bc..."
  sudo apt update && sudo apt -y install bc
fi
if ! command -v chronyc &>/dev/null; then
	echo "Installing chrony"
	sudo apt update && sudo apt -y install chrony
	sudo systemctl enable chrony
	sudo systemctl restart chrony
fi

# Create a directory owned by the base user, working with/without sudo
make_user_dir() {
  local dir="$1"
  if [ -n "${SUDO_USER:-}" ]; then
    # running under sudo: make as base user and ensure ownership
    sudo -u "$BASE_USER" mkdir -p "$dir"
    sudo chown "$BASE_USER:$BASE_GROUP" "$dir"
  else
    # not under sudo: normal create (already owned by us)
    mkdir -p "$dir"
  fi
}

# Write a file as the base user, robust under -euo pipefail
write_user_file() {
  local path="$1"; shift
  local content="$*"
  if [ -n "${SUDO_USER:-}" ]; then
    printf '%s\n' "$content" | sudo -u "$BASE_USER" tee "$path" >/dev/null
    sudo chown "$BASE_USER:$BASE_GROUP" "$path"
  else
    printf '%s\n' "$content" >"$path"
  fi
}

fix_and_pretty_json() {
  local raw="$1"

  # Trim whitespace
  raw="$(echo "$raw" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"

  # If empty, just bail
  [ -z "$raw" ] && return 0

  # Ensure it starts with '{'
  if [[ "$raw" != \{* ]]; then
    raw="{${raw}"
  fi

  # Fix missing opening quote on first key:
  # {noise_floor":...}  ->  {"noise_floor":...}
  raw="$(echo "$raw" | sed -E 's/^\{([^"]+)":/{"\1":/')"

  # Ensure ending '}'
  if [[ "$raw" != *\} ]]; then
    raw="${raw}}"
  fi

  # Pretty-print if possible
  echo "$raw" | jq . 2>/dev/null || echo "$raw"
}

ensure_meshcore_config() {
  # Ensure jq and curl exist
  if ! command -v jq >/dev/null 2>&1; then
    echo "Installing jq..."
    sudo apt update && sudo apt -y install jq
  fi

  if ! command -v curl >/dev/null 2>&1; then
    echo "Installing curl..."
    sudo apt update && sudo apt -y install curl
  fi

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

  RADIO_TITLE="Custom"
  RADIO_DESC="Custom: ${freq}MHz / SF${sf} / BW${bw} / CR${cr}"
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

  # Exported globals for caller for suggested entry
  RADIO_TITLE="${_RADIO_TITLES[$sel]}"
  RADIO_DESC="${_RADIO_DESCS[$sel]}"
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

# Helper to send a command and capture reply
serial_cmd() {
  local line="$*"
  local max_retries=5
  local delay_between=0.08
  local out
  local rx_pat='^[0-9]{2}:[0-9]{2}(:[0-9]{2})?[[:space:]]*-[[:space:]]*[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}[[:space:]]*U:'

  for ((attempt=1; attempt<=max_retries; attempt++)); do
    sleep 0.01
    out="$(
      printf "%b" "${line}\r\n" \
      | timeout 2s socat - "$device_name,raw,echo=0,b${BAUD:-57600}" 2>/dev/null \
      | tr -d '\r' \
      | sed -E $'s/\x1B\\[[0-9;]*[A-Za-z]//g' \
      | sed -E 's/^[[:space:][:cntrl:]]*(->|>)+[[:space:]]*//' \
      | sed -E 's/^[[:space:][:cntrl:]]+//; s/[[:space:]]+$//' \
      | sed -E 's/^[^0-9A-Za-z+\-]+//' \
      | awk -v cmd="$line" '
          BEGIN {
            # RX-log line pattern: HH:MM[:SS] - D/M/YYYY U:
            rx = "^[0-9]{2}:[0-9]{2}(:[0-9]{2})?[[:space:]]*-[[:space:]]*[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}[[:space:]]*U:"
          }
          NF {
            # Skip RX logs and command echoes
            if ($0 ~ rx) next
            if ($0 == cmd) next
            keep[++n] = $0
          }
          END {
            if (n) print keep[n];
          }'
    )"

    # Retry if we got nothing or still caught a log line somehow
    if [[ -z "$out" || "$out" =~ $rx_pat || "$out" == "$line" ]]; then
      sleep "$delay_between"
      continue
    fi

    printf "%s\n" "$out"
    return 0
  done

  # Last resort: print whatever we have (may be empty)
  printf "%s\n" "$out"
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
  local key="$1" cur="$2" new="$3" mode="${4:-str}"
  new="$( trim "$new")"
  cur="$( trim "$cur")"
  [ -z "$new" ] && { echo "No change: $key left as '$cur'"; return 0; }

  if [ "$mode" = "num" ]; then
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
  serial_cmd "set $key $new"
}

load_repeater_settings() {
  echo "reading all radio settings"

  # https://github.com/meshcore-dev/MeshCore/blob/main/src/helpers/CommonCLI.cpp#L131
  # keys to fetch (radio handled separately)
  local k v
  local keys=(
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
	  prv.key
	  public.key
	  lat
	  lon
  )

  # fetch generic keys
  for k in "${keys[@]}"; do
    v="$(serial_cmd "get $k" | trim)"
    case "$k" in
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
	  repeat)                 setting_repeat="$v" ;;
	  lat)                    setting_lat="$v" ;;
      lon)                    setting_lon="$v" ;;
      prv.key)                setting_private_key="$v" ;;
      public.key)             setting_public_key="$v" ;;
      rxdelay)                setting_rxdelay="$v" ;;
      txdelay)                setting_txdelay="$v" ;;
      direct.txdelay)         setting_direct_txdelay="$v" ;;
      flood.max)              setting_flood_max="$v" ;;
	  tx)                     setting_tx="$v" ;;
	  role)                   setting_role="$v" ;;

    esac
  done

  # radio needs CSV parsing: {freq},{bw},{sf},{cr}
  local radio_raw
  radio_raw="$(serial_cmd 'get radio' | trim)"
  # remove spaces around commas just in case
  radio_raw="$(echo "$radio_raw" | sed -E 's/[[:space:]]*,[[:space:]]*/,/g')"
  IFS=',' read -r RADIO_FREQ RADIO_BW RADIO_SF RADIO_CR <<< "$radio_raw"
}

edit_repeater_settings_menu() {
  while :; do
    echo
    echo "Current settings:"
    echo " 1) tx                    = $setting_tx"
    echo " 2) repeat                = $setting_repeat"
    echo " 3) allow.read.only       = $setting_allow_read_only"
    echo " 4) agc.reset.interval    = $setting_agc_reset_interval"
    echo " 5) advert.interval       = $setting_advert_interval"
    echo " 6) flood.advert.interval = $setting_flood_advert_interval"
    echo " 7) flood.max             = $setting_flood_max"
    echo " 8) guest.password        = $setting_guest_password"
    echo " 9) password              = $setting_password"
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
	echo " R) Refresh above settings from device"
    echo " A) Send advert now"
    echo " L) Logs: start/stop/erase"
    echo " C) Clear stats"
	echo " Q) Quit"
    echo
    echo "Choose an item to edit, an action (A/L/C), or q to finish."
    read -rp "Choice: " choice

    case "$choice" in
      q|Q) echo "Done."; break ;;

      r|R)
        echo "Reloading settings from device..."
        load_repeater_settings
		snapshot_radio_baseline
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
			serial_cmd "set guest.password $v"
			setting_guest_password="$v"
		  else
			echo "No change to guest.password"
		  fi
		  ;;

		9)
		  read -rp "password (current: ${setting_password:-<empty>}): " v
		  if [ -n "$v" ] && [ "$v" != "$setting_password" ]; then
			echo "Updating password"
			serial_cmd "set password $v"
			setting_password="$v"
		  else
			echo "No change to password"
		  fi
		  ;;

		10)
		  echo "Existing key: ${setting_private_key}"
		  read -rp "private key (blank to keep): " v
		  if [ -n "$v" ] && [ "$v" != "$setting_private_key" ]; then
			echo "Updating private key"
			serial_cmd "set prv.key $v"
			setting_private_key="$v"
		  else
			echo "Private key unchanged."
		  fi
		  ;;

		12)
		  read -rp "name (current: $setting_name): " v
		  if [ -n "$v" ] && [ "$v" != "$setting_name" ]; then
			serial_cmd "set name $v"
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
			  serial_cmd "set radio ${RADIO_FREQ},${RADIO_BW},${RADIO_SF},${RADIO_CR}"
			else
			  echo "Radio unchanged."
			fi
		  fi
		  ;;

      a|A)
        echo "Sending advert..."
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

      c|C)
        echo "Clearing stats..."
        serial_cmd "stats clear"
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


# Make sure we're setup
make_user_dir "$(dirname "$DEVICE_PORT_FILE")"
make_user_dir "$(dirname "$DEVICE_PORT_NAME_FILE")"

# Get serial device
choose_serial
device_name=""
[[ -f "$DEVICE_PORT_FILE" ]] && device_name="$(<"$DEVICE_PORT_FILE")"
# Make sure device exists
if [ ! -e "$device_name" ]; then
  echo "Error: device $device_name not found" >&2
  exit 1
fi

# Sync Time
chronyc tracking | grep -E '^(Ref(erence)? time|System time)'

# Read clock from device
device_epoch="$(
  serial_cmd clock \
  | sed -En 's/.*([0-9]{1,2}):([0-9]{2}) *- *([0-9]{1,2})\/([0-9]{1,2})\/([0-9]{4}) *UTC.*/\5-\4-\3 \1:\2:00/p' \
  | xargs -I{} date -u -d "{}" +%s
)"

# Current host UNIX time (seconds since epoch)
host_epoch=$(date +%s)

diff=$(( device_epoch - host_epoch ))
adiff=${diff#-}


echo "device_epoch: $device_epoch"
echo "host_epoch  : $host_epoch"
echo "Device time (Local): $(date -d "@$device_epoch" '+%Y-%m-%d %H:%M %Z')"
echo "Host   time (Local): $(date -d "@$host_epoch" '+%Y-%m-%d %H:%M %Z')"
# Verdict: only act if more than 2 days off (86400 sec * 2)
if [ "$adiff" -gt 172800 ]; then
  echo "Clock off by more than 2 days; syncing time now. Sending: time $host_epoch"
  serial_cmd "time $host_epoch"
else
  echo "Clock within 2 days"
fi

StatsRadio=$( serial_cmd stats-radio )
fix_and_pretty_json "$StatsRadio"
StatsPackets=$( serial_cmd stats-packets )
fix_and_pretty_json "$StatsPackets"
StatsCore=$( serial_cmd stats-core )
fix_and_pretty_json "$StatsCore"


board=$(serial_cmd "board" )
ver=$(serial_cmd "ver" )
echo "$board - $ver"

load_repeater_settings
snapshot_radio_baseline

edit_repeater_settings_menu

if confirm_restart_radio; then
  echo "Restarting radio..."
  # put your restart command here, e.g.:
  # serial_cmd "restart"
else
  echo "Radio restart skipped."
fi

exit
