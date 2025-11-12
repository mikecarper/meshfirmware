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

if ! command -v chronyc &>/dev/null; then
	echo "Installing chrony"
	sudo apt update && sudo apt -y install chrony
	sudo systemctl enable chrony
	sudo systemctl restart chrony
fi

# Sync Time
chronyc tracking

# Ensure socat is installed.
if ! command -v socat &>/dev/null; then
	echo "Installing socat"
	sudo apt update && sudo apt -y install socat
fi

REPO_OWNER="meshcore-dev"
REPO_NAME="MeshCore"
CONFIG_URL="https://api.meshcore.nz/api/v1/config"

         FIRMWARE_ROOT="${PWD_SCRIPT}/${REPO_OWNER}_${REPO_NAME}"
      DEVICE_PORT_FILE="${FIRMWARE_ROOT}/09device_port_file.txt"
 DEVICE_PORT_NAME_FILE="${FIRMWARE_ROOT}/10device_port_name_file.txt"
     RADIO_CONFIG_FILE="${FIRMWARE_ROOT}/meshcore_config.json}"
 

BOOT_WAIT="${BOOT_WAIT:-2}" 
BAUD="${3:-115200}"
TIMEOUT="${4:-4}"


mkdir -p "$(dirname "$DEVICE_PORT_FILE")"
mkdir -p "$(dirname "$DEVICE_PORT_NAME_FILE")"

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
  echo "Spreading factor options: 7, 8, 9, 10, 11, 12"
  while :; do
    read -rp "SF (7-12): " sf
    if [[ "$sf" =~ ^[0-9]+$ ]] && [ "$sf" -ge 7 ] && [ "$sf" -le 12 ]; then
      break
    fi
    echo "Please enter 7, 8, 9, 10, 11, or 12."
  done

  # Bandwidth
  echo "Bandwidth options (kHz): 62.5, 125, 250, 500"
  while :; do
    read -rp "BW (62.5, 125, 250, 500): " bw
    case "$bw" in
      62.5|125|250|500)
        break
        ;;
      *)
        echo "Please enter one of: 62.5, 125, 250, 500."
        ;;
    esac
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
choose_serial
device_name=""
[[ -f "$DEVICE_PORT_FILE" ]] && device_name="$(<"$DEVICE_PORT_FILE")"


# Make sure device exists
if [ ! -e "$device_name" ]; then
  echo "Error: device $device_name not found" >&2
  exit 1
fi

# Helper to send a command and capture reply
serial_cmd() {
  local line="$*"
  printf "%b" "${line}\r\n" \
  | socat - "$device_name,raw,echo=0,b${BAUD:-115200}" 2>/dev/null \
  | tr -d '\r' \
  | awk 'NF{last=$0} END{print last}' \
  | sed -E $'s/\x1B\\[[0-9;]*[A-Za-z]//g' \
  | sed -E 's/^[[:space:][:cntrl:]]*(->|>)+[[:space:]]*//' \
  | sed -E 's/^[[:space:][:cntrl:]]+//; s/[[:space:]]+$//' \
  | sed -E 's/^[^0-9A-Za-z+\-]+//'    # fallback: drop anything weird before data
}

trim() { 
	sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
}

load_repeater_settings() {
  echo "reading all radio settings"

  # keys to fetch (radio handled separately)
  local k v
  local keys=(
    tx
    repeat
    allow.read.only
    agc.reset.interval
    advert.interval
    flood.advert.interval
    guest.password
    password
    prv.key
    public.key
    name
    lat
    lon
    txdelay
  )

  # fetch generic keys
  for k in "${keys[@]}"; do
    v="$(serial_cmd "get $k" | trim)"
    case "$k" in
      tx)                     setting_tx="$v" ;;
      repeat)                 setting_repeat="$v" ;;
      allow.read.only)        setting_allow_read_only="$v" ;;
      agc.reset.interval)     setting_agc_reset_interval="$v" ;;
      advert.interval)        setting_advert_interval="$v" ;;
      flood.advert.interval)  setting_flood_advert_interval="$v" ;;
      guest.password)         setting_guest_password="$v" ;;
      password)               setting_password="$v" ;;
      prv.key)                setting_private_key="$v" ;;
      public.key)             setting_public_key="$v" ;;
      name)                   setting_name="$v" ;;
      lat)                    setting_lat="$v" ;;
      lon)                    setting_lon="$v" ;;
      txdelay)                setting_txdelay="$v" ;;
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
	echo " r) Refresh this list"
    echo " 1) tx                 = $setting_tx"
    echo " 2) repeat             = $setting_repeat"
    echo " 3) allow.read.only    = $setting_allow_read_only"
    echo " 4) agc.reset.interval = $setting_agc_reset_interval"
    echo " 5) advert.interval    = $setting_advert_interval"
    echo " 6) flood.advert.intvl = $setting_flood_advert_interval"
    echo " 7) guest.password     = $setting_guest_password"
    echo " 8) password           = $setting_password"
    echo " 9) private key        = $setting_private_key"
    echo "10) public key         = ${setting_public_key:0:16}...${setting_public_key:48:16} (read-only)"
    echo "11) name               = $setting_name"
    echo "12) lat                = $setting_lat"
    echo "13) lon                = $setting_lon"
    echo "14) txdelay            = $setting_txdelay"
    echo "15) radio              = freq=$RADIO_FREQ bw=$RADIO_BW sf=$RADIO_SF cr=$RADIO_CR"
    echo
    echo "Choose a setting to edit, or q to finish."
    read -rp "Choice: " choice

    case "$choice" in
	  q|Q)
		echo "Done editing settings."
		break
		;;
		
	  r|R)
		load_repeater_settings
		;;


	  1)
		read -rp "tx (current: $setting_tx): " v
		[ -n "$v" ] && setting_tx="$v"
		serial_cmd "set tx $setting_tx"
		;;

	  2)
		while :; do
		  read -rp "repeat (on/off, current: $setting_repeat): " v
		  [ -z "$v" ] && break
		  case "$v" in
			on|off)
			  setting_repeat="$v"
			  break
			  ;;
			*)
			  echo "Please enter on or off."
			  ;;
		  esac
		done
		serial_cmd "set repeat $setting_repeat"
		;;

	  3)
		while :; do
		  read -rp "allow.read.only (on/off, current: $setting_allow_read_only): " v
		  [ -z "$v" ] && break
		  case "$v" in
			on|off)
			  setting_allow_read_only="$v"
			  break
			  ;;
			*)
			  echo "Please enter on or off."
			  ;;
		  esac
		done
		serial_cmd "set allow.read.only $setting_allow_read_only"
		;;

	  4)
		read -rp "agc.reset.interval (current: $setting_agc_reset_interval): " v
		[ -n "$v" ] && setting_agc_reset_interval="$v"
		serial_cmd "set agc.reset.interval $setting_agc_reset_interval"
		;;

	  5)
		read -rp "advert.interval (current: $setting_advert_interval): " v
		[ -n "$v" ] && setting_advert_interval="$v"
		serial_cmd "set advert.interval $setting_advert_interval"
		;;

	  6)
		read -rp "flood.advert.interval (current: $setting_flood_advert_interval): " v
		[ -n "$v" ] && setting_flood_advert_interval="$v"
		serial_cmd "set flood.advert.interval $setting_flood_advert_interval"
		;;

	  7)
		read -rp "guest.password (current: $setting_guest_password): " v
		[ -n "$v" ] && setting_guest_password="$v"
		serial_cmd "set guest.password $setting_guest_password"
		;;

	  8)
		read -rp "password (current: $setting_password): " v
		[ -n "$v" ] && setting_password="$v"
		serial_cmd "set password $setting_password"
		;;

	  9)
		echo "Go here ton find a free prefix"
		echo "https://analyzer.letsme.sh/nodes/prefix-utilization"
		echo ""
		echo "Go here to make one"
		echo "https://gessaman.com/mc-keygen/"
		echo
		read -rp "private key (current shortened): ${setting_private_key:0:16}...  New value (blank to keep): " v
		if [ -n "$v" ]; then
		  setting_private_key="$v"
		  serial_cmd "set prv.key $setting_private_key"
		else
		  echo "Private key unchanged."
		fi
		;;

	  10)
		echo "public key is derived from private key and cannot be edited here."
		;;

	  11)
		read -rp "name (current: $setting_name): " v
		[ -n "$v" ] && setting_name="$v"
		serial_cmd "set name setting_name"
		;;

	  12)
		read -rp "lat (current: $setting_lat): " v
		[ -n "$v" ] && setting_lat="$v"
		serial_cmd "set lat $setting_lat"
		;;

	  13)
		read -rp "lon (current: $setting_lon): " v
		[ -n "$v" ] && setting_lon="$v"
		serial_cmd "set lon $setting_lon"
		;;

		14)
		  while :; do
			read -rp "txdelay (0.0–2.0, current: $setting_txdelay): " v
			# Keep current if empty
			if [ -z "$v" ]; then
			  v="$setting_txdelay"
			  break
			fi
			# Check numeric (integer or decimal)
			if [[ "$v" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
			  # Ensure it's within 0.0–2.0
			  if (( $(echo "$v >= 0.0 && $v <= 2.0" | bc -l) )); then
				break
			  else
				echo "Value must be between 0.0 and 2.0"
			  fi
			else
			  echo "Please enter a valid number (e.g. 0.5, 1, 2.0)"
			fi
		  done
		  setting_txdelay="$v"
		  serial_cmd "set txdelay $setting_txdelay"
		  ;;

		  15)
			if select_suggested_radio_setting; then
			  echo
			  echo "You selected: $RADIO_TITLE $RADIO_DESC"
			  echo "Setting the radio to these settings"
			  sleep 0.5
			  serial_cmd "set radio ${RADIO_FREQ},${RADIO_BW},${RADIO_SF},${RADIO_CR}"
			fi
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

board=$(serial_cmd "board" )
ver=$(serial_cmd "ver" )

echo "$board - $ver"

load_repeater_settings

edit_repeater_settings_menu

if confirm_restart_radio; then
  echo "Restarting radio..."
  # put your restart command here, e.g.:
  # serial_cmd "restart"
else
  echo "Radio restart skipped."
fi

exit
