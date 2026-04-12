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
SERIAL_BAUD_CACHE=57600
SERIAL_IDLE_TIMEOUT=2.5 
SERIAL_TOTAL_TIMEOUT=7.5

# Resolve base user/group
BASE_USER="${SUDO_USER:-$USER}"
BASE_GROUP="$(id -gn "$BASE_USER")"
SUDO_KEEPALIVE_PID=""

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

ensure_sudo_session
start_sudo_keepalive
ensure_serial_group_access

if [[ -n "${SUDO_USER:-}" ]]; then
  umask 022
fi

install_packages() {
  sudo apt-get update
  sudo apt-get -y install "$@"
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

force_time_sync() {
  if command -v chronyc >/dev/null 2>&1; then
    sudo systemctl enable chrony >/dev/null 2>&1 || true
    sudo systemctl restart chrony >/dev/null 2>&1 || true
    sudo chronyc -a makestep >/dev/null 2>&1 || sudo chronyc makestep >/dev/null 2>&1
    chronyc tracking | grep -E '^(Ref(erence)? time|System time)'
    return 0
  fi

  if command -v ntpd >/dev/null 2>&1; then
    sudo ntpd -gq
    return 0
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
				DEVICE_NAME="$detected_dev"
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
					DEVICE_NAME="$detected_dev"
					return
	            fi
        fi
        echo "Invalid selection – please try again."
    done
}
choose_serial || true

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

  # Fast read/exit behavior
  local total_timeout="${SERIAL_TOTAL_TIMEOUT:-7.5s}"  # hard cap
  local idle_timeout="${SERIAL_IDLE_TIMEOUT:-2.5}"    # socat exits after idle
  local device_name_now="${DEVICE_NAME}"
  if [[ -z "${device_name_now}" ]]; then
	device_name_now="/dev/ttyACM0"
  fi

  ensure_serial_access "$device_name_now"

  # RX-log line pattern (skip)
  local rx_pat='^[0-9]{2}:[0-9]{2}(:[0-9]{2})?[[:space:]]*-[[:space:]]*[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}[[:space:]]*U:'

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
	setting_guest_password=""
	setting_password=""
	setting_name=""
	setting_repeat=""
	setting_lat=""
	setting_lon=""
	setting_private_key=""
	setting_public_key=""
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
  
  setting_powersaving="$(serial_cmd 'powersaving' | trim)"

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
	echo " R) Refresh above settings from device"
	#echo " a) Send 0 hop advert now"
    echo " A) Send flood advert now"
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

		0)
		  read -rp "Command to run: " v
		  if [ -n "$v" ] && [ "$v" != "$setting_name" ]; then
			echo "Running: $v"
			if [[ -n "${device_epoch:-}" ]]; then
				serial_cmd "$v"
			else
				serial_cmd_echo "$v"
			fi
			setting_name="$v"
		  else
			echo "No change to name"
		  fi
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
		  
      #a)
      #  echo "Sending zero hop advert..."
      #  serial_cmd "advert"
      #  ;;
	  
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
    read -rp "Power-cycle the node, wait for it to reconnect, then retry clock sync now? [Y/n]: " ans
    case "$ans" in
      [Yy]|"")
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


# Sync Time
force_time_sync

# Read clock from device
device_epoch="$(read_device_clock_epoch)"

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
  adiff=$((172800 + 1))
  echo "Device time (Local): unavailable"
fi


# Verdict: only act if more than 2 days off (86400 sec * 2)
if [ "$adiff" -gt 172800 ]; then
  if [[ -n "${device_epoch:-}" ]]; then
    echo "Clock off by more than 2 days; syncing time now. Sending: time $host_epoch"
  else
    echo "Device clock unreadable; syncing time now. Sending: time $host_epoch"
  fi
  if ! serial_cmd "time $host_epoch" >/dev/null; then
    echo "Warning: device did not acknowledge the time sync command"
  fi
  echo
else
  echo "Clock within 2 days"
fi

if [[ -n "${device_epoch:-}" ]]; then

	board=$(serial_cmd "board" )
	ver=$(serial_cmd "ver" )

	echo "$board - $ver"

	load_repeater_settings
	snapshot_radio_baseline
else
	echo "Serial Commands seem to be broken"
	if prompt_powercycle_and_retry_time_sync "$host_epoch"; then
		sleep 2
		device_epoch="$(read_device_clock_epoch)"
	fi
	if [[ -n "${device_epoch:-}" ]]; then
		board=$(serial_cmd "board" )
		ver=$(serial_cmd "ver" )

		echo "$board - $ver"

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
