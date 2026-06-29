#!/usr/bin/env bash
set -euo pipefail

# Upload MeshCore build outputs to each target listed in ~/.targets.
#
# ~/.targets formats:
#   user@host[:port]
#   user@host[:port]|key=/path/to/key
#   user:password@host[:port]
#   user:password@host[:port]|key=/path/to/key
#
# Examples:
#   mike@192.168.1.50
#   mike@example.local:2222|key=~/.ssh/id_ed25519
#   mike:secret@192.168.1.50
#   mike:secret@example.local:2222
#
# Optional overrides:
#   TARGETS_FILE=/path/to/targets ./upload_meshcore_out.sh
#   MESHCORE_DIR=/path/to/MeshCore ./upload_meshcore_out.sh
#   OUT_DIR=/path/to/out ./upload_meshcore_out.sh
#   REMOTE_DIR='~/meshfirmware/meshcore-dev_MeshCore/downloads/custom' ./upload_meshcore_out.sh
#   FILE_MODE=merged ./upload_meshcore_out.sh

TARGETS_FILE="${TARGETS_FILE:-$HOME/.targets}"
REMOTE_DIR="${REMOTE_DIR:-~/meshfirmware/meshcore-dev_MeshCore/downloads/custom}"
FILE_MODE="${FILE_MODE:-nonmerged}"
DRY_RUN=0
RUN_MENU=1

usage() {
	cat <<'USAGE'
Usage: upload_meshcore_out.sh [-n] [--no-menu] [--nonmerged|--merged|--all]

Reads targets from ~/.targets and uploads regular files from MeshCore/out.

Target format:
  user@host[:port]
  user@host[:port]|key=/path/to/key
  user:password@host[:port]
  user:password@host[:port]|key=/path/to/key

Options:
  -n, --dry-run   Show what would be uploaded without connecting.
  --no-menu       Upload immediately after ensuring the targets file exists.
  --nonmerged     Upload files whose names do not contain "-merged" (default).
  --merged        Upload files whose names contain "-merged".
  --all           Upload all regular files in MeshCore/out.
  --mode MODE     Set file mode: nonmerged, merged, or all.
  -h, --help      Show this help.
USAGE
}

set_file_mode() {
	local mode="$1"
	case "$mode" in
		nonmerged|non-merged)
			FILE_MODE="nonmerged"
			;;
		merged)
			FILE_MODE="merged"
			;;
		all)
			FILE_MODE="all"
			;;
		*)
			echo "Invalid file mode: $mode" >&2
			echo "Expected one of: nonmerged, merged, all" >&2
			exit 2
			;;
	esac
}

while (($#)); do
	case "$1" in
		-n|--dry-run)
			DRY_RUN=1
			shift
			;;
		--no-menu)
			RUN_MENU=0
			shift
			;;
		--nonmerged|--non-merged)
			set_file_mode nonmerged
			shift
			;;
		--merged)
			set_file_mode merged
			shift
			;;
		--all)
			set_file_mode all
			shift
			;;
		--mode)
			[[ $# -ge 2 ]] || {
				echo "--mode requires a value: nonmerged, merged, or all" >&2
				exit 2
			}
			set_file_mode "$2"
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "Unknown option: $1" >&2
			usage >&2
			exit 2
			;;
	esac
done

set_file_mode "$FILE_MODE"

need_cmd() {
	local cmd="$1"
	if ! command -v "$cmd" >/dev/null 2>&1; then
		echo "Missing required command: $cmd" >&2
		return 1
	fi
}

trim() {
	local value="$1"
	value="${value#"${value%%[![:space:]]*}"}"
	value="${value%"${value##*[![:space:]]}"}"
	printf '%s' "$value"
}

shell_quote() {
	local value="$1"
	printf "'%s'" "${value//\'/\'\\\'\'}"
}

detect_meshcore_dir() {
	local script_dir candidate
	script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	for candidate in \
		"${MESHCORE_DIR:-}" \
		"$script_dir/../MeshCore" \
		"$HOME/git/MeshCore" \
		"$HOME/MeshCore"; do
		[[ -n "$candidate" ]] || continue
		if [[ -d "$candidate/out" ]]; then
			cd "$candidate" && pwd
			return 0
		fi
	done
	return 1
}

remote_mkdir_command() {
	local dir="$REMOTE_DIR"
	# The $HOME references below are for the remote shell, not this script.
	# shellcheck disable=SC2016
	case "$dir" in
		\~)
			printf 'mkdir -p "$HOME"'
			;;
		\~/*)
			printf 'mkdir -p "$HOME"/%s' "$(shell_quote "${dir#\~/}")"
			;;
		/*)
			printf 'mkdir -p %s' "$(shell_quote "$dir")"
			;;
		*)
			printf 'mkdir -p "$HOME"/%s' "$(shell_quote "$dir")"
			;;
	esac
}

remote_dir_shell_expr() {
	local dir="$REMOTE_DIR"
	if [[ "$dir" != "/" ]]; then
		dir="${dir%/}"
	fi

	# The $HOME references below are for the remote shell, not this script.
	# shellcheck disable=SC2016
	case "$dir" in
		\~)
			printf '"$HOME"'
			;;
		\~/*)
			printf '"$HOME"/%s' "$(shell_quote "${dir#\~/}")"
			;;
		/*)
			printf '%s' "$(shell_quote "$dir")"
			;;
		*)
			printf '"$HOME"/%s' "$(shell_quote "$dir")"
			;;
	esac
}

remote_file_shell_expr() {
	local base_name="$1"
	printf '%s/%s' "$(remote_dir_shell_expr)" "$(shell_quote "$base_name")"
}

remote_copy_path() {
	local dir="$REMOTE_DIR"
	case "$dir" in
		\~)
			printf '%s' '~'
			;;
		\~/*|/*)
			printf '%s' "${dir%/}"
			;;
		*)
			printf '%s/%s' '~' "${dir%/}"
			;;
	esac
}

has_tty() {
	[[ -r /dev/tty && -w /dev/tty ]]
}

prompt_yes_no() {
	local prompt="$1" default="${2:-n}" answer suffix
	if ! has_tty; then
		echo "Cannot prompt without a TTY." >&2
		return 1
	fi

	case "$default" in
		y|Y) suffix="[Y/n]" ;;
		*) suffix="[y/N]" ;;
	esac

	while true; do
		read -r -p "$prompt $suffix " answer < /dev/tty || return 1
		answer="$(trim "$answer")"
		if [[ -z "$answer" ]]; then
			answer="$default"
		fi
		case "$answer" in
			y|Y|yes|YES|Yes) return 0 ;;
			n|N|no|NO|No) return 1 ;;
			*) echo "Please answer y or n." > /dev/tty ;;
		esac
	done
}

prompt_text() {
	local prompt="$1" default="${2:-}" value
	if ! has_tty; then
		echo "Cannot prompt without a TTY." >&2
		return 1
	fi

	if [[ -n "$default" ]]; then
		read -r -p "$prompt [$default]: " value < /dev/tty || return 1
		value="$(trim "$value")"
		printf '%s' "${value:-$default}"
	else
		while true; do
			read -r -p "$prompt: " value < /dev/tty || return 1
			value="$(trim "$value")"
			if [[ -n "$value" ]]; then
				printf '%s' "$value"
				return 0
			fi
			echo "Value is required." > /dev/tty
		done
	fi
}

prompt_optional_text() {
	local prompt="$1" default="${2:-}" value
	if ! has_tty; then
		echo "Cannot prompt without a TTY." >&2
		return 1
	fi

	if [[ -n "$default" ]]; then
		read -r -p "$prompt [$default]: " value < /dev/tty || return 1
		value="$(trim "$value")"
		printf '%s' "${value:-$default}"
	else
		read -r -p "$prompt: " value < /dev/tty || return 1
		trim "$value"
	fi
}

prompt_secret() {
	local prompt="$1" value
	if ! has_tty; then
		echo "Cannot prompt without a TTY." >&2
		return 1
	fi

	while true; do
		read -r -s -p "$prompt: " value < /dev/tty || return 1
		echo > /dev/tty
		if [[ -n "$value" ]]; then
			printf '%s' "$value"
			return 0
		fi
		echo "Value is required." > /dev/tty
	done
}

prompt_secret_with_default() {
	local prompt="$1" default="${2:-}" value
	if ! has_tty; then
		echo "Cannot prompt without a TTY." >&2
		return 1
	fi

	if [[ -n "$default" ]]; then
		read -r -s -p "$prompt [blank keeps existing]: " value < /dev/tty || return 1
		echo > /dev/tty
		printf '%s' "${value:-$default}"
		return 0
	fi

	prompt_secret "$prompt"
}

expand_local_path() {
	local path="$1"
	case "$path" in
		\~)
			printf '%s' "$HOME"
			;;
		\~/*)
			printf '%s/%s' "$HOME" "${path#\~/}"
			;;
		*)
			printf '%s' "$path"
			;;
	esac
}

format_target_line() {
	local user="$1" password="$2" host="$3" port="$4" key_path="$5" hostport line
	hostport="$host"
	[[ "$port" != "22" ]] && hostport+=":$port"

	if [[ -n "$password" ]]; then
		line="${user}:${password}@${hostport}"
	else
		line="${user}@${hostport}"
	fi

	if [[ -n "$key_path" ]]; then
		line+="|key=${key_path}"
	fi

	printf '%s\n' "$line"
}

parse_target() {
	local raw="$1" quiet="${2:-0}" line main extras extra key value creds hostport
	line="$(trim "$raw")"
	[[ -z "$line" || "${line:0:1}" == "#" ]] && return 1

	line="${line#ssh://}"
	main="${line%%|*}"
	extras=""
	if [[ "$line" == *"|"* ]]; then
		extras="${line#*|}"
	fi

	creds="${main%@*}"
	hostport="${main#*@}"
	if [[ "$creds" == "$main" || -z "$hostport" ]]; then
		((quiet)) || echo "Skipping invalid target line: $raw" >&2
		return 1
	fi

	if [[ "$creds" == *:* ]]; then
		TARGET_USER="${creds%%:*}"
		TARGET_PASS="${creds#*:}"
	else
		TARGET_USER="$creds"
		TARGET_PASS=""
	fi
	TARGET_HOST="$hostport"
	TARGET_PORT=22
	TARGET_KEY=""

	if [[ "$hostport" =~ ^(.+):([0-9]+)$ ]]; then
		TARGET_HOST="${BASH_REMATCH[1]}"
		TARGET_PORT="${BASH_REMATCH[2]}"
	fi

	if [[ -n "$extras" ]]; then
		IFS='|' read -r -a TARGET_EXTRA_FIELDS <<< "$extras"
		for extra in "${TARGET_EXTRA_FIELDS[@]}"; do
			extra="$(trim "$extra")"
			[[ -n "$extra" ]] || continue
			key="${extra%%=*}"
			value="${extra#*=}"
			case "$key" in
				key|identity|identity_file)
					TARGET_KEY="$value"
					;;
				*)
					((quiet)) || echo "Ignoring unknown target option '$key' in line: $raw" >&2
					;;
			esac
		done
	fi

	if [[ -z "$TARGET_USER" || -z "$TARGET_HOST" ]]; then
		((quiet)) || echo "Skipping invalid target line: $raw" >&2
		return 1
	fi
}

target_label() {
	local hostport="$TARGET_HOST" auth_parts=()
	[[ "$TARGET_PORT" != "22" ]] && hostport+=":$TARGET_PORT"

	if [[ -n "${TARGET_PASS:-}" ]]; then
		auth_parts+=("password")
	fi
	if [[ -n "${TARGET_KEY:-}" ]]; then
		auth_parts+=("key=$(basename "$TARGET_KEY")")
	fi
	if ((${#auth_parts[@]} == 0)); then
		auth_parts+=("ssh-config")
	fi

	printf '%s@%s (%s)' "$TARGET_USER" "$hostport" "$(IFS=,; printf '%s' "${auth_parts[*]}")"
}

ensure_targets_parent_dir() {
	local target_dir
	target_dir="$(dirname "$TARGETS_FILE")"
	mkdir -p "$target_dir"
}

write_target_lines() {
	local -n lines_ref=$1
	local target_dir tmp
	ensure_targets_parent_dir
	target_dir="$(dirname "$TARGETS_FILE")"
	tmp="$(mktemp "$target_dir/.targets.XXXXXX")"
	for line in "${lines_ref[@]}"; do
		printf '%s\n' "$line" >> "$tmp"
	done
	mv "$tmp" "$TARGETS_FILE"
	chmod 600 "$TARGETS_FILE" 2>/dev/null || true
}

prompt_target_entry() {
	local default_user="${1:-}" default_host="${2:-}" default_port="${3:-22}"
	local default_password="${4:-}" default_key="${5:-}"
	local user password="" host port key_path="" key_path_expanded auth_default auth_choice

	user="$(prompt_text "SSH user" "$default_user")" || return 1
	host="$(prompt_text "SSH host" "$default_host")" || return 1
	port="$(prompt_text "SSH port" "$default_port")" || return 1

	if [[ -n "$default_password" && -n "$default_key" ]]; then
		auth_default=3
	elif [[ -n "$default_password" ]]; then
		auth_default=2
	else
		auth_default=1
	fi

	while true; do
		{
			echo
			echo "Authentication"
			echo "  1) SSH key / ssh-agent / ~/.ssh/config"
			echo "  2) Password"
			echo "  3) SSH key plus password fallback"
		} > /dev/tty
		read -r -p "Choice [$auth_default]: " auth_choice < /dev/tty || return 1
		auth_choice="$(trim "$auth_choice")"
		[[ -z "$auth_choice" ]] && auth_choice="$auth_default"
		case "$auth_choice" in
			1|2|3) break ;;
			*) echo "Invalid selection." > /dev/tty ;;
		esac
	done

	case "$auth_choice" in
		1)
			key_path="$(prompt_optional_text "SSH key path (blank for default SSH config/agent)" "$default_key")" || return 1
			password=""
			;;
		2)
			key_path=""
			password="$(prompt_secret_with_default "SSH password" "$default_password")" || return 1
			;;
		3)
			key_path="$(prompt_optional_text "SSH key path (blank for default SSH config/agent)" "$default_key")" || return 1
			password="$(prompt_secret_with_default "SSH password" "$default_password")" || return 1
			;;
	esac

	if [[ "$user" == *:* || "$user" == *@* ]]; then
		echo "User cannot contain ':' or '@'." >&2
		return 1
	fi
	if [[ "$password" == *@* ]]; then
		echo "Password cannot contain '@' with the user:password@host target format." >&2
		return 1
	fi
	if [[ "$host" == *@* || -z "$host" ]]; then
		echo "Host cannot contain '@'." >&2
		return 1
	fi
	if [[ "$key_path" == *"|"* ]]; then
		echo "Key path cannot contain '|'." >&2
		return 1
	fi
	if [[ ! "$port" =~ ^[0-9]+$ ]]; then
		echo "Port must be numeric." >&2
		return 1
	fi
	if [[ -n "$key_path" ]]; then
		key_path_expanded="$(expand_local_path "$key_path")"
		if [[ ! -f "$key_path_expanded" ]]; then
			echo "Warning: SSH key file does not exist locally: $key_path" > /dev/tty
			prompt_yes_no "Continue with this key path anyway?" n || return 1
		fi
	fi

	format_target_line "$user" "$password" "$host" "$port" "$key_path"
}

prompt_target_entry_with_test() {
	local entry
	while true; do
		entry="$(prompt_target_entry "$@")" || return 1
		parse_target "$entry" 1 || return 1
		if test_target_connection; then
			echo "Connection test passed." >&2
			printf '%s\n' "$entry"
			return 0
		fi

		echo "Connection test failed for $(target_label)." >&2
		if prompt_yes_no "Edit credentials and retry?" y; then
			continue
		fi
		if prompt_yes_no "Save this target anyway?" n; then
			printf '%s\n' "$entry"
			return 0
		fi
		return 1
	done
}

load_targets() {
	TARGET_FILE_LINES=()
	TARGET_ENTRY_LINE_NUMBERS=()
	TARGET_ENTRY_LABELS=()

	[[ -f "$TARGETS_FILE" ]] || return 0

	local line line_number=0
	while IFS= read -r line || [[ -n "$line" ]]; do
		TARGET_FILE_LINES+=("$line")
		((line_number += 1))
		if parse_target "$line" 1; then
			TARGET_ENTRY_LINE_NUMBERS+=("$line_number")
			TARGET_ENTRY_LABELS+=("$(target_label)")
		fi
	done < "$TARGETS_FILE"
}

list_targets() {
	load_targets
	if ((${#TARGET_ENTRY_LABELS[@]} == 0)); then
		echo "No valid targets in $TARGETS_FILE"
		return 1
	fi

	echo "Targets in $TARGETS_FILE:"
	local i
	for i in "${!TARGET_ENTRY_LABELS[@]}"; do
		printf '  %2d) %s\n' "$((i + 1))" "${TARGET_ENTRY_LABELS[$i]}"
	done
}

select_target_entry() {
	local prompt="${1:-Select target}" choice
	load_targets
	if ((${#TARGET_ENTRY_LABELS[@]} == 0)); then
		echo "No valid targets in $TARGETS_FILE" >&2
		return 1
	fi

	list_targets > /dev/tty
	while true; do
		read -r -p "$prompt: " choice < /dev/tty || return 1
		choice="$(trim "$choice")"
		if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= ${#TARGET_ENTRY_LABELS[@]})); then
			SELECTED_TARGET_INDEX=$((choice - 1))
			return 0
		fi
		echo "Invalid selection." > /dev/tty
	done
}

create_targets_file() {
	local entries=() entry
	if [[ -f "$TARGETS_FILE" ]] && ! prompt_yes_no "Replace $TARGETS_FILE?" n; then
		return 1
	fi

	echo "Creating $TARGETS_FILE"
	while true; do
		entry="$(prompt_target_entry_with_test)" || return 1
		entries+=("$entry")
		prompt_yes_no "Add another target?" n || break
	done

	write_target_lines entries
	echo "Wrote ${#entries[@]} target(s) to $TARGETS_FILE"
}

add_target_entry() {
	local entry lines=()
	entry="$(prompt_target_entry_with_test)" || return 1
	if [[ -f "$TARGETS_FILE" ]]; then
		mapfile -t lines < "$TARGETS_FILE"
	fi
	lines+=("$entry")
	write_target_lines lines
	echo "Added target to $TARGETS_FILE"
}

update_target_entry() {
	local selected_line_index entry
	select_target_entry "Update which target" || return 1
	selected_line_index=$((TARGET_ENTRY_LINE_NUMBERS[SELECTED_TARGET_INDEX] - 1))
	parse_target "${TARGET_FILE_LINES[$selected_line_index]}" 1 || return 1
	entry="$(prompt_target_entry_with_test "$TARGET_USER" "$TARGET_HOST" "$TARGET_PORT" "$TARGET_PASS" "$TARGET_KEY")" || return 1
	TARGET_FILE_LINES[selected_line_index]="$entry"
	write_target_lines TARGET_FILE_LINES
	echo "Updated target in $TARGETS_FILE"
}

remove_target_entry() {
	local selected_line_index new_lines=() i
	select_target_entry "Remove which target" || return 1
	selected_line_index=$((TARGET_ENTRY_LINE_NUMBERS[SELECTED_TARGET_INDEX] - 1))
	if ! prompt_yes_no "Remove ${TARGET_ENTRY_LABELS[$SELECTED_TARGET_INDEX]}?" n; then
		return 1
	fi

	for i in "${!TARGET_FILE_LINES[@]}"; do
		((i == selected_line_index)) && continue
		new_lines+=("${TARGET_FILE_LINES[$i]}")
	done
	write_target_lines new_lines
	echo "Removed target from $TARGETS_FILE"
}

ensure_targets_file() {
	if [[ -f "$TARGETS_FILE" ]]; then
		return 0
	fi

	echo "Targets file not found: $TARGETS_FILE"
	if prompt_yes_no "Create it now?" y; then
		create_targets_file
		return $?
	fi

	echo "Create $TARGETS_FILE with lines like: user@host[:port]|key=/path/to/key or user:password@host[:port]" >&2
	return 1
}

choose_file_mode() {
	local choice
	while true; do
		echo
		echo "File selection mode"
		echo "  1) nonmerged (default)"
		echo "  2) merged"
		echo "  3) all"
		read -r -p "Choice [1]: " choice < /dev/tty || return 1
		choice="$(trim "$choice")"
		[[ -z "$choice" ]] && choice=1

		case "$choice" in
			1) set_file_mode nonmerged; return 0 ;;
			2) set_file_mode merged; return 0 ;;
			3) set_file_mode all; return 0 ;;
			*) echo "Invalid selection." ;;
		esac
	done
}

targets_menu() {
	ensure_targets_file || return 1

	local choice
	while true; do
		echo
		echo "Upload menu ($TARGETS_FILE)"
		echo "Current file selection: $FILE_MODE"
		echo "  1) Upload now"
		echo "  2) Change file selection"
		echo "  3) Create/replace target file"
		echo "  4) Add target"
		echo "  5) Update target"
		echo "  6) Remove target"
		echo "  7) List targets"
		echo "  8) Exit"
		read -r -p "Choice [1]: " choice < /dev/tty || return 1
		choice="$(trim "$choice")"
		[[ -z "$choice" ]] && choice=1

		case "$choice" in
			1) return 0 ;;
			2) choose_file_mode || true ;;
			3) create_targets_file || true ;;
			4) add_target_entry || true ;;
			5) update_target_entry || true ;;
			6) remove_target_entry || true ;;
			7) list_targets || true ;;
			8) exit 0 ;;
			*) echo "Invalid selection." ;;
		esac
	done
}

load_upload_files() {
	case "$FILE_MODE" in
		nonmerged)
			mapfile -d '' FILES < <(find "$OUT_DIR" -maxdepth 1 -type f ! -iname '*-merged*' -print0 | sort -z)
			;;
		merged)
			mapfile -d '' FILES < <(find "$OUT_DIR" -maxdepth 1 -type f -iname '*-merged*' -print0 | sort -z)
			;;
		all)
			mapfile -d '' FILES < <(find "$OUT_DIR" -maxdepth 1 -type f -print0 | sort -z)
			;;
	esac
}

target_ssh_options() {
	SSH_OPTIONS=(
		-o BatchMode=no
		-o StrictHostKeyChecking=accept-new
		-o ConnectTimeout=8
		-p "$TARGET_PORT"
	)
	if [[ -n "${TARGET_KEY:-}" ]]; then
		SSH_OPTIONS+=(
			-i "$(expand_local_path "$TARGET_KEY")"
			-o IdentitiesOnly=yes
		)
	fi
}

target_scp_options() {
	SCP_OPTIONS=(
		-o BatchMode=no
		-o StrictHostKeyChecking=accept-new
		-o ConnectTimeout=8
		-P "$TARGET_PORT"
	)
	if [[ -n "${TARGET_KEY:-}" ]]; then
		SCP_OPTIONS+=(
			-i "$(expand_local_path "$TARGET_KEY")"
			-o IdentitiesOnly=yes
		)
	fi
}

ensure_auth_tooling() {
	need_cmd ssh
	need_cmd scp
	if [[ -n "${TARGET_PASS:-}" ]]; then
		need_cmd sshpass
	fi
}

run_target_ssh() {
	local remote_command="$1"
	target_ssh_options

	if [[ -n "${TARGET_PASS:-}" ]]; then
		need_cmd sshpass
		# shellcheck disable=SC2029
		SSHPASS="$TARGET_PASS" sshpass -e ssh \
			"${SSH_OPTIONS[@]}" \
			"${TARGET_USER}@${TARGET_HOST}" \
			"$remote_command"
	else
		# shellcheck disable=SC2029
		ssh \
			"${SSH_OPTIONS[@]}" \
			"${TARGET_USER}@${TARGET_HOST}" \
			"$remote_command"
	fi
}

run_target_scp_file() {
	local source_file="$1" dest="$2"
	target_scp_options

	if [[ -n "${TARGET_PASS:-}" ]]; then
		need_cmd sshpass
		SSHPASS="$TARGET_PASS" sshpass -e scp \
			"${SCP_OPTIONS[@]}" \
			-- "$source_file" "$dest"
	else
		scp \
			"${SCP_OPTIONS[@]}" \
			-- "$source_file" "$dest"
	fi
}

local_sha256() {
	local file="$1"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$file" | awk '{print $1}'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$file" | awk '{print $1}'
	elif command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 "$file" | awk '{print $NF}'
	else
		echo "No local SHA-256 tool found. Install sha256sum, shasum, or openssl." >&2
		return 1
	fi
}

remote_sha256_for_basename() {
	local base_name="$1" remote_file remote_command output
	remote_file="$(remote_file_shell_expr "$base_name")"
	remote_command="f=${remote_file}; if [ ! -e \"\$f\" ]; then echo MISSING; elif [ -d \"\$f\" ]; then echo DIRECTORY; elif command -v sha256sum >/dev/null 2>&1; then sha256sum \"\$f\" | awk '{print \$1}'; elif command -v shasum >/dev/null 2>&1; then shasum -a 256 \"\$f\" | awk '{print \$1}'; elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 \"\$f\" | awk '{print \$NF}'; else echo NO_SHA256_TOOL; fi"
	output="$(run_target_ssh "$remote_command")" || return 1
	printf '%s\n' "$output" | tr -d '\r' | sed -n '/./p' | tail -n1
}

upload_file_to_target() {
	local file="$1" dest_dir="$2" base_name local_sum remote_sum
	base_name="$(basename "$file")"

	if ((DRY_RUN)); then
		printf '  check: %s; upload only if missing or checksum differs\n' "$base_name"
		return 0
	fi

	local_sum="$(local_sha256 "$file")" || return 1
	remote_sum="$(remote_sha256_for_basename "$base_name")" || {
		echo "Could not check remote checksum for $base_name; not replacing it." >&2
		return 1
	}

	if [[ "$remote_sum" != "MISSING" &&
		"$remote_sum" != "DIRECTORY" &&
		"$remote_sum" != "NO_SHA256_TOOL" &&
		! "$remote_sum" =~ ^[0-9a-fA-F]{64}$ ]]; then
		echo "Remote checksum output was invalid; not replacing: $base_name" >&2
		return 1
	fi

	case "$remote_sum" in
		MISSING)
			echo "Uploading new file: $base_name"
			run_target_scp_file "$file" "$dest_dir"
			;;
		DIRECTORY)
			echo "Remote path exists as a directory, not replacing: $base_name" >&2
			return 1
			;;
		NO_SHA256_TOOL)
			echo "Remote file exists but no SHA-256 tool is available; not replacing: $base_name" >&2
			return 1
			;;
		"$local_sum")
			echo "Same file already present, checksum matches; skipping: $base_name"
			;;
		*)
			echo "Remote file differs; replacing: $base_name"
			run_target_scp_file "$file" "$dest_dir"
			;;
	esac
}

test_target_connection() {
	if ((DRY_RUN)); then
		echo "Dry run: skipping connection test for $(target_label)" >&2
		return 0
	fi

	ensure_auth_tooling
	echo "Testing SSH connection to $(target_label)..." >&2
	run_target_ssh 'true'
}

ensure_target_ready() {
	local line_index="$1" entry
	if ((DRY_RUN)); then
		return 0
	fi

	if test_target_connection; then
		return 0
	fi

	echo "Connection failed for $(target_label)." >&2
	if ! has_tty; then
		return 1
	fi

	if ! prompt_yes_no "Update credentials and retry?" y; then
		return 1
	fi

	entry="$(prompt_target_entry_with_test "$TARGET_USER" "$TARGET_HOST" "$TARGET_PORT" "$TARGET_PASS" "$TARGET_KEY")" || return 1
	parse_target "$entry" 1 || return 1
	TARGET_FILE_LINES[line_index]="$entry"
	write_target_lines TARGET_FILE_LINES
	echo "Updated target in $TARGETS_FILE"
	return 0
}

upload_to_target() {
	local dest remote_path mkdir_cmd
	remote_path="$(remote_copy_path)"
	dest="${TARGET_USER}@${TARGET_HOST}:${remote_path}/"
	mkdir_cmd="$(remote_mkdir_command)"

	echo "Target: ${TARGET_USER}@${TARGET_HOST}:${TARGET_PORT}"
	echo "Remote: $remote_path/"
	if ((DRY_RUN)); then
		printf '  mkdir: ssh -p %s' "$TARGET_PORT"
		if [[ -n "${TARGET_KEY:-}" ]]; then
			printf ' -i %q' "$(expand_local_path "$TARGET_KEY")"
		fi
		printf ' %s@%s %q\n' "$TARGET_USER" "$TARGET_HOST" "$mkdir_cmd"
		printf '  destination: %s\n' "$dest"
		for file in "${FILES[@]}"; do
			upload_file_to_target "$file" "$dest"
		done
		return 0
	fi

	run_target_ssh "$mkdir_cmd"
	for file in "${FILES[@]}"; do
		upload_file_to_target "$file" "$dest"
	done
}

need_cmd find
need_cmd sort

if ((RUN_MENU)); then
	targets_menu
else
	ensure_targets_file
fi

if ((DRY_RUN == 0)); then
	need_cmd ssh
	need_cmd scp
fi

if [[ -z "${OUT_DIR:-}" ]]; then
	MESHCORE_DIR="$(detect_meshcore_dir)" || {
		echo "Could not find MeshCore/out. Set MESHCORE_DIR or OUT_DIR." >&2
		exit 1
	}
	OUT_DIR="$MESHCORE_DIR/out"
fi

if [[ ! -d "$OUT_DIR" ]]; then
	echo "Output directory not found: $OUT_DIR" >&2
	exit 1
fi

load_upload_files
if ((${#FILES[@]} == 0)); then
	echo "No $FILE_MODE files found in $OUT_DIR" >&2
	exit 1
fi

echo "Source: $OUT_DIR"
echo "File selection: $FILE_MODE"
echo "Files:"
for file in "${FILES[@]}"; do
	printf '  %s\n' "$(basename "$file")"
done
echo

load_targets
target_count=${#TARGET_ENTRY_LINE_NUMBERS[@]}

if ((target_count == 0)); then
	echo "No valid targets found in $TARGETS_FILE" >&2
	exit 1
fi

for target_index in "${!TARGET_ENTRY_LINE_NUMBERS[@]}"; do
	target_line_index=$((TARGET_ENTRY_LINE_NUMBERS[target_index] - 1))
	parse_target "${TARGET_FILE_LINES[target_line_index]}"
	ensure_target_ready "$target_line_index"
	if ! upload_to_target; then
		echo "Upload failed for $(target_label)." >&2
		if ((DRY_RUN)) || ! has_tty || ! prompt_yes_no "Update credentials and retry upload?" y; then
			exit 1
		fi
		entry="$(prompt_target_entry_with_test "$TARGET_USER" "$TARGET_HOST" "$TARGET_PORT" "$TARGET_PASS" "$TARGET_KEY")" || exit 1
		parse_target "$entry" 1 || exit 1
		TARGET_FILE_LINES[target_line_index]="$entry"
		write_target_lines TARGET_FILE_LINES
		echo "Updated target in $TARGETS_FILE"
		upload_to_target
	fi
	echo
done

echo "Done."
