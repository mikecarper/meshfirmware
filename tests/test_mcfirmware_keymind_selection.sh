#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcfirmware.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "$tmp_dir"' EXIT

extract_function() {
	local function_name=$1
	awk -v signature="${function_name}() {" '
		$0 == signature { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
}

for function_name in _jq1 preserve_selection_for_active_provider; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

CONFIG_FILE="${tmp_dir}/provider.json"
SELECTED_DEVICE_FILE="${tmp_dir}/device"
ARCHITECTURE_FILE="${tmp_dir}/architecture"
ERASE_URL_FILE="${tmp_dir}/erase"
SELECTED_ROLE_FILE="${tmp_dir}/role"
SELECTED_TITLE_FILE="${tmp_dir}/title"
SELECTED_SUBTITLE_FILE="${tmp_dir}/subtitle"
SELECTED_VERSION_FILE="${tmp_dir}/version"
SELECTED_TYPE_FILE="${tmp_dir}/type"
SELECTED_URL_FILE="${tmp_dir}/url"
export DEBUG_JQ=0

printf '%s\n' '{
  "device": [{
    "name": "Heltec v4",
    "type": "esp32",
    "firmware": [
      {"role": "repeater", "title": "Repeater", "version": {}},
      {"role": "repeater", "title": "Repeater", "subTitle": "TFT", "version": {}},
      {"role": "roomServer", "title": "Room Server", "version": {}}
    ]
  }]
}' > "$CONFIG_FILE"

for stale_file in \
	"$ARCHITECTURE_FILE" "$ERASE_URL_FILE" "$SELECTED_VERSION_FILE" \
	"$SELECTED_TYPE_FILE" "$SELECTED_URL_FILE"; do
	printf '%s\n' stale > "$stale_file"
done

output="$(preserve_selection_for_active_provider \
	'Heltec v4' repeater Repeater '')"
[[ "$(<"$SELECTED_DEVICE_FILE")" == 'Heltec v4' ]]
[[ "$(<"$SELECTED_ROLE_FILE")" == repeater ]]
[[ "$(<"$SELECTED_TITLE_FILE")" == Repeater ]]
[[ "$(<"$SELECTED_SUBTITLE_FILE")" == '' ]]
for stale_file in \
	"$ARCHITECTURE_FILE" "$ERASE_URL_FILE" "$SELECTED_VERSION_FILE" \
	"$SELECTED_TYPE_FILE" "$SELECTED_URL_FILE"; do
	[[ ! -e "$stale_file" ]]
done
grep -Fq 'Keeping previous device: Heltec v4' <<< "$output"
grep -Fq 'Keeping previous role: repeater (Repeater)' <<< "$output"
echo "PASS: exact device and role choices survive a Keymind provider change"

preserve_selection_for_active_provider \
	'Heltec v4' repeater 'A different repeater' '' >/dev/null
[[ "$(<"$SELECTED_DEVICE_FILE")" == 'Heltec v4' ]]
[[ ! -e "$SELECTED_ROLE_FILE" ]]
echo "PASS: ambiguous Keymind role variants are not guessed"

preserve_selection_for_active_provider \
	'Heltec v4' roomServer 'Old room-server label' '' >/dev/null
[[ "$(<"$SELECTED_ROLE_FILE")" == roomServer ]]
[[ "$(<"$SELECTED_TITLE_FILE")" == 'Room Server' ]]
echo "PASS: a uniquely compatible role is preserved across label changes"

preserve_selection_for_active_provider \
	'Unsupported board' repeater Repeater '' >/dev/null
[[ ! -e "$SELECTED_DEVICE_FILE" ]]
[[ ! -e "$SELECTED_ROLE_FILE" ]]
echo "PASS: unsupported choices fall back to device selection"

[[ "$(grep -c 'preserve_selection_for_active_provider' "$script_path")" -eq 2 ]]
echo "PASS: the Keymind version-menu path invokes selection preservation"
