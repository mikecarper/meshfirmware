#!/usr/bin/env bash
# Test doubles are invoked through production functions evaluated at runtime.
# shellcheck disable=SC2016,SC2317
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcsetup.sh"

extract_function() {
	local function_name=$1
	awk -v signature="${function_name}() {" '
		$0 == signature { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
}

for function_name in \
	clean_node_info_field normalize_firmware_version \
	format_detected_node_summary print_detected_node_summary \
	refresh_detected_node_info; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

trim() {
	printf '%s' "$*" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
}

export DEVICE_NAME=/dev/ttyACM-test
DETECTED_NODE_BOARD=''
DETECTED_NODE_VERSION=''

query_companion_device_info() {
	printf '%s\t%s\t%s' \
		'Heltec V4.3 OLED' 'v1.17.1.5-halo-keym' '14'
}
query_companion_full_version() {
	printf '%s' 'v1.17.1.5-halo-keymind-cascade-dev-1f1ce55f'
}
serial_cmd() {
	echo "FAIL: used text CLI despite complete Companion info" >&2
	return 99
}

refresh_detected_node_info
[[ "$DETECTED_NODE_BOARD" == 'Heltec V4.3 OLED' ]]
[[ "$DETECTED_NODE_VERSION" == \
	'v1.17.1.5-halo-keymind-cascade-dev-1f1ce55f' ]]
[[ "$(print_detected_node_summary)" == \
	'Detected: Heltec V4.3 OLED. v1.17.1.5-halo-keymind-cascade-dev-1f1ce55f' ]]
echo "PASS: mcsetup shows complete Companion board and firmware identity"

query_companion_device_info() { return 1; }
query_companion_full_version() { return 1; }
serial_cmd() {
	case "$1" in
		board) printf '%s' 'RAK 4631' ;;
		ver) printf '%s' 'v1.17.1 (Build: 03-Sep-2026)' ;;
		*) return 1 ;;
	esac
}

refresh_detected_node_info
[[ "$(print_detected_node_summary)" == 'Detected: RAK 4631. v1.17.1' ]]
echo "PASS: mcsetup normalizes text-CLI board and version replies"

python3 - "$script_path" <<'PY'
import sys

script = open(sys.argv[1], encoding="utf-8").read()
needle = 'print_detected_node_summary\n    read -rp "Choice'
if script.count(needle) != 2:
    raise SystemExit("detected identity must be immediately above both setup choices")
if script.index("serial_cmd() {") > script.index("choose_serial || true"):
    raise SystemExit("serial helpers must be defined before device identity is queried")
PY
echo "PASS: mcsetup prints detected identity immediately above both choices"
