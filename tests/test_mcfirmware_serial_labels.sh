#!/usr/bin/env bash
# Test doubles are invoked through production functions evaluated at runtime.
# shellcheck disable=SC2016,SC2317
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script_path="${repo_root}/mcfirmware.sh"

extract_function() {
	local function_name=$1
	awk -v signature="${function_name}() {" '
		$0 == signature { capture = 1 }
		capture { print }
		capture && $0 == "}" { exit }
	' "$script_path"
}

for function_name in \
	clean_node_info_field format_detected_node_summary read_board_with_retry \
	read_node_info_with_retry; do
	definition="$(extract_function "$function_name")"
	[[ "$definition" == "${function_name}() {"* ]] || {
		echo "failed to extract ${function_name}" >&2
		exit 1
	}
	# Deliberately evaluate functions extracted from the production script.
	# shellcheck disable=SC2294
	eval "$definition"
done

expect_equal() {
	local description=$1 expected=$2 actual=$3
	if [[ "$actual" != "$expected" ]]; then
		echo "FAIL: ${description}: expected '${expected}', got '${actual}'" >&2
		exit 1
	fi
	echo "PASS: ${description}"
}

expect_equal "ordinary board text remains usable" \
	"Seeed SenseCAP Indicator" \
	"$(clean_node_info_field $'\r\n  Seeed SenseCAP Indicator  \r\n')"
expect_equal "unsafe framed bytes cannot become a chooser label" "" \
	"$(clean_node_info_field $'\x05\x01\x00=framed-reply\x7f')"
expect_equal "device command errors cannot become a chooser label" "" \
	"$(clean_node_info_field 'ERROR COMMAND ERROR COMMAND')"
expect_equal "implausibly long serial text is rejected" "" \
	"$(clean_node_info_field "$(printf 'A%.0s' {1..121})")"
expect_equal "detected board and version use the choice-menu format" \
	"Detected: Heltec V4.3 OLED. v1.17.1.5-halo-keymind" \
	"$(format_detected_node_summary \
		'Heltec V4.3 OLED' 'v1.17.1.5-halo-keymind')"
expect_equal "detected board remains useful without a version" \
	"Detected: Heltec V4.3 OLED" \
	"$(format_detected_node_summary 'Heltec V4.3 OLED' '')"

query_companion_device_info() {
	printf '%s\t%s\t%s' \
		'Heltec V4.3 OLED' 'v1.17.1.5-halo-keym' '14'
}
query_companion_full_version() {
	printf '%s' 'v1.17.1.5-halo-keymind-cascade-dev-1f1ce55f'
}
quick_node_info_cmd() {
	echo "FAIL: used ASCII version despite a framed full-version reply" >&2
	return 99
}
expect_equal "protocol v14 supplies the untruncated Companion version" \
	$'Heltec V4.3 OLED\tv1.17.1.5-halo-keymind-cascade-dev-1f1ce55f' \
	"$(read_node_info_with_retry /dev/ttyACM-test)"

query_companion_board_model() {
	printf '%s\n' 'Heltec V4.3 OLED'
}
quick_node_info_cmd() {
	printf '%s\n' 'should not be used'
}
expect_equal "Binary Companion model is preferred" "Heltec V4.3 OLED" \
	"$(read_board_with_retry /dev/ttyACM-test)"
# Command substitutions run in a subshell, so verify precedence by making an
# unexpected ASCII fallback fatal rather than relying on the counters above.
quick_node_info_cmd() {
	echo "FAIL: queried ASCII after a valid Binary Companion reply" >&2
	return 99
}
expect_equal "valid Binary Companion reply avoids ASCII probing" \
	"Heltec V4.3 OLED" "$(read_board_with_retry /dev/ttyACM-test)"

query_companion_board_model() { return 1; }
quick_node_info_cmd() { printf '%s\n' 'RAK3401'; }
expect_equal "text CLI remains the fallback for repeaters" "RAK3401" \
	"$(read_board_with_retry /dev/ttyACM-repeater)"

grep -Fq '| grep -a -E -v "$rx_pat"' "$script_path" || {
	echo "FAIL: serial_cmd can still emit grep binary-file diagnostics" >&2
	exit 1
}
echo "PASS: serial pipeline explicitly treats device bytes as text"

grep -Fq 'my $version = substr($payload, 60, 20);' "$script_path" || {
	echo "FAIL: Companion device info does not extract its firmware version" >&2
	exit 1
}
grep -Fq 'detected_summary="$(format_detected_node_summary' "$script_path" || {
	echo "FAIL: detected node details are not rendered above the device choice" >&2
	exit 1
}
echo "PASS: Companion version is shown above the device choice when available"
